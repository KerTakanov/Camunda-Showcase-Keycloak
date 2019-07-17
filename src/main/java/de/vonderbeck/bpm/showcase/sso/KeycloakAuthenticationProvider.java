package de.vonderbeck.bpm.showcase.sso;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.InternalServerErrorException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.rest.security.auth.impl.ContainerBasedAuthenticationProvider;
import org.camunda.bpm.engine.rest.util.EngineUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;

/**
 * OAuth2 Authentication Provider for usage with Keycloak and KeycloakIdentityProviderPlugin. 
 */
public class KeycloakAuthenticationProvider extends ContainerBasedAuthenticationProvider {

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
        OAuth2Authentication authentication = null;// = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        String token = null;

        if (SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2Authentication) {
            authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        } else{
            token = request.getHeader("Authorization").substring("Bearer ".length());
        }

        if (authentication == null && token == null) {
            return AuthenticationResult.unsuccessful();
        }

        if (authentication != null) {
            return contextAuthentication(authentication);
        } else { // token
            return tokenAuthentication(token);
        }
    }

    private AuthenticationResult tokenAuthentication(String token) {
        String decodedToken = JwtHelper.decode(token).getClaims();
        try {
            String userEmail = (String) new ObjectMapper().readValue(decodedToken, Map.class).get("email");

            // Authentication successful
            AuthenticationResult authenticationResult = new AuthenticationResult(userEmail, true);
            authenticationResult.setGroups(getUserGroups(userEmail, EngineUtil.lookupProcessEngine("default")));

            return authenticationResult;
        } catch (IOException e) {
            e.printStackTrace();
            throw new InternalServerErrorException("Couldn't extract email for JWT Token");
        }
    }

    private AuthenticationResult contextAuthentication(OAuth2Authentication authentication) {
        Authentication userAuthentication = authentication.getUserAuthentication();
        if (userAuthentication == null || userAuthentication.getDetails() == null) {
            return AuthenticationResult.unsuccessful();
        }

        // Extract user ID from Keycloak authentication result - which is part of the requested user info
        @SuppressWarnings("unchecked")
        // String userId = ((HashMap<String, String>) userAuthentication.getDetails()).get("sub");
                String userId = ((HashMap<String, String>) userAuthentication.getDetails()).get("email"); // useEmailAsCamundaUserId = true
        // String userId = ((HashMap<String, String>) userAuthentication.getDetails()).get("preferred_username"); // useUsernameAsCamundaUserId = true
        if (StringUtils.isEmpty(userId)) {
            return AuthenticationResult.unsuccessful();
        }

        // Authentication successful
        AuthenticationResult authenticationResult = new AuthenticationResult(userId, true);
        authenticationResult.setGroups(getUserGroups(userId, EngineUtil.lookupProcessEngine("default")));

        return authenticationResult;
    }

    private List<String> getUserGroups(String userId, ProcessEngine engine){
        List<String> groupIds = new ArrayList<>();
        // query groups using KeycloakIdentityProvider plugin
        engine.getIdentityService().createGroupQuery().groupMember(userId).list()
        	.forEach( g -> groupIds.add(g.getId()));
        return groupIds;
    }

}