package com.neranjana.springsecuritytryout.resourceserver;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.ArrayList;
import java.util.List;

public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    public static final String SCOPE = "scope";

    private Object filterObject;
    private Object returnObject;

    /**
     * Creates a new instance
     *
     * @param authentication the {@link Authentication} to use. Cannot be null.
     */
    public CustomMethodSecurityExpressionRoot(Authentication authentication) {
        super(authentication);
    }

    @Override
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    @Override
    public Object getFilterObject() {
        return this.filterObject;
    }

    @Override
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    @Override
    public Object getReturnObject() {
        return this.returnObject;
    }

    @Override
    public Object getThis() {
        return this;
    }

    public boolean hasAnyScope(String... requiredScopes) {

        boolean isAuthorized = false;

        for (String scope : requiredScopes) {
            if (getTokenScopes().contains(scope)) {
                isAuthorized = true;
                break; // Found one valid scope. No need to continue;
            }
        }
        return isAuthorized;
    }

    private Object getTokenAttribute(String attributeName) {
        Object tokenAttribute = null;
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken token = ((JwtAuthenticationToken) authentication);
            tokenAttribute = token.getTokenAttributes().get(attributeName);
        }
        return tokenAttribute;
    }

    private List<String> getTokenScopes() {
        List<String> scopeList;
        Object tokenScopes = getTokenAttribute(SCOPE);
        if (tokenScopes != null && tokenScopes instanceof List) {
            scopeList = (List<String>) tokenScopes;
        } else {
            scopeList = new ArrayList<>();
        }
        return scopeList;
    }
}
