/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.spi.OAuthService;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.SeedException;
import org.seedstack.seed.web.SecurityFilter;
import org.seedstack.seed.web.security.SessionRegeneratingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.shiro.web.util.WebUtils.toHttp;
import static org.seedstack.oauth.internal.OAuthUtils.buildGenericError;
import static org.seedstack.oauth.internal.OAuthUtils.createScope;
import static org.seedstack.oauth.internal.OAuthUtils.requestTokens;

@SecurityFilter("oauthCallback")
public class OAuthCallbackFilter extends AuthenticatingFilter implements SessionRegeneratingFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthCallbackFilter.class);
    private static final String DEFAULT_REDIRECT_URL = "/";
    private static final String AUTHORIZATION = "Authorization";
    private String redirectUrl = DEFAULT_REDIRECT_URL;
    @Inject
    private OAuthService oAuthService;
    @Configuration
    private OAuthConfig oauthConfig;

    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        AuthenticationToken token = createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                    "must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        }
        try {
            Subject subject = getSubject(request, response);
            subject.login(token);

            ((HttpServletResponse) response).addHeader(AUTHORIZATION, token.getCredentials().toString());

            return onLoginSuccess(token, subject, request, response);
        } catch (AuthenticationException e) {
            return onLoginFailure(token, e, request, response);
        }
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        return requestTokens(
                oAuthService.getOAuthProvider(),
                oauthConfig,
                new AuthorizationCodeGrant(
                        parseAuthorizationCode(toHttp(request)),
                        checkNotNull(oauthConfig.getRedirect(), "Missing redirect URI")),
                getNonce(),
                createScope(oauthConfig.getScopes())
        );
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
                                     ServletResponse response) throws Exception {
        regenerateSession(subject);
        issueSuccessRedirect(request, response);
        return false;
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
                                     ServletResponse response) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Authentication exception", e);
        }

        try {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
        } catch (IOException e1) {
            LOGGER.debug("Unable to send 403 HTTP code to client", e1);
        }
        return false;
    }

    /**
     * Returns the URL to where the user will be redirected after logout. Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @return the URL to where the user will be redirected after logout.
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Sets the URL to where the user will be redirected after logout. Default is the web application's context root,
     * i.e. {@code "/"}
     *
     * @param redirectUrl the url to where the user will be redirected after logout
     */
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    private AuthorizationCode parseAuthorizationCode(HttpServletRequest request) {
        AuthorizationResponse authorizationResponse;
        try {
            authorizationResponse = AuthorizationResponse
                    .parse(new URI(request.getRequestURI()), getParameterMap(request));
        } catch (ParseException | URISyntaxException e) {
            throw SeedException.wrap(e, OAuthErrorCode.FAILED_TO_PARSE_AUTHORIZATION_RESPONSE);
        }

        if (authorizationResponse.indicatesSuccess()) {
            // Validate that response state is consistent with the one stored in session
            State storedState = checkNotNull(
                    (State) SecurityUtils.getSubject().getSession().getAttribute(OAuthAuthenticationFilter.STATE_KEY),
                    "No OAuth state found in security session");
            State returnedState = checkNotNull(authorizationResponse.getState(),
                    "No OAuth state returned by authorization provider");
            if (!storedState.equals(returnedState)) {
                throw new IllegalStateException("OAuth state mismatch");
            }
            return ((AuthorizationSuccessResponse) authorizationResponse).getAuthorizationCode();
        } else {
            throw buildGenericError((ErrorResponse) authorizationResponse);
        }
    }

    private Nonce getNonce() {
        return (Nonce) SecurityUtils.getSubject().getSession().getAttribute(OAuthAuthenticationFilter.NONCE_KEY);
    }

    private Map<String, List<String>> getParameterMap(HttpServletRequest httpServletRequest) {
        Map<String, List<String>> map = new HashMap<>();
        for (Map.Entry<String, String[]> parameter : httpServletRequest.getParameterMap().entrySet()) {
            map.put(parameter.getKey(), new ArrayList<>(Arrays.asList(parameter.getValue())));
        }
        return map;
    }
}
