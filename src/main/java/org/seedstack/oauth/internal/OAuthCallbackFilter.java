/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthService;
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
import java.util.*;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.shiro.web.util.WebUtils.toHttp;
import static org.seedstack.oauth.internal.OAuthUtils.*;

@SecurityFilter("oauthCallback")
public class OAuthCallbackFilter extends AuthenticatingFilter implements SessionRegeneratingFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthCallbackFilter.class);
    @Inject
    private OAuthService oAuthService;
    @Configuration
    private OAuthConfig oauthConfig;

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        try {
            AuthorizationCode authorizationCode = parseAuthorizationCode(toHttp(request));
            return requestTokens(
                    oAuthService.getOAuthProvider(),
                    oauthConfig,
                    new AuthorizationCodeGrant(
                            authorizationCode,
                            checkNotNull(oauthConfig.getRedirect(), "Missing redirect URI")),
                    getNonce(),
                    createScope(oauthConfig.getScopes())
            );
        } catch (Exception e) {
            return OAuthAuthenticationTokenImpl.ERRORED.apply(new AuthenticationException(e));
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean loggedIn = executeLogin(request, response);
        if (!loggedIn) {
            try {
                ((HttpServletResponse) response).sendError(
                        HttpServletResponse.SC_UNAUTHORIZED,
                        OAuthUtils.formatUnauthorizedMessage(request, oauthConfig.isReturnUnauthorizedReason())
                );
            } catch (IOException e1) {
                LOGGER.debug("Unable to send {} HTTP code to client", HttpServletResponse.SC_UNAUTHORIZED, e1);
            }
        }
        return loggedIn;
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
                                     ServletResponse response) throws Exception {
        regenerateSession(subject);
        issueSuccessRedirect(request, response);
        return false;
    }

    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Authentication exception", e);
        }
        request.setAttribute(OAuthUtils.LOGIN_FAILURE_REASON_KEY, e);
        return false;
    }

    private AuthorizationCode parseAuthorizationCode(HttpServletRequest request) throws AuthorizationException {
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
