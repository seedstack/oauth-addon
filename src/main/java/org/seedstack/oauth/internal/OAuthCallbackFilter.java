/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.util.Objects;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.token.OAuthToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.web.SecurityFilter;
import org.seedstack.seed.web.security.WebSecurityConfig;
import org.seedstack.seed.web.security.internal.SessionRegenerationCapable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SecurityFilter("oauthCallback")
public class OAuthCallbackFilter extends AuthenticatingFilter implements SessionRegenerationCapable {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthCallbackFilter.class);
    private static final String DEFAULT_REDIRECT_URL = "/";
    private final OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
    private String redirectUrl = DEFAULT_REDIRECT_URL;
    @Configuration
    private WebSecurityConfig webSecurityConfig;
    @Configuration
    private OAuthConfig oAuthConfig;

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        if (request instanceof HttpServletRequest) {
            OAuthToken oAuthToken = exchangeCodeForToken(((HttpServletRequest) request));
            return new OAuthAuthenticationToken("toto", oAuthToken.getAccessToken());
        } else {
            throw new AuthenticationException("OAuthCallbackFilter only support HttpServletRequests");
        }
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
     * Returns the URL to where the user will be redirected after logout.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @return the URL to where the user will be redirected after logout.
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Sets the URL to where the user will be redirected after logout.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @param redirectUrl the url to where the user will be redirected after logout
     */
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    private org.apache.oltu.oauth2.common.token.OAuthToken exchangeCodeForToken(HttpServletRequest request)
            throws OAuthProblemException {
        OAuthAuthzResponse oAuthAuthzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);

        // Verify that stored and returned state match
        checkState(oAuthAuthzResponse.getState());

        // Proceed to the exchange
        try {
            OAuthClientRequest oAuthClientRequest = OAuthClientRequest
                    .tokenLocation(oAuthConfig.endpoints().getToken())
                    .setRedirectURI(oAuthConfig.endpoints().getRedirect())
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(oAuthConfig.getClientId())
                    .setClientSecret(oAuthConfig.getClientSecret())
                    .setCode(oAuthAuthzResponse.getCode())
                    .buildBodyMessage();
            return oAuthClient.accessToken(oAuthClientRequest, OAuth.HttpMethod.POST).getOAuthToken();
        } catch (OAuthSystemException e) {
            throw new RuntimeException(e); // TODO
        }
    }

    private void checkState(String returnedState) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        String storedState = (String) session.getAttribute(OAuthAuthenticationFilter.STATE_KEY);
        if (!Objects.equals(
                checkNotNull(storedState, "No OAuth state found in security session"),
                checkNotNull(returnedState, "No OAuth state returned by authorization provider")
        )) {
            throw new IllegalStateException("OAuth state mismatch");
        }
    }
}
