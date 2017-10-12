/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static org.apache.shiro.web.util.WebUtils.issueRedirect;

import java.io.IOException;
import java.util.Optional;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ParameterStyle;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.web.SecurityFilter;
import org.seedstack.seed.web.security.internal.SessionRegenerationCapable;
import org.seedstack.seed.web.spi.AntiXsrfService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SecurityFilter("oauth")
public class OAuthAuthenticationFilter extends AuthenticatingFilter implements SessionRegenerationCapable {
    static final String STATE_KEY = "seedstackOAuthState";
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthAuthenticationFilter.class);
    private static final String RESPONSE_TYPE = "code";
    @Inject
    private AntiXsrfService antiXsrfService;
    @Configuration
    private OAuthConfig oAuthConfig;

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        return getAccessToken(((HttpServletRequest) request))
                .map(accessToken -> new OAuthAuthenticationToken("toto", accessToken))
                .orElse(null);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean loggedIn = false;
        if (getAccessToken(((HttpServletRequest) request)).isPresent()) {
            loggedIn = executeLogin(request, response);
        }
        if (!loggedIn) {
            redirectToAuthorizationLocation(request, response);
        }
        return loggedIn;
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
            ServletResponse response) throws Exception {
        regenerateSession(subject);
        return super.onLoginSuccess(token, subject, request, response);
    }

    private Optional<String> getAccessToken(HttpServletRequest request) {
        try {
            return Optional.of(new OAuthAccessResourceRequest(request, ParameterStyle.HEADER).getAccessToken());
        } catch (OAuthSystemException e) {
            throw new RuntimeException(e);
        } catch (OAuthProblemException e) {
            return Optional.empty();
        }
    }

    private void redirectToAuthorizationLocation(ServletRequest request, ServletResponse response) {
        try {
            String state = antiXsrfService.generateRandomToken();
            String locationUri = OAuthClientRequest
                    .authorizationLocation(oAuthConfig.endpoints().getAuthorization())
                    .setRedirectURI(oAuthConfig.endpoints().getRedirect())
                    .setClientId(oAuthConfig.getClientId())
                    .setResponseType(RESPONSE_TYPE)
                    .setState(state)
                    .setScope(String.join(" ", oAuthConfig.getScopes()))
                    .buildQueryMessage()
                    .getLocationUri();
            LOGGER.debug("Redirecting client to authorization endpoint: " + locationUri);
            saveState(state);
            saveRequest(request);
            issueRedirect(request, response, locationUri);
        } catch (OAuthSystemException | IOException e) {
            throw new RuntimeException(e); // TODO
        }
    }

    private void saveState(String state) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        session.setAttribute(STATE_KEY, state);
    }
}
