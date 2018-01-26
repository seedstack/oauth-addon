/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.shiro.web.util.WebUtils.issueRedirect;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.web.SecurityFilter;
import org.seedstack.seed.web.security.SessionRegeneratingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SecurityFilter("oauth")
public class OAuthAuthenticationFilter extends AuthenticatingFilter implements SessionRegeneratingFilter {
    static final String STATE_KEY = "org.seedstack.oauth.OAuthState";
    static final String NONCE_KEY = "org.seedstack.oauth.OIDCNonce";
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthAuthenticationFilter.class);
    private static final String AUTHORIZATION = "Authorization";
    @Inject
    private OAuthProvider oauthProvider;
    @Configuration
    private OAuthConfig oauthConfig;

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        return new OAuthAuthenticationToken(
                resolveAccessToken(WebUtils.toHttp(request))
                        .orElseThrow(() -> new AuthenticationException("Missing access token")));
    }

    private Optional<AccessToken> resolveAccessToken(HttpServletRequest request) throws ParseException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null) {
            // Bearer access token
            try {
                return Optional.of(BearerAccessToken.parse(authorizationHeader));
            } catch (ParseException e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Unable to parse bearer access token from: " + authorizationHeader);
                }
            }
        }
        return Optional.empty();
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean loggedIn = false;
        if (resolveAccessToken(WebUtils.toHttp(request)).isPresent()) {
            loggedIn = executeLogin(request, response);
        }
        if (!loggedIn) {
            redirectToAuthorizationEndpoint(request, response);
        }
        return loggedIn;
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
            ServletResponse response) throws Exception {
        regenerateSession(subject);
        return super.onLoginSuccess(token, subject, request, response);
    }

    private void redirectToAuthorizationEndpoint(ServletRequest request, ServletResponse response) throws IOException {
        State state = new State();
        Nonce nonce = new Nonce();
        URI uri;
        if (oauthProvider.isOpenIdCapable()) {
            uri = buildAuthenticationURI(state, nonce);
        } else {
            uri = buildAuthorizationURI(state);
        }
        saveState(state, nonce);
        saveRequest(request);
        issueRedirect(request, response, uri.toString());
    }

    private URI buildAuthorizationURI(State state) {
        URI endpointURI = oauthProvider.getAuthorizationEndpoint();
        Map<String, String> parameters = OAuthUtils.extractQueryParameters(endpointURI);
        endpointURI = OAuthUtils.stripQueryString(endpointURI);

        AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new ClientID(checkNotNull(oauthConfig.getClientId(), "Missing client identifier")))
                .scope(createScope(oauthConfig.getScopes()))
                .redirectionURI(checkNotNull(oauthConfig.getRedirect(), "Missing redirect URI"))
                .endpointURI(endpointURI)
                .state(state);

        for (Map.Entry<String, String> parameter : parameters.entrySet()) {
            builder.customParameter(parameter.getKey(), parameter.getValue());
        }

        return builder.build().toURI();
    }

    private URI buildAuthenticationURI(State state, Nonce nonce) {
        URI endpointURI = oauthProvider.getAuthorizationEndpoint();
        Map<String, String> parameters = OAuthUtils.extractQueryParameters(endpointURI);
        endpointURI = OAuthUtils.stripQueryString(endpointURI);

        AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                createOidcScope(oauthConfig.getScopes()),
                new ClientID(checkNotNull(oauthConfig.getClientId(), "Missing client identifier")),
                checkNotNull(oauthConfig.getRedirect(), "Missing redirect URI"))
                .endpointURI(endpointURI)
                .state(state)
                .nonce(nonce);

        for (Map.Entry<String, String> parameter : parameters.entrySet()) {
            builder.customParameter(parameter.getKey(), parameter.getValue());
        }

        return builder.build().toURI();
    }

    private void saveState(State state, Nonce nonce) {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        session.setAttribute(STATE_KEY, state);
        session.setAttribute(NONCE_KEY, nonce);
    }

    private Scope createScope(List<String> scopes) {
        if (scopes == null) {
            return new Scope();
        } else {
            return new Scope(scopes.toArray(new String[scopes.size()]));
        }
    }

    private Scope createOidcScope(List<String> scopes) {
        Scope scope = createScope(scopes);
        scope.add(OIDCScopeValue.OPENID);
        return scope;
    }
}
