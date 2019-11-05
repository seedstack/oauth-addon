/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.spi.OAuthProvider;
import org.seedstack.seed.SeedException;
import org.seedstack.shed.exception.BaseException;

final class OAuthUtils {
    private OAuthUtils() {
        // no instantiation allowed
    }

    static BaseException buildGenericError(ErrorResponse errorResponse) {
        ErrorObject errorObject = errorResponse.getErrorObject();
        return SeedException.createNew(OAuthErrorCode.OAUTH_PROVIDER_RETURNED_AN_ERROR)
                .put("description", errorObject.getDescription())
                .put("code", errorObject.getCode())
                .put("httpStatus", errorObject.getHTTPStatusCode());
    }

    static URI stripQueryString(URI uri) {
        try {
            return new URI(uri.getScheme(),
                    uri.getAuthority(),
                    uri.getPath(),
                    null,
                    uri.getFragment());
        } catch (URISyntaxException e) {
            throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_PROCESS_URI);
        }
    }

    static Map<String, List<String>> extractQueryParameters(URI uri) {
        final Map<String, List<String>> queryPairs = new HashMap<>();
        String query = uri.getQuery();
        if (!Strings.isNullOrEmpty(query)) {
            try {
                final String[] pairs = query.split("&");
                for (String pair : pairs) {
                    final int idx = pair.indexOf("=");
                    final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
                    final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1),
                            "UTF-8") : null;
                    queryPairs.computeIfAbsent(key, f -> new ArrayList<>()).add(value);
                }
            } catch (UnsupportedEncodingException e) {
                throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_PROCESS_URI);
            }
        }
        return queryPairs;
    }

    static OAuthAuthenticationTokenImpl requestTokens(OAuthProvider oauthProvider, OAuthConfig oauthConfig,
            AuthorizationGrant authorizationGrant, Nonce nonce, List<String> scopes) {
        URI endpointURI = oauthProvider.getTokenEndpoint();
        Map<String, List<String>> parameters = OAuthUtils.extractQueryParameters(endpointURI);
        endpointURI = OAuthUtils.stripQueryString(endpointURI);

        TokenRequest tokenRequest = new TokenRequest(
                checkNotNull(endpointURI, "Missing token endpoint"),
                new ClientSecretBasic(
                        new ClientID(checkNotNull(oauthConfig.getClientId(), "Missing client identifier")),
                        new Secret(checkNotNull(oauthConfig.getClientSecret(), "Missing client secret"))),
                authorizationGrant,
                createScope(scopes, oauthProvider),
                new ArrayList<>(),
                parameters);

        TokenResponse tokenResponse;
        try {
            if (oauthProvider.isOpenIdCapable()) {
                tokenResponse = OIDCTokenResponse.parse(tokenRequest.toHTTPRequest().send());
            } else {
                tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
            }
        } catch (IOException | ParseException e) {
            throw SeedException.wrap(e, OAuthErrorCode.FAILED_TO_REQUEST_TOKENS);
        }

        if (tokenResponse.indicatesSuccess()) {
            if (tokenResponse instanceof OIDCTokenResponse) {
                OIDCTokens oidcTokens = ((OIDCTokenResponse) tokenResponse).getOIDCTokens();
                return new OidcAuthenticationTokenImpl(
                        oidcTokens.getAccessToken(),
                        oidcTokens.getRefreshToken(),
                        oidcTokens.getIDToken(),
                        nonce);
            } else {
                Tokens tokens = ((AccessTokenResponse) tokenResponse).getTokens();
                return new OAuthAuthenticationTokenImpl(tokens.getAccessToken(), tokens.getRefreshToken());
            }
        } else {
            throw buildGenericError((ErrorResponse) tokenResponse);
        }
    }

    static Scope createScope(List<String> scopes, OAuthProvider oAuthProvider) {
        Scope scope;
        if (scopes == null) {
            return null;
        } else {
            scope = new Scope(scopes.toArray(new String[0]));
        }
        if (oAuthProvider.isOpenIdCapable()) {
            scope.add(OIDCScopeValue.OPENID);
        }
        return scope;
    }
}
