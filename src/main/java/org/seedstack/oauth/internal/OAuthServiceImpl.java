/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.oauth.OAuthService;
import org.seedstack.seed.Configuration;
import org.seedstack.seed.SeedException;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.Tokens;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.seedstack.oauth.internal.OAuthUtils.buildGenericError;
import java.io.IOException;
import java.util.List;
import javax.inject.Inject;


import org.apache.shiro.authc.AuthenticationToken;

public class OAuthServiceImpl implements OAuthService {

    @Configuration
    private OAuthConfig oauthConfig;
    
    @Inject
    private OAuthProvider oauthProvider;
    
    public AuthenticationToken getTokenFromClientCredentials() {
        Tokens tokens = requestTokens(new ClientCredentialsGrant());
        return new OAuthAuthenticationToken(tokens.getAccessToken());
    }
    
    
    private Tokens requestTokens(AuthorizationGrant authorizationGrant) {
        TokenRequest tokenRequest = new TokenRequest(
                checkNotNull(oauthProvider.getTokenEndpoint(), "Missing token endpoint"),
                new ClientSecretBasic(
                        new ClientID(checkNotNull(oauthConfig.getClientId(), "Missing client identifier")),
                        new Secret(checkNotNull(oauthConfig.getClientSecret(), "Missing client secret"))),
                authorizationGrant,createScope(oauthConfig.getScopes()));

        TokenResponse tokenResponse;
        try{
            tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (IOException | ParseException e) {
            throw SeedException.wrap(e, OAuthErrorCode.FAILED_TO_REQUEST_TOKENS);
        }

        if (tokenResponse.indicatesSuccess()) {
                return ((AccessTokenResponse) tokenResponse).getTokens();
        } else {
            throw buildGenericError((ErrorResponse) tokenResponse);
        }
    }
    
    
    private Scope createScope(List<String> scopes) {
        if (scopes == null) {
            return new Scope();
        } else {
            return new Scope(scopes.toArray(new String[scopes.size()]));
        }
    }

}
