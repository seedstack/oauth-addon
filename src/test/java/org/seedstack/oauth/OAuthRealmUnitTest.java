/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth;

import static org.junit.Assert.assertNotNull;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Optional;
import javax.inject.Provider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.reflect.Whitebox;
import org.seedstack.oauth.fixtures.MockedManualOAuthProvider;
import org.seedstack.oauth.fixtures.TestAccessTokenValidator;
import org.seedstack.oauth.internal.OAuthRealm;
import org.seedstack.oauth.internal.OidcAuthenticationToken;
import org.seedstack.seed.security.AuthenticationException;
import org.seedstack.seed.security.AuthenticationInfo;
import org.seedstack.seed.security.AuthenticationToken;

public class OAuthRealmUnitTest {
    private OAuthRealm underTest;
    private OAuthConfig oauthConfig;
    private OAuthProvider oauthProvider;
    private String accessTokenValue = "ya29.Gl0OBRawZls_r7atLBziIl051NW1xWZTp96JbPyuz8g09Ty0QvavJaQz"
            + "BMtpclRxDxgq2b3pdQbUFCDaRq-qIJ7Qsw_KQmYMhxxczJsXP7DqMkiQf7CvOsZhwQkqpfE";
    private AccessToken accessToken = new BearerAccessToken(accessTokenValue);

    @Before
    public void before() throws Exception {
        this.underTest = new OAuthRealm();
        mockOAuthConfig();
        mockOAuthProvider();
        mockAccessTokenValidator();
    }

    @Test
    public void authenticationInfoReturnedShouldBeNonNull() {
        AuthenticationInfo info = underTest.getAuthenticationInfo(mockedToken());
        assertNotNull(info);
    }

    @Test(expected = AuthenticationException.class)
    public void authenticationInfoShouldThrowAuthenticationException() {
        underTest.getAuthenticationInfo(null);
    }

    @Test(expected = TokenValidationException.class)
    public void authenticationInfoShouldThrowTokenValidationException() {
        underTest.getAuthenticationInfo(mockedTokenWithIncorrectNonce());
    }

    @Test(expected = AuthenticationException.class)
    public void authenticationInfoShouldThrowAuthenticationExceptionForNullAccessToken() {
        underTest.getAuthenticationInfo(mockedTokenNullAccessToken());
    }

    @Test
    public void outhConfigShouldBeNotNull() {
        mockOAuthConfig();
        assertNotNull(this.oauthConfig);
    }

    @Test
    public void outhProviderShouldBeNotNull() throws Exception {
        mockOAuthProvider();
        assertNotNull(this.oauthProvider);
    }

    //Mock plain jwt
    private JWT createPlainJWT() {
        PlainHeader plainHeader = new PlainHeader(null, null, null, null, null);

        Long iat = System.currentTimeMillis();
        Long exp = (iat) + (3600 * 60);

        JWTClaimsSet jWTClaimsSet = new JWTClaimsSet.Builder()
                .claim("at_hash", "GlCoaDfQuUvpilxrKRBBdQ")
                .audience("testClientId")
                .subject("118090614001964330293")
                .claim("email_verified", "true")
                .claim("azp", "testClientId")
                .issuer("https://accounts.google.com")
                .expirationTime(new Date(exp))
                .claim("nonce", "123")
                .issueTime(new Date(iat))
                .claim("email", "jyotirathalye@gmail.com").build();

        return new PlainJWT(plainHeader, jWTClaimsSet);

    }

    //Mock OAuthConfig
    private void mockOAuthConfig() {
        this.oauthConfig = Mockito.mock(OAuthConfig.class);
        OAuthConfig.OpenIdConnectConfig openIdConnectConfig = Mockito.mock(OAuthConfig.OpenIdConnectConfig.class);
        Whitebox.setInternalState(underTest, "oauthConfig", this.oauthConfig);
        Mockito.when(oauthConfig.getClientId())
                .thenReturn("testClientId");
        Mockito.when(this.oauthConfig.openIdConnect()).thenReturn(openIdConnectConfig);
        Mockito.when(this.oauthConfig.openIdConnect().isUnsecuredTokenAllowed()).thenReturn(true);
    }

    //Mock OAuthProvider
    private void mockOAuthProvider() throws Exception {
        this.oauthProvider = Mockito.mock(MockedManualOAuthProvider.class);
        Whitebox.setInternalState(underTest, "oauthProvider", this.oauthProvider);
        Mockito.when(this.oauthProvider.getIssuer()).thenReturn(dummyIssuer());

    }

    //Mock AccessTokenValidator
    @SuppressWarnings("unchecked")
    private void mockAccessTokenValidator() {
        Provider<AccessTokenValidator> providerForValidator = (Provider<AccessTokenValidator>) Mockito
                .mock(Provider.class);
        Whitebox.setInternalState(underTest, "accessTokenValidatorProvider", providerForValidator);
        //PlainAccessTokenValidator pv = Mockito.mock(PlainAccessTokenValidator.class);
        Mockito.when(providerForValidator.get()).thenReturn(new TestAccessTokenValidator());

    }

    //Mock access token
    private AuthenticationToken mockedToken() {
        Nonce nonce = new Nonce("123");
        JWT plainJWT = createPlainJWT();

        return new OidcAuthenticationToken(accessToken, plainJWT, nonce);
    }

    private AuthenticationToken mockedTokenWithIncorrectNonce() {
        Nonce nonce = new Nonce("789");
        JWT plainJWT = createPlainJWT();

        return new OidcAuthenticationToken(accessToken, plainJWT, nonce);
    }

    private AuthenticationToken mockedTokenNullAccessToken() {
        Nonce nonce = new Nonce("123");
        JWT plainJWT = createPlainJWT();
        return new OidcAuthenticationToken(null, plainJWT, nonce);
    }

    private Optional<URI> dummyIssuer() throws URISyntaxException {
        return Optional.of(new URI("https://accounts.google.com"));
    }

}
