/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.provider.resources;

import java.util.Date;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

public class TokenBuilder {

    private boolean testInvalidNonce; 
    private boolean testTokenExpiry;
    private boolean testInvalidAudience;
    
    private static String accessTokenValue = "ya29.Gl0OBRawZls_r7atLBziIl051NW1xWZTp96JbPyuz8g09Ty0QvavJaQzBMtpclRxDxgq2b3pdQbUFCDaRq-qIJ7Qsw_KQmYMhxxczJsXP7DqMkiQf7CvOsZhwQkqpfE";
    private static String tokenType = "Bearer";
    private static int tokenExpiresIn = 3563;
    private static String clientID = "testClientId";
    
    
    public String buildPlainJWT(String nonce){

        PlainHeader plainHeader = new PlainHeader(null,null,null,null,null);
        
        Long iat = System.currentTimeMillis();
        Long exp = (iat) + (3600*60);
        
        if(testInvalidNonce){
            nonce = "TL2-yFCanqzoiVwOPxQwVHrf.invalid.nonce";
        }else if(testInvalidAudience){
            clientID = "2344574985.incorrect.client";
        }else if(testTokenExpiry){
            exp = iat;
        }
        JWTClaimsSet jWTClaimsSet = new JWTClaimsSet.Builder()
                                            .claim("at_hash", "GlCoaDfQuUvpilxrKRBBdQ")
                                            .audience(clientID)
                                            .subject("118090614001964330293")
                                            .claim("email_verified", "true")
                                            .claim("azp", clientID)
                                            .issuer("https://mockedserver.com")
                                            .expirationTime(new Date(exp))
                                            .claim("nonce", nonce)
                                            .issueTime(new Date(iat))
                                            .claim("email", "jyotirathalye@gmail.com").build();
        
        return new PlainJWT(plainHeader, jWTClaimsSet).serialize();
        
    }
    
    
    public TokenData buildToken(String nonce){
        TokenData td = new TokenData();
        td.setAccess_token(accessTokenValue);
        td.setExpires_in(tokenExpiresIn);
        td.setToken_type(tokenType);
        td.setId_token(buildPlainJWT(nonce));
        return td;
    }

    public void setTestInvalidNonce(boolean testInvalidNonce) {
        this.testInvalidNonce = testInvalidNonce;
    }
    
    public void setTestTokenExpiry(boolean testTokenExpiry) {
        this.testTokenExpiry = testTokenExpiry;
    }

    public void setTestInvalidAudience(boolean testInvalidAudience) {
        this.testInvalidAudience = testInvalidAudience;
    }
    
}
