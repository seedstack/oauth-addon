/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.util.List;

class DiscoveryDocument {
    private URI issuer;
    @JsonProperty("authorization_endpoint")
    private URI authorizationEndpoint;
    @JsonProperty("token_endpoint")
    private URI tokenEndpoint;
    @JsonProperty("userinfo_endpoint")
    private URI userinfoEndpoint;
    @JsonProperty("revocation_endpoint")
    private URI revocationEndpoint;
    @JsonProperty("jwks_uri")
    private URI jwksUri;
    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;
    @JsonProperty("subject_types_supported")
    private List<String> subjectTypesSupported;
    @JsonProperty("id_token_signing_alg_values_supported")
    private List<String> idTokenSigningAlgValuesSupported;
    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;
    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;
    @JsonProperty("claims_supported")
    private List<String> claimsSupported;
    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported;

    URI getIssuer() {
        return issuer;
    }

    void setIssuer(URI issuer) {
        this.issuer = issuer;
    }

    URI getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    void setAuthorizationEndpoint(URI authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    void setTokenEndpoint(URI tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    URI getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    void setUserinfoEndpoint(URI userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    URI getRevocationEndpoint() {
        return revocationEndpoint;
    }

    void setRevocationEndpoint(URI revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
    }

    URI getJwksUri() {
        return jwksUri;
    }

    void setJwksUri(URI jwksUri) {
        this.jwksUri = jwksUri;
    }

    List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    void setResponseTypesSupported(List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    void setSubjectTypesSupported(List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    List<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    void setIdTokenSigningAlgValuesSupported(List<String> idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
    }

    List<String> getScopesSupported() {
        return scopesSupported;
    }

    void setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
    }

    List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    void setTokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    List<String> getClaimsSupported() {
        return claimsSupported;
    }

    void setClaimsSupported(List<String> claimsSupported) {
        this.claimsSupported = claimsSupported;
    }

    List<String> getCodeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    void setCodeChallengeMethodsSupported(List<String> codeChallengeMethodsSupported) {
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
    }
}