/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import java.net.URI;
import java.util.List;

class DiscoveryDocument {
    private URI issuer;
    private URI authorization_endpoint;
    private URI token_endpoint;
    private URI userinfo_endpoint;
    private URI revocation_endpoint;
    private URI jwks_uri;
    private List<String> response_types_supported;
    private List<String> subject_types_supported;
    private List<String> id_token_signing_alg_values_supported;
    private List<String> scopes_supported;
    private List<String> token_endpoint_auth_methods_supported;
    private List<String> claims_supported;
    private List<String> code_challenge_methods_supported;

    URI getIssuer() {
        return issuer;
    }

    void setIssuer(URI issuer) {
        this.issuer = issuer;
    }

    URI getAuthorization_endpoint() {
        return authorization_endpoint;
    }

    void setAuthorization_endpoint(URI authorization_endpoint) {
        this.authorization_endpoint = authorization_endpoint;
    }

    URI getToken_endpoint() {
        return token_endpoint;
    }

    void setToken_endpoint(URI token_endpoint) {
        this.token_endpoint = token_endpoint;
    }

    URI getUserinfo_endpoint() {
        return userinfo_endpoint;
    }

    void setUserinfo_endpoint(URI userinfo_endpoint) {
        this.userinfo_endpoint = userinfo_endpoint;
    }

    URI getRevocation_endpoint() {
        return revocation_endpoint;
    }

    void setRevocation_endpoint(URI revocation_endpoint) {
        this.revocation_endpoint = revocation_endpoint;
    }

    URI getJwks_uri() {
        return jwks_uri;
    }

    void setJwks_uri(URI jwks_uri) {
        this.jwks_uri = jwks_uri;
    }

    List<String> getResponse_types_supported() {
        return response_types_supported;
    }

    void setResponse_types_supported(List<String> response_types_supported) {
        this.response_types_supported = response_types_supported;
    }

    List<String> getSubject_types_supported() {
        return subject_types_supported;
    }

    void setSubject_types_supported(List<String> subject_types_supported) {
        this.subject_types_supported = subject_types_supported;
    }

    List<String> getId_token_signing_alg_values_supported() {
        return id_token_signing_alg_values_supported;
    }

    void setId_token_signing_alg_values_supported(List<String> id_token_signing_alg_values_supported) {
        this.id_token_signing_alg_values_supported = id_token_signing_alg_values_supported;
    }

    List<String> getScopes_supported() {
        return scopes_supported;
    }

    void setScopes_supported(List<String> scopes_supported) {
        this.scopes_supported = scopes_supported;
    }

    List<String> getToken_endpoint_auth_methods_supported() {
        return token_endpoint_auth_methods_supported;
    }

    void setToken_endpoint_auth_methods_supported(List<String> token_endpoint_auth_methods_supported) {
        this.token_endpoint_auth_methods_supported = token_endpoint_auth_methods_supported;
    }

    List<String> getClaims_supported() {
        return claims_supported;
    }

    void setClaims_supported(List<String> claims_supported) {
        this.claims_supported = claims_supported;
    }

    List<String> getCode_challenge_methods_supported() {
        return code_challenge_methods_supported;
    }

    void setCode_challenge_methods_supported(List<String> code_challenge_methods_supported) {
        this.code_challenge_methods_supported = code_challenge_methods_supported;
    }
}