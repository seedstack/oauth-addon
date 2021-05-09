/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import org.seedstack.coffig.Config;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Config("security.oauth")
public class OAuthConfig {
    @NotNull
    private ProviderConfig provider = new ProviderConfig();
    @NotNull
    private AlgorithmConfig algorithms = new AlgorithmConfig();
    private URI discoveryDocument;
    private URI redirect;
    private String clientId;
    private String clientSecret;
    @NotNull
    private List<String> scopes = new ArrayList<>();
    @NotNull
    private Set<String> requiredClaims = new HashSet<>();
    @NotNull
    private Set<String> prohibitedClaims = new HashSet<>();
    @NotNull
    private Map<String, String> exactMatchClaims = new HashMap<>();
    private Set<String> allowedAudiences = new HashSet<>();
    @NotNull
    private Map<String, List<String>> customParameters = new HashMap<>();
    private Class<? extends AccessTokenValidator> accessTokenValidator = UserInfoAccessTokenValidator.class;
    private boolean autoFetchUserInfo = false;
    private boolean treatScopesAsRoles = false;
    private String additionalRolesClaim;
    private String additionalPermissionsClaim;
    private boolean discloseUnauthorizedReason = true;

    public ProviderConfig provider() {
        return provider;
    }

    public AlgorithmConfig algorithms() {
        return algorithms;
    }

    public URI getDiscoveryDocument() {
        return discoveryDocument;
    }

    public OAuthConfig setDiscoveryDocument(URI discoveryDocument) {
        this.discoveryDocument = discoveryDocument;
        return this;
    }

    public URI getRedirect() {
        return redirect;
    }

    public OAuthConfig setRedirect(URI redirect) {
        this.redirect = redirect;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public OAuthConfig setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public OAuthConfig setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public List<String> getScopes() {
        return Collections.unmodifiableList(scopes);
    }

    public void addScope(String scope) {
        this.scopes.add(scope);
    }

    public Set<String> getRequiredClaims() {
        return Collections.unmodifiableSet(requiredClaims);
    }

    public OAuthConfig setRequiredClaims(Set<String> requiredClaims) {
        this.requiredClaims = new HashSet<>(requiredClaims);
        return this;
    }

    public Set<String> getProhibitedClaims() {
        return Collections.unmodifiableSet(prohibitedClaims);
    }

    public OAuthConfig setProhibitedClaims(Set<String> prohibitedClaims) {
        this.prohibitedClaims = new HashSet<>(prohibitedClaims);
        return this;
    }

    public Map<String, String> getExactMatchClaims() {
        return Collections.unmodifiableMap(exactMatchClaims);
    }

    public void setExactMatchClaims(Map<String, String> exactMatchClaims) {
        this.exactMatchClaims = new HashMap<>(exactMatchClaims);
    }

    public void addExactMatchClaim(String name, String value) {
        this.exactMatchClaims.put(name, value);
    }

    public Set<String> getAllowedAudiences() {
        return allowedAudiences == null ? null : Collections.unmodifiableSet(allowedAudiences);
    }

    public OAuthConfig setAllowedAudiences(Set<String> allowedAudiences) {
        if (allowedAudiences == null) {
            this.allowedAudiences = null;
        } else {
            this.allowedAudiences = new HashSet<>(allowedAudiences);
        }
        return this;
    }

    public Map<String, List<String>> getCustomParameters() {
        Map<String, List<String>> result = new HashMap<>();
        customParameters.forEach((k, v) -> result.put(k, Collections.unmodifiableList(v)));
        return result;
    }

    public OAuthConfig setCustomParameters(Map<String, List<String>> customParameters) {
        this.customParameters = new HashMap<>();
        customParameters.forEach((k, v) -> this.customParameters.put(k, new ArrayList<>(v)));
        return this;
    }

    public OAuthConfig addCustomParameter(String name, String value) {
        this.customParameters.computeIfAbsent(name, v -> new ArrayList<>()).add(value);
        return this;
    }

    public Class<? extends AccessTokenValidator> getAccessTokenValidator() {
        return accessTokenValidator;
    }

    public OAuthConfig setAccessTokenValidator(Class<? extends AccessTokenValidator> accessTokenValidator) {
        this.accessTokenValidator = accessTokenValidator;
        return this;
    }

    public boolean isAutoFetchUserInfo() {
        return autoFetchUserInfo;
    }

    public OAuthConfig setAutoFetchUserInfo(boolean autoFetchUserInfo) {
        this.autoFetchUserInfo = autoFetchUserInfo;
        return this;
    }

    public boolean isTreatScopesAsRoles() {
        return treatScopesAsRoles;
    }

    public OAuthConfig setTreatScopesAsRoles(boolean treatScopesAsRoles) {
        this.treatScopesAsRoles = treatScopesAsRoles;
        return this;
    }

    public String getAdditionalRolesClaim() {
        return additionalRolesClaim;
    }

    public OAuthConfig setAdditionalRolesClaim(String additionalRolesClaim) {
        this.additionalRolesClaim = additionalRolesClaim;
        return this;
    }

    public String getAdditionalPermissionsClaim() {
        return additionalPermissionsClaim;
    }

    public OAuthConfig setAdditionalPermissionsClaim(String additionalPermissionsClaim) {
        this.additionalPermissionsClaim = additionalPermissionsClaim;
        return this;
    }

    public boolean isDiscloseUnauthorizedReason() {
        return discloseUnauthorizedReason;
    }

    public OAuthConfig setDiscloseUnauthorizedReason(boolean discloseUnauthorizedReason) {
        this.discloseUnauthorizedReason = discloseUnauthorizedReason;
        return this;
    }

    @Config("provider")
    public static class ProviderConfig {
        private URI authorization;
        private URI token;
        private URI revocation;
        private URI issuer;
        private URI jwks;
        private URI userInfo;

        public URI getAuthorization() {
            return authorization;
        }

        public ProviderConfig setAuthorization(URI authorization) {
            this.authorization = authorization;
            return this;
        }

        public URI getToken() {
            return token;
        }

        public ProviderConfig setToken(URI token) {
            this.token = token;
            return this;
        }

        public URI getRevocation() {
            return revocation;
        }

        public void setRevocation(URI revocation) {
            this.revocation = revocation;
        }

        public URI getIssuer() {
            return issuer;
        }

        public ProviderConfig setIssuer(URI issuer) {
            this.issuer = issuer;
            return this;
        }

        public URI getJwks() {
            return jwks;
        }

        public ProviderConfig setJwks(URI jwks) {
            this.jwks = jwks;
            return this;
        }

        public URI getUserInfo() {
            return userInfo;
        }

        public ProviderConfig setUserInfo(URI userInfo) {
            this.userInfo = userInfo;
            return this;
        }
    }

    public static class AlgorithmConfig {
        private String accessSigningAlgorithm = "RS256";
        private String idSigningAlgorithm = "RS256";
        private boolean plainTokenAllowed = false;

        public String getAccessSigningAlgorithm() {
            return accessSigningAlgorithm;
        }

        public AlgorithmConfig setAccessSigningAlgorithm(String accessSigningAlgorithm) {
            this.accessSigningAlgorithm = accessSigningAlgorithm;
            return this;
        }

        public String getIdSigningAlgorithm() {
            return idSigningAlgorithm;
        }

        public AlgorithmConfig setIdSigningAlgorithm(String idSigningAlgorithm) {
            this.idSigningAlgorithm = idSigningAlgorithm;
            return this;
        }

        public boolean isPlainTokenAllowed() {
            return plainTokenAllowed;
        }

        public AlgorithmConfig setPlainTokenAllowed(boolean plainTokenAllowed) {
            this.plainTokenAllowed = plainTokenAllowed;
            return this;
        }
    }
}
