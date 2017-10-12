/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.seedstack.coffig.Config;
import org.seedstack.coffig.SingleValue;

@Config("security.oauth")
public class OAuthConfig {
    private OpenIdConnectConfig openIdConnect = new OpenIdConnectConfig();
    private ProviderConfig provider;
    private URI discoveryDocument;
    private URI redirect;
    private String clientId;
    private String clientSecret;
    private List<String> scopes = new ArrayList<>();

    public OpenIdConnectConfig openIdConnect() {
        return openIdConnect;
    }

    public URI getDiscoveryDocument() {
        return discoveryDocument;
    }

    public OAuthConfig setDiscoveryDocument(URI discoveryDocument) {
        this.discoveryDocument = discoveryDocument;
        return this;
    }

    public ProviderConfig getProvider() {
        return provider;
    }

    public OAuthConfig setProvider(ProviderConfig provider) {
        this.provider = provider;
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

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getScopes() {
        return Collections.unmodifiableList(scopes);
    }

    public void addScope(String scope) {
        this.scopes.add(scope);
    }

    @Config("openIdConnect")
    public static class OpenIdConnectConfig {
        @SingleValue
        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public OpenIdConnectConfig setEnabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }
    }

    @Config("provider")
    public static class ProviderConfig {
        private URI authorization;
        private URI token;
        private URI userInfo;
        private URI revocation;

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

        public URI getUserInfo() {
            return userInfo;
        }

        public ProviderConfig setUserInfo(URI userInfo) {
            this.userInfo = userInfo;
            return this;
        }

        public URI getRevocation() {
            return revocation;
        }

        public void setRevocation(URI revocation) {
            this.revocation = revocation;
        }
    }
}
