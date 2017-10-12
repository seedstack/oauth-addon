/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.validation.Valid;
import org.hibernate.validator.constraints.NotBlank;
import org.seedstack.coffig.Config;

@Config("security.oauth")
public class OAuthConfig {
    @Valid
    private EndpointConfig endpoints = new EndpointConfig();
    private List<String> scopes = new ArrayList<>();
    @NotBlank
    private String clientId;
    @NotBlank
    private String clientSecret;

    public EndpointConfig endpoints() {
        return endpoints;
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

    @Config("endpoints")
    public static class EndpointConfig {
        @NotBlank
        private String authorization;
        @NotBlank
        private String token;
        @NotBlank
        private String redirect;
        private String userInfo;

        public String getAuthorization() {
            return authorization;
        }

        public EndpointConfig setAuthorization(String authorization) {
            this.authorization = authorization;
            return this;
        }

        public String getToken() {
            return token;
        }

        public EndpointConfig setToken(String token) {
            this.token = token;
            return this;
        }

        public String getRedirect() {
            return redirect;
        }

        public EndpointConfig setRedirect(String redirect) {
            this.redirect = redirect;
            return this;
        }

        public String getUserInfo() {
            return userInfo;
        }

        public EndpointConfig setUserInfo(String userInfo) {
            this.userInfo = userInfo;
            return this;
        }
    }
}
