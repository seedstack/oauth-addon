/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.nuun.kernel.api.plugin.InitState;
import io.nuun.kernel.api.plugin.context.InitContext;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.seed.SeedException;
import org.seedstack.seed.core.internal.AbstractSeedPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;

public class OAuthPlugin extends AbstractSeedPlugin {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthPlugin.class);
    private OAuthConfig oauthConfig;
    private OidcDiscoveryDocument discoveryDocument;
    private boolean configured;

    @Override
    public String name() {
        return "oauth";
    }

    @Override
    protected InitState initialize(InitContext initContext) {
        oauthConfig = getConfiguration(OAuthConfig.class);
        discoveryDocument = resolveDiscoveryDocument();
        if (discoveryDocument != null) {
            LOGGER.info("Discovered OpenIdConnect provider " + discoveryDocument.getIssuer());
            configured = true;
        } else if (oauthConfig.provider().getAuthorization() != null && oauthConfig.provider().getToken() != null) {
            if (oauthConfig.provider().getIssuer() != null) {
                LOGGER.info("Configured OpenIdConnect provider " + oauthConfig.provider().getIssuer());
            } else {
                LOGGER.info("Configured OAuth provider");
            }
            configured = true;
        } else {
            LOGGER.info("No OAuth provider configured");
        }
        return InitState.INITIALIZED;
    }

    private OidcDiscoveryDocument resolveDiscoveryDocument() {
        URI discoveryDocument = oauthConfig.getDiscoveryDocument();
        if (discoveryDocument != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                return objectMapper.readValue(discoveryDocument.toURL(), OidcDiscoveryDocument.class);
            } catch (IOException e) {
                throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_FETCH_OPENID_CONNECT_DISCOVERY_DOCUMENT);
            }
        } else {
            return null;
        }
    }

    @Override
    public Object nativeUnitModule() {
        if (configured) {
            return new OAuthModule(discoveryDocument, oauthConfig.getAccessTokenValidator());
        } else {
            return null;
        }
    }
}
