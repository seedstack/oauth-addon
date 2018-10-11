/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.nuun.kernel.api.plugin.InitState;
import io.nuun.kernel.api.plugin.context.InitContext;
import java.io.IOException;
import java.net.URI;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.seed.SeedException;
import org.seedstack.seed.core.internal.AbstractSeedPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthPlugin extends AbstractSeedPlugin {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthPlugin.class);
    private OAuthConfig oauthConfig;
    private OidcDiscoveryDocument discoveryDocument;

    @Override
    public String name() {
        return "oauth";
    }

    @Override
    protected InitState initialize(InitContext initContext) {
        oauthConfig = getConfiguration(OAuthConfig.class);
        discoveryDocument = resolveOAuthProvider(oauthConfig);
        if (discoveryDocument != null) {
            LOGGER.info("Discovered OpenIdConnect provider " + discoveryDocument.getIssuer());
        } else if (oauthConfig.openIdConnect().getIssuer() != null) {
            LOGGER.info("Configured OpenIdConnect provider " + oauthConfig.openIdConnect().getIssuer());
        } else {
            LOGGER.info("Configured OAuth provider");
        }
        return InitState.INITIALIZED;
    }

    private OidcDiscoveryDocument resolveOAuthProvider(OAuthConfig oauthConfig) {
        URI discoveryDocument = oauthConfig.getDiscoveryDocument();
        OAuthConfig.ProviderConfig provider = oauthConfig.provider();
        if (discoveryDocument != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                return objectMapper.readValue(discoveryDocument.toURL(), OidcDiscoveryDocument.class);
            } catch (IOException e) {
                throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_FETCH_OPENID_CONNECT_DISCOVERY_DOCUMENT);
            }
        } else if (provider != null && provider.getAuthorization() != null && provider.getToken() != null) {
            return null;
        }
    }

    @Override
    public Object nativeUnitModule() {
        return new OAuthModule(discoveryDocument, oauthConfig.getAccessTokenValidator());
    }
}
