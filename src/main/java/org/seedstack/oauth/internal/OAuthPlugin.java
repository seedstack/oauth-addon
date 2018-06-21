/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import io.nuun.kernel.api.plugin.InitState;
import io.nuun.kernel.api.plugin.context.InitContext;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.seed.SeedException;
import org.seedstack.seed.core.internal.AbstractSeedPlugin;
import org.seedstack.seed.web.internal.WebPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthPlugin extends AbstractSeedPlugin {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthPlugin.class);
    private OAuthProvider oauthProvider;
    private OAuthConfig oauthConfig;

    @Override
    public String name() {
        return "oauth";
    }

    @Override
    protected Collection<Class<?>> dependencies() {
        // We must initialize after the WebPlugin so we can access the contextPath in config
        return Lists.newArrayList(WebPlugin.class);
    }

    @Override
    protected InitState initialize(InitContext initContext) {
        oauthConfig = getConfiguration(OAuthConfig.class);
        resolveOAuthProvider(oauthConfig);
        return InitState.INITIALIZED;
    }

    private void resolveOAuthProvider(OAuthConfig oauthConfig) {
        URI discoveryDocument = oauthConfig.getDiscoveryDocument();
        OAuthConfig.ProviderConfig provider = oauthConfig.provider();
        if (discoveryDocument != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                oauthProvider = new DiscoveredOAuthProvider(
                        oauthConfig,
                        objectMapper.readValue(discoveryDocument.toURL(), DiscoveryDocument.class)
                );
            } catch (IOException e) {
                throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_FETCH_OPENID_CONNECT_DISCOVERY_DOCUMENT);
            }
        } else if (provider != null && provider.getAuthorization() != null && provider.getToken() != null) {
            oauthProvider = new ManualOAuthProvider(oauthConfig);
        }

        if (oauthProvider != null) {
            LOGGER.info("Configured OAuth provider " + oauthProvider.getIssuer().map(URI::toString).orElse("unknown"));
        } else {
            LOGGER.info("No OAuth provider configured");
        }
    }

    @Override
    public Object nativeUnitModule() {
        if (oauthProvider != null) {
            return new OAuthModule(oauthProvider, oauthConfig.getAccessTokenValidator());
        } else {
            return null;
        }
    }
}
