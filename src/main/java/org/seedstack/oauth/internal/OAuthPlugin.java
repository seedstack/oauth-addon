/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import static org.seedstack.shed.misc.PriorityUtils.sortByPriority;
import static org.seedstack.shed.reflect.ClassPredicates.classIsDescendantOf;
import static org.seedstack.shed.reflect.ClassPredicates.classIsInterface;
import static org.seedstack.shed.reflect.ClassPredicates.classModifierIs;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.nuun.kernel.api.plugin.InitState;
import io.nuun.kernel.api.plugin.context.InitContext;
import io.nuun.kernel.api.plugin.request.ClasspathScanRequest;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.kametic.specifications.Specification;
import org.seedstack.oauth.AccessTokenValidator;
import org.seedstack.oauth.OAuthConfig;
import org.seedstack.oauth.OAuthProvider;
import org.seedstack.seed.SeedException;
import org.seedstack.seed.core.internal.AbstractSeedPlugin;
import org.seedstack.seed.core.internal.utils.SpecificationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthPlugin extends AbstractSeedPlugin {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthPlugin.class);
    private static final Specification<Class<?>> ACCESS_TOKEN_VALIDATOR = new SpecificationBuilder<>(
            classIsInterface().negate()
                    .and(classModifierIs(Modifier.ABSTRACT).negate())
                    .and(classIsDescendantOf(AccessTokenValidator.class))).build();
    private final List<Class<? extends AccessTokenValidator<?>>> accessTokenValidatorClasses = new ArrayList<>();
    private OAuthProvider oAuthProvider;

    @Override
    public String name() {
        return "oauth";
    }

    @Override
    public Collection<ClasspathScanRequest> classpathScanRequests() {
        return classpathScanRequestBuilder()
                .specification(ACCESS_TOKEN_VALIDATOR)
                .build();
    }

    @Override
    protected InitState initialize(InitContext initContext) {
        OAuthConfig oAuthConfig = getConfiguration(OAuthConfig.class);
        resolveOAuthProvider(oAuthConfig);
        detectAccessTokenValidators(initContext);
        return InitState.INITIALIZED;
    }

    @Override
    public Object nativeUnitModule() {
        return new OAuthModule(oAuthProvider, accessTokenValidatorClasses);
    }

    @SuppressWarnings("unchecked")
    private void detectAccessTokenValidators(InitContext initContext) {
        for (Class<?> candidate : initContext.scannedTypesBySpecification().get(ACCESS_TOKEN_VALIDATOR)) {
            if (AccessTokenValidator.class.isAssignableFrom(candidate)) {
                LOGGER.trace("Detected access token validator {}", candidate.getName());
                accessTokenValidatorClasses.add((Class<? extends AccessTokenValidator<?>>) candidate);
            }
        }
        sortByPriority(accessTokenValidatorClasses);
        LOGGER.debug("Detected {} access token validator(s)", accessTokenValidatorClasses.size());
    }

    private void resolveOAuthProvider(OAuthConfig oAuthConfig) {
        URI discoveryDocument = oAuthConfig.getDiscoveryDocument();
        OAuthConfig.ProviderConfig provider = oAuthConfig.getProvider();
        if (discoveryDocument != null) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                oAuthProvider = new DiscoveredOAuthProvider(objectMapper.readValue(
                        discoveryDocument.toURL(),
                        DiscoveryDocument.class));
            } catch (IOException e) {
                throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_FETCH_OPENID_CONNECT_DISCOVERY_DOCUMENT);
            }
        } else if (provider != null) {
            oAuthProvider = new ManualOAuthProvider(oAuthConfig.getProvider());
        } else {
            throw SeedException.createNew(OAuthErrorCode.MISSING_DISCOVERY_DOCUMENT_OR_MANUAL_CONFIGURATION);
        }
        LOGGER.info("Configured OAuth provider " + oAuthProvider.getIssuer().map(URI::toString).orElse("unknown"));
    }
}
