/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public interface OAuthProvider {
    boolean isOpenIdCapable();

    Optional<URI> getIssuer();

    URI getAuthorizationEndpoint();

    URI getTokenEndpoint();

    Optional<URI> getUserInfoEndpoint();

    Optional<URI> getRevocationEndpoint();

    List<String> getIdTokenSigningAlgValuesSupported();

    URI getJwksUri();
}
