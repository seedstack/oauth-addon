/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public interface OAuthService {
    default OAuthAuthenticationToken authenticateWithClientCredentials() {
        return authenticateWithClientCredentials(new ArrayList<>());
    }

    OAuthAuthenticationToken authenticateWithClientCredentials(List<String> scopes);

    OAuthProvider getOAuthProvider();

    Optional<String> validate(OAuthAuthenticationToken authenticationToken);
}
