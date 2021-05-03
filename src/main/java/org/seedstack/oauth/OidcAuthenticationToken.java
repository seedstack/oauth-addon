/*
 * Copyright © 2013-2021, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import java.util.Map;

public interface OidcAuthenticationToken extends OAuthAuthenticationToken {
    /**
     * @return the ID JSON Web Token (JWT) in its compact format consisting
     * of Base64URL-encoded parts delimited by period ('.') characters.
     */
    String getIdToken();

    /**
     * @return all the claims present in the identity token.
     */
    Map<String, Object> getIdClaims();
}
