/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import org.seedstack.oauth.AccessClaims;
import org.seedstack.seed.security.principals.PrincipalProvider;

import java.util.HashMap;
import java.util.Map;

class AccessClaimsPrincipalProvider implements PrincipalProvider<AccessClaims> {
    private final InternalAccessClaims accessClaims;

    AccessClaimsPrincipalProvider(Map<String, Object> accessClaims) {
        this.accessClaims = new InternalAccessClaims(accessClaims);
    }

    @Override
    public AccessClaims get() {
        return accessClaims;
    }

    private static class InternalAccessClaims extends HashMap<String, Object> implements AccessClaims {
        private static final long serialVersionUID = 1L;

        private InternalAccessClaims(Map<String, Object> accessClaims) {
            super(accessClaims);
        }
    }
}
