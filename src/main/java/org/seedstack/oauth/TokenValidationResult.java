/*
 * Copyright © 2013-2020, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth;

import java.util.*;

/**
 * This class describes the information obtained from successful token validation: the subject id if authenticated
 * (empty string otherwise), the granted scopes, the identity claims, the access claims,  and the raw tokens.
 */
public class TokenValidationResult {
    private final String subjectId;
    private final List<String> scopes;
    private final Map<String, Object> claims;
    private final Map<String, Object> accessClaims;
    private final OAuthAuthenticationToken token;

    public TokenValidationResult(String subjectId, List<String> scopes, Map<String, Object> claims,
                                 Map<String, Object> accessClaims, OAuthAuthenticationToken token) {
        this.subjectId = subjectId;
        this.scopes = new ArrayList<>(scopes);
        this.claims = new HashMap<>(claims);
        this.accessClaims = new HashMap<>(accessClaims);
        this.token = token;
    }

    public String getSubjectId() {
        return subjectId;
    }

    public List<String> getScopes() {
        return Collections.unmodifiableList(scopes);
    }

    public Map<String, Object> getClaims() {
        return Collections.unmodifiableMap(claims);
    }

    public Map<String, Object> getAccessClaims() {
        return Collections.unmodifiableMap(accessClaims);
    }

    public OAuthAuthenticationToken getToken() {
        return token;
    }

    public boolean isAnonymous() {
        return subjectId == null || subjectId.isEmpty();
    }
}
