/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.fixtures;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import org.seedstack.seed.security.SecuritySupport;
import org.seedstack.seed.security.principals.Principals;
import org.seedstack.seed.security.principals.SimplePrincipalProvider;

@Path("/profile")
public class ProfileResource {
    @Inject
    private SecuritySupport securitySupport;

    @GET
    @Produces("application/json")
    public ProfileRepresentation sayHello() {
        ProfileRepresentation profileRepresentation = new ProfileRepresentation();
        Optional.ofNullable(securitySupport.getSimplePrincipalByName(Principals.FIRST_NAME))
                .map(SimplePrincipalProvider::getPrincipal)
                .ifPresent(profileRepresentation::setFirstName);
        Optional.ofNullable(securitySupport.getSimplePrincipalByName(Principals.LAST_NAME))
                .map(SimplePrincipalProvider::getPrincipal)
                .ifPresent(profileRepresentation::setLastName);
        Optional.ofNullable(securitySupport.getSimplePrincipalByName(Principals.FULL_NAME))
                .map(SimplePrincipalProvider::getPrincipal)
                .ifPresent(profileRepresentation::setFullName);
        Optional.ofNullable(securitySupport.getSimplePrincipalByName("picture"))
                .map(SimplePrincipalProvider::getPrincipal)
                .ifPresent(profileRepresentation::setPictureUrl);

        Map<String, String> principals = new HashMap<>();
        for (SimplePrincipalProvider simplePrincipalProvider : securitySupport.getSimplePrincipals()) {
            principals.put(simplePrincipalProvider.getName(), simplePrincipalProvider.getValue());
        }
        profileRepresentation.setPrincipals(principals);

        return profileRepresentation;
    }
}
