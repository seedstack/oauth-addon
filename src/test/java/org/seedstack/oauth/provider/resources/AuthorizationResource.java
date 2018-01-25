/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.provider.resources;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

@Path("/provider/authorize")
public class AuthorizationResource {
    private static final String CODE = "4/n-RGoEYxlrWeK99Y1aAc6T59bqY65kXHtMxngInIOjM";

    @GET
    public Response authoriseUser(@QueryParam("redirect_uri") String redirect_uri,
            @QueryParam("state") String state, @QueryParam("nonce") String nonce)
            throws UnsupportedEncodingException {
        NonceHandler n = new NonceHandler();
        n.storeNonce(nonce);

        return Response.status(302).header("Location",
                URLDecoder.decode(redirect_uri, "UTF-8") + "?" + "code=" + CODE + "&state=" + state).build();

    }

}
