/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import org.seedstack.seed.SeedException;
import org.seedstack.shed.exception.BaseException;

final class OAuthUtils {
    private OAuthUtils() {
        // no instantiation allowed
    }

    static BaseException buildGenericError(ErrorResponse errorResponse) {
        ErrorObject errorObject = errorResponse.getErrorObject();
        return SeedException.createNew(OAuthErrorCode.OAUTH_PROVIDER_RETURNED_AN_ERROR)
                .put("description", errorObject.getDescription())
                .put("code", errorObject.getCode())
                .put("httpStatus", errorObject.getHTTPStatusCode());
    }

    static URI stripQueryString(URI uri) {
        try {
            return new URI(uri.getScheme(),
                    uri.getAuthority(),
                    uri.getPath(),
                    null,
                    uri.getFragment());
        } catch (URISyntaxException e) {
            throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_PROCESS_URI);
        }
    }

    static Map<String, String> extractQueryParameters(URI uri) {
        final Map<String, String> queryPairs = new HashMap<>();
        String query = uri.getQuery();
        if (!Strings.isNullOrEmpty(query)) {
            try {
                final String[] pairs = query.split("&");
                for (String pair : pairs) {
                    final int idx = pair.indexOf("=");
                    final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
                    final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1),
                            "UTF-8") : null;
                    queryPairs.put(key, value);
                }
            } catch (UnsupportedEncodingException e) {
                throw SeedException.wrap(e, OAuthErrorCode.UNABLE_TO_PROCESS_URI);
            }
        }
        return queryPairs;
    }
}
