/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
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
}
