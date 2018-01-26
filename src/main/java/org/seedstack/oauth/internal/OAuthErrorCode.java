/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import org.seedstack.shed.exception.ErrorCode;

enum OAuthErrorCode implements ErrorCode {
    FAILED_TO_PARSE_AUTHORIZATION_RESPONSE,
    FAILED_TO_REQUEST_TOKENS,
    MISSING_DISCOVERY_DOCUMENT_OR_MANUAL_CONFIGURATION,
    OAUTH_PROVIDER_RETURNED_AN_ERROR,
    SIGNING_ALGORITHM_NOT_SUPPORTED_BY_PROVIDER,
    UNABLE_TO_FETCH_OPENID_CONNECT_DISCOVERY_DOCUMENT,
    UNABLE_TO_PROCESS_URI
}
