/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.oauth.internal;

import org.seedstack.shed.exception.ErrorCode;

enum OAuthErrorCode implements ErrorCode {
    UNABLE_TO_FIND_SUITABLE_ACCESS_TOKEN_VALIDATOR,
    MISSING_DISCOVERY_DOCUMENT_OR_MANUAL_CONFIGURATION, UNABLE_TO_FETCH_OPENID_CONNECT_DISCOVERY_DOCUMENT
}
