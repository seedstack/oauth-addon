/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.fixtures;

import org.seedstack.shed.exception.ErrorCode;

public enum TokenErrorCode implements ErrorCode {
    UNABLE_TO_FETCH_PRIVATE_KEY,
    FAILED_TO_LOAD_JWKS
}
