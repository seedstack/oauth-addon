/*
 * Copyright © 2013-2018, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.internal;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.io.Serializable;

public class SerializableUserInfo extends UserInfo implements Serializable {
    public SerializableUserInfo(UserInfo userInfo) {
        super(userInfo.toJSONObject());
    }

    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
        try {
            out.writeUTF(toJWTClaimsSet().toJSONObject().toString());
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new IOException("Error during JWT claim set parsing", e);
        }
    }

    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            this.claims.clear();
            this.claims.putAll(JSONObjectUtils.parse(in.readUTF()));
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new IOException("Error during JWT claim set parsing", e);
        }
    }

    private void readObjectNoData() throws ObjectStreamException {
        this.claims.clear();
    }
}
