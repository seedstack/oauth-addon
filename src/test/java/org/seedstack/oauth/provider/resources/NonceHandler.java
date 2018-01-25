/*
 * Copyright © 2013-2017, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.seedstack.oauth.provider.resources;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NonceHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(NonceHandler.class);

    public void storeNonce(String nonce) {
        try {
            Files.write(Paths.get("temp.txt"), nonce.getBytes());
        } catch (IOException e) {
            LOGGER.debug("Unable to store nonce");
        }
    }

    public String getNonce() {
        BufferedReader br = null;
        String nonce = "";
        try {
            br = Files.newBufferedReader(Paths.get("temp.txt"));
            nonce = br.readLine();
        } catch (IOException e) {
            LOGGER.debug("Unable to retrieve nonce");
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    LOGGER.debug("Unable to close nonce reader");
                }
            }
        }
        return nonce;
    }

    public void deleteFile() {
        try {
            Files.delete(Paths.get("temp.txt"));
        } catch (IOException e) {
            LOGGER.debug("Unable to discard temporary nonce storage");
        }
    }
}
