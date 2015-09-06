/*
 * Copyright 2013 dc-square GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.hivemq.plugin.fileauthentication.util;

import com.hivemq.plugin.fileauthentication.authentication.HashedSaltedPassword;
import com.hivemq.plugin.fileauthentication.exception.PasswordFormatException;
import com.google.common.base.Charsets;
import org.bouncycastle.util.encoders.Base64;

/**
 * This util extracts hash and salt from the given string.
 *
 * @author Christian Goetz
 */
public class HashSaltUtil {

    /**
     * Retrieves hash and salt.
     *
     * @param saltFirst specifies if the salt is place in front or behind of the hash
     * @param separator separator of the hash and salt
     * @param hashedSaltedPassword string which contains hash and salt together with separator
     * @return new {@link HashedSaltedPassword} with salt and hash
     * @throws PasswordFormatException if the format was wrong and hash/salt could not be retrieved correctly
     */
    public static HashedSaltedPassword retrieve(boolean saltFirst, String separator, String hashedSaltedPassword) throws PasswordFormatException {

        if (separator == null || hashedSaltedPassword == null || !hashedSaltedPassword.contains(separator)) {
            throw new PasswordFormatException("The format of the password in the credential file is not like expected!");
        }

        int separatorIndex = hashedSaltedPassword.indexOf(separator);

        String salt;
        String hash;
        if (saltFirst) {
            salt = new String(Base64.decode(hashedSaltedPassword.substring(0, separatorIndex).getBytes()), Charsets.UTF_8);
            hash = hashedSaltedPassword.substring(separatorIndex + 1);
        } else {
            salt = new String(Base64.decode(hashedSaltedPassword.substring(separatorIndex + 1)), Charsets.UTF_8);
            hash = hashedSaltedPassword.substring(0, separatorIndex);
        }

        return new HashedSaltedPassword(hash, salt);

    }

}
