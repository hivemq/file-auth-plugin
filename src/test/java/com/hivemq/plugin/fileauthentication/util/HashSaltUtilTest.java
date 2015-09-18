/*
 * Copyright 2015 dc-square GmbH
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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;

/**
 * @author Christian Goetz
 */
public class HashSaltUtilTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void test_no_separator() throws Exception {
        exception.expect(PasswordFormatException.class);
        HashSaltUtil.retrieve(false, null, "t$t");
    }

    @Test
    public void test_no_password() throws Exception {
        exception.expect(PasswordFormatException.class);
        HashSaltUtil.retrieve(false, "$", null);
    }

    @Test
    public void test_no_separator_in_password() throws Exception {
        exception.expect(PasswordFormatException.class);
        HashSaltUtil.retrieve(false, "$", "test");
    }

    @Test
    public void test_is_salt_first() throws Exception {
        String salt = "salt";
        String hash = "hash";
        String separator = "$";

        String saltBase64 = new String(Base64.encode(salt.getBytes()), Charsets.UTF_8);

        final HashedSaltedPassword hashedSaltedPassword = HashSaltUtil.retrieve(true, separator, saltBase64 + separator + hash);

        assertEquals(hashedSaltedPassword.getHash(), hash);
        assertEquals(hashedSaltedPassword.getSalt(), salt);


    }

    @Test
    public void test_is_hash_first() throws Exception {
        String salt = "salt";
        String hash = "hash";
        String separator = "$";

        String saltBase64 = new String(Base64.encode(salt.getBytes()), Charsets.UTF_8);

        final HashedSaltedPassword hashedSaltedPassword = HashSaltUtil.retrieve(false, separator, hash + separator + saltBase64);

        assertEquals(hashedSaltedPassword.getHash(), hash);
        assertEquals(hashedSaltedPassword.getSalt(), salt);


    }
}
