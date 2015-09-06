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
