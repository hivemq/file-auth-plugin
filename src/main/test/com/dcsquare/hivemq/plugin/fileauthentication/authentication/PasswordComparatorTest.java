package com.dcsquare.hivemq.plugin.fileauthentication.authentication;

import com.dcsquare.hivemq.plugin.fileauthentication.util.HashSaltUtil;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Christian Goetz
 */
public class PasswordComparatorTest {

    private PasswordComparator passwordComparator;

    @Before
    public void setUp() throws Exception {
        passwordComparator = new PasswordComparator();

    }

    @Test
    public void test_validate_wrong_hashedsaltedpassword() throws Exception {
        String saltedhashedString = "M7NoPZ11kDRk5s69fMsSsnqvnOuOZmPpyORP2FVdIE4R7qyUJIrokWzSxHLYxh/4MDG8FghfN8dAJh6SEImj9Q==$77+977+977+977+9ZBxZJe+/vUbvv71HQu+/ve+/vU3vv73vv73vv70tf++/ve+/vVXGje+/ve+/vVdE77+977+977+977+9GO+/ve+/vRnvv712UEQcBO+/vVjvv73Rhw==";

        final HashedSaltedPassword hashedSaltedPassword = HashSaltUtil.retrieve(false, "$", saltedhashedString);

        String salt = hashedSaltedPassword.getSalt();
        String hash = hashedSaltedPassword.getHash();

        final boolean password = passwordComparator.validateHashedAndSaltedPassword("SHA-512", "wrong", hash, 1000000, salt);

        assertFalse(password);

    }

    @Test
    public void test_validate_correct_hashedsaltedpassword() throws Exception {
        String saltedhashedString = "M7NoPZ11kDRk5s69fMsSsnqvnOuOZmPpyORP2FVdIE4R7qyUJIrokWzSxHLYxh/4MDG8FghfN8dAJh6SEImj9Q==$77+977+977+977+9ZBxZJe+/vUbvv71HQu+/ve+/vU3vv73vv73vv70tf++/ve+/vVXGje+/ve+/vVdE77+977+977+977+9GO+/ve+/vRnvv712UEQcBO+/vVjvv73Rhw==";

        final HashedSaltedPassword hashedSaltedPassword = HashSaltUtil.retrieve(false, "$", saltedhashedString);

        String salt = hashedSaltedPassword.getSalt();
        String hash = hashedSaltedPassword.getHash();

        final boolean password = passwordComparator.validateHashedAndSaltedPassword("SHA-512", "password", hash, 1000000, salt);

        assertTrue(password);

    }


    @Test
    public void test_validate_wrong_saltedhashedpassword() throws Exception {
        String saltedhashedString = "77+9L++/vX9f77+9fmnvv73vv70e77+9OR4377+9UFrvv71tHzY377+92aPvv71gFm/vv73PgUgo77+9Tg/vv73vv73vv70e77+977+9We+/vRPvv70i$A2ZYZMkEkdKxIZcLDd8JmzI2EvXf0CunM1mzzrZ8UE5ZklGSTQWCJgnPwx6Ja5gndH1uFCQ/naXN7uj91hvBOQ==";

        final HashedSaltedPassword hashedSaltedPassword = HashSaltUtil.retrieve(true, "$", saltedhashedString);

        String salt = hashedSaltedPassword.getSalt();
        String hash = hashedSaltedPassword.getHash();

        final boolean password = passwordComparator.validateHashedAndSaltedPassword("SHA-512", "wrong", hash, 1000000, salt);

        assertFalse(password);

    }

    @Test
    public void test_validate_correct_saltedhashedpassword() throws Exception {
        String saltedhashedString = "77+9L++/vX9f77+9fmnvv73vv70e77+9OR4377+9UFrvv71tHzY377+92aPvv71gFm/vv73PgUgo77+9Tg/vv73vv73vv70e77+977+9We+/vRPvv70i$A2ZYZMkEkdKxIZcLDd8JmzI2EvXf0CunM1mzzrZ8UE5ZklGSTQWCJgnPwx6Ja5gndH1uFCQ/naXN7uj91hvBOQ==";

        final HashedSaltedPassword hashedSaltedPassword = HashSaltUtil.retrieve(true, "$", saltedhashedString);

        String salt = hashedSaltedPassword.getSalt();
        String hash = hashedSaltedPassword.getHash();

        final boolean password = passwordComparator.validateHashedAndSaltedPassword("SHA-512", "password", hash, 1000000, salt);

        assertTrue(password);

    }

    @Test
    public void test_validate_wrong_password() throws Exception {
        final boolean password = passwordComparator.validateHashedPassword("SHA-512", "wrong", "wcPX9K84FBCni8IaS9wpmt37YRv5hncjJ7vYCRtJj9gFgMAGESZt8oGvZTBWkog3EIZX3lA7EcnM4/qY4uDpUqzkSj/SISUc", 1000000);

        assertFalse(password);

    }

    @Test
    public void test_validate_correct_password() throws Exception {
        final boolean password = passwordComparator.validateHashedPassword("SHA-512", "password", "wcPX9K84FBCni8IaS9wpmt37YRv5hncjJ7vYCRtJj9gFgMAGESZt8oGvZTBWkog3EIZX3lA7EcnM4/qY4uDpUqzkSj/SISUc", 1000000);

        assertTrue(password);

    }

    @Test
    public void test_validate_correct_plaintext() throws Exception {
        String passwort1 = "p";
        String passwort2 = "p";

        assertTrue(passwordComparator.validatePlaintextPassword(passwort1, passwort2));

    }

    @Test
    public void test_validate_wrong_plaintext() throws Exception {
        String passwort1 = "p1";
        String passwort2 = "p2";

        assertFalse(passwordComparator.validatePlaintextPassword(passwort1, passwort2));

    }
}
