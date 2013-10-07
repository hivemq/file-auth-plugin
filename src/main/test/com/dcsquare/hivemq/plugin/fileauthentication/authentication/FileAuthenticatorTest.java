package com.dcsquare.hivemq.plugin.fileauthentication.authentication;

import com.dcsquare.hivemq.plugin.fileauthentication.exception.PasswordFormatException;
import com.dcsquare.hivemq.spi.security.ClientCredentialsData;
import com.google.common.base.Optional;
import org.apache.commons.configuration.Configuration;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author Christian Goetz
 */
public class FileAuthenticatorTest {

    @Mock
    PasswordComparator passwordComparator;

    @Mock
    Configuration configuration;

    @Mock
    ClientCredentialsData clientCredentialsData;

    FileAuthenticator fileAuthenticator;

    @Before
    public void setUp() throws Exception {
        initMocks(this);
    }

    @Test
    public void test_no_username() throws Exception {

        when(clientCredentialsData.getUsername()).thenReturn(Optional.<String>absent());
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of("password"));

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }

    @Test
    public void test_no_password() throws Exception {

        when(clientCredentialsData.getUsername()).thenReturn(Optional.of("user"));
        when(clientCredentialsData.getPassword()).thenReturn(Optional.<String>absent());

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }

    @Test
    public void test_user_is_not_present_in_credential_file() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of("password"));

        when(configuration.getString(providedUsername)).thenReturn(null);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }

    @Test
    public void test_user_correct_plaintext_password() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "password";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashing.enabled")).thenReturn(false);

        when(passwordComparator.validatePlaintextPassword(filePassword, providedPassword)).thenReturn(true);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertTrue(isAuthenticated);
    }

    @Test
    public void test_user_wrong_plaintext_password() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "wrong";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashing.enabled")).thenReturn(false);

        when(passwordComparator.validatePlaintextPassword(filePassword, providedPassword)).thenReturn(false);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }

    @Test
    public void test_user_correct_hashed_password() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "password";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashingSalt.enabled", true)).thenReturn(false);
        when(configuration.getBoolean("passwordHashing.enabled", true)).thenReturn(true);
        final String algorithm = "SHA-512";
        when(configuration.getString("passwordHashing.algorithm", "SHA-512")).thenReturn(algorithm);
        final int iterations = 1000000;
        when(configuration.getInt("passwordHashing.iterations", 1000000)).thenReturn(iterations);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        when(passwordComparator.validateHashedPassword(algorithm, providedPassword, filePassword, iterations)).thenReturn(true);


        FileAuthenticator fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertTrue(isAuthenticated);
    }

    @Test
    public void test_user_wrong_hashed_password() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "wrong";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashingSalt.enabled", true)).thenReturn(false);
        when(configuration.getBoolean("passwordHashing.enabled", true)).thenReturn(true);
        final String algorithm = "SHA-512";
        when(configuration.getString("passwordHashing.algorithm", "SHA-512")).thenReturn(algorithm);
        final int iterations = 1000000;
        when(configuration.getInt("passwordHashing.iterations", 1000000)).thenReturn(iterations);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        when(passwordComparator.validateHashedPassword(algorithm, providedPassword, filePassword, iterations)).thenReturn(false);


        FileAuthenticator fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }


    @Test
    public void test_user_correct_salted_password() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "password";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashingSalt.enabled", true)).thenReturn(true);
        when(configuration.getBoolean("passwordHashing.enabled", true)).thenReturn(true);
        final String algorithm = "SHA-512";
        when(configuration.getString("passwordHashing.algorithm", "SHA-512")).thenReturn(algorithm);
        final int iterations = 1000000;
        when(configuration.getInt("passwordHashing.iterations", 1000000)).thenReturn(iterations);

        final String salt = "salt";
        final String hash = "hash";
        HashedSaltedPassword abc = new HashedSaltedPassword(hash, salt);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        when(passwordComparator.validateHashedAndSaltedPassword(algorithm, providedPassword, hash, iterations, salt)).thenReturn(true);


        FileAuthenticatorForTest fileAuthenticator = new FileAuthenticatorForTest(configuration, passwordComparator, abc);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertTrue(isAuthenticated);
    }


    @Test
    public void test_user_wrong_salted_password() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "wrong";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashingSalt.enabled", true)).thenReturn(true);
        when(configuration.getBoolean("passwordHashing.enabled", true)).thenReturn(true);
        final String algorithm = "SHA-512";
        when(configuration.getString("passwordHashing.algorithm", "SHA-512")).thenReturn(algorithm);
        final int iterations = 1000000;
        when(configuration.getInt("passwordHashing.iterations", 1000000)).thenReturn(iterations);

        final String salt = "salt";
        final String hash = "hash";
        HashedSaltedPassword abc = new HashedSaltedPassword(hash, salt);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        when(passwordComparator.validateHashedAndSaltedPassword(algorithm, providedPassword, hash, iterations, salt)).thenReturn(false);


        FileAuthenticatorForTest fileAuthenticator = new FileAuthenticatorForTest(configuration, passwordComparator, abc);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }


    @Test
    public void test_user_wrong_salt_hash_format() throws Exception {

        final String providedUsername = "user";
        when(clientCredentialsData.getUsername()).thenReturn(Optional.of(providedUsername));
        final String providedPassword = "wrong";
        when(clientCredentialsData.getPassword()).thenReturn(Optional.of(providedPassword));

        final String filePassword = "password";
        when(configuration.getString(providedUsername)).thenReturn(filePassword);
        when(configuration.getBoolean("passwordHashingSalt.enabled", true)).thenReturn(true);
        when(configuration.getBoolean("passwordHashing.enabled", true)).thenReturn(true);
        final String algorithm = "SHA-512";
        when(configuration.getString("passwordHashing.algorithm", "SHA-512")).thenReturn(algorithm);
        final int iterations = 1000000;
        when(configuration.getInt("passwordHashing.iterations", 1000000)).thenReturn(iterations);

        final String salt = "salt";
        final String hash = "hash";
        HashedSaltedPassword abc = new HashedSaltedPassword(hash, salt);

        fileAuthenticator = new FileAuthenticator(configuration, passwordComparator);
        when(passwordComparator.validateHashedAndSaltedPassword(algorithm, providedPassword, hash, iterations, salt)).thenReturn(true);


        FileAuthenticatorForTest2 fileAuthenticator = new FileAuthenticatorForTest2(configuration, passwordComparator, abc);
        final Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);

        assertFalse(isAuthenticated);
    }

    class FileAuthenticatorForTest extends FileAuthenticator {

        public HashedSaltedPassword hashedSaltedPassword;

        public FileAuthenticatorForTest(Configuration configurations, PasswordComparator passwordComparator, HashedSaltedPassword hashedSaltedPassword) {
            super(configurations, passwordComparator);
            this.hashedSaltedPassword = hashedSaltedPassword;
        }

        @Override
        HashedSaltedPassword getHashAndSalt(String hashedPassword) throws PasswordFormatException {
            return hashedSaltedPassword;
        }
    }

    class FileAuthenticatorForTest2 extends FileAuthenticator {

        public HashedSaltedPassword hashedSaltedPassword;

        public FileAuthenticatorForTest2(Configuration configurations, PasswordComparator passwordComparator, HashedSaltedPassword hashedSaltedPassword) {
            super(configurations, passwordComparator);
            this.hashedSaltedPassword = hashedSaltedPassword;
        }

        @Override
        HashedSaltedPassword getHashAndSalt(String hashedPassword) throws PasswordFormatException {
            throw new PasswordFormatException("Wrong Format");
        }
    }


}
