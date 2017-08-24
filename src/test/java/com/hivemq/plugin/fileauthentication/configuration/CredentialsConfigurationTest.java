package com.hivemq.plugin.fileauthentication.configuration;

import com.google.common.base.Optional;
import com.hivemq.plugin.fileauthentication.authentication.FileAuthenticator;
import com.hivemq.plugin.fileauthentication.authentication.PasswordComparator;
import com.hivemq.plugin.fileauthentication.callback.CredentialChangeCallback;
import com.hivemq.spi.config.SystemInformation;
import com.hivemq.spi.security.ClientCredentialsData;
import com.hivemq.spi.services.PluginExecutorService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.reflection.Whitebox;

import java.io.File;
import java.io.FileWriter;
import java.net.InetAddress;
import java.util.Properties;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;


public class CredentialsConfigurationTest {


    private CredentialsConfiguration credentialsConfiguration;

    @Mock
    PluginExecutorService pluginExecutorService;

    @Mock
    SystemInformation systemInformation;

    @Mock
    ClientCredentialsData clientCredentialsData;


    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();


    @Mock
    Configuration configuration;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        credentialsConfiguration = new CredentialsConfiguration(pluginExecutorService, "", 10, systemInformation);
    }


    @Test
    public void credentialChange_sucess() throws Exception {

        File credentialsFile = temporaryFolder.newFile();
        try (FileWriter out = new FileWriter(credentialsFile, true)) {
            out.write("test = test \n asd = 3\n");
            out.flush();
            CredentialsConfiguration credentialsConfiguration = new CredentialsConfiguration(pluginExecutorService, credentialsFile.getAbsolutePath(), 1, systemInformation);
            credentialsConfiguration.init();

            int hashBefore = credentialsConfiguration.hashCode();

            Properties propertiesBefore = (Properties) credentialsConfiguration.getProperties().clone();
            out.write("testUser2 = testpw");
            out.flush();
            credentialsConfiguration.reload();
            int hashAfter = credentialsConfiguration.hashCode();
            assertTrue(hashBefore != hashAfter);
            assertFalse(credentialsConfiguration.getProperties().equals(propertiesBefore));
        }
    }

    @Test
    public void credentialChange_cache_invalidated_login_sucess() throws Exception {
        File credentialsFile = temporaryFolder.newFile();

        try (FileWriter out = new FileWriter(credentialsFile, true)) {
            out.write("test=test\n asd=3 \n");
            out.flush();
            CredentialsConfiguration credentialsConfiguration = new CredentialsConfiguration(pluginExecutorService, credentialsFile.getAbsolutePath(), 1, systemInformation);
            credentialsConfiguration.init();

            configuration = new Configuration(pluginExecutorService, systemInformation);
            Whitebox.setInternalState(configuration, "credentialsConfiguration", credentialsConfiguration);

            final String user = "testUser";
            final String pw = "testPw";

            when(clientCredentialsData.getUsername()).thenReturn(Optional.of(user));
            when(clientCredentialsData.getPassword()).thenReturn(Optional.of(pw));
            when(clientCredentialsData.getInetAddress()).thenReturn(Optional.of(InetAddress.getLoopbackAddress()));
            Whitebox.setInternalState(configuration, "credentialsConfiguration", credentialsConfiguration);

            FileAuthenticator fileAuthenticator = new FileAuthenticator(configuration, new PasswordComparator());

            Whitebox.setInternalState(fileAuthenticator, "isHashed", false);//otherwise hashing is active

            credentialsConfiguration.reload();
            Boolean isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);
            assertFalse(isAuthenticated);


            out.write(user + "=" + pw);
            out.flush();
            credentialsConfiguration.reload();

            isAuthenticated = fileAuthenticator.checkCredentials(clientCredentialsData);
            assertTrue(isAuthenticated);


        }
    }


    @Test
    public void add_callback_test_success() throws Exception {

        CredentialChangeCallback callback = new CredentialChangeCallback() {
            @Override
            public void onCredentialChange() {
            }
        };
        Boolean ret = credentialsConfiguration.addCallback(callback);
        assertTrue(ret);
    }

    @Test
    public void add_callback_test_duplicates() throws Exception {

        CredentialChangeCallback callback = new CredentialChangeCallback() {
            @Override
            public void onCredentialChange() {

            }
        };
        credentialsConfiguration.addCallback(callback);
        final Boolean ret = credentialsConfiguration.addCallback(callback);
        assertFalse(ret);

    }


    @Test(expected = NullPointerException.class)
    public void add_callback_test_null() throws Exception {
        credentialsConfiguration.addCallback(null);
    }

    @Test
    public void BadInput_test() throws Exception {
        File credentialsFile = temporaryFolder.newFile();
        try (FileWriter out = new FileWriter(credentialsFile, false)) {
            out.write("test = test \n asd = 3\n");
            out.flush();
            CredentialsConfiguration config = new CredentialsConfiguration(pluginExecutorService, credentialsFile.getAbsolutePath(), 1, systemInformation);
            config.init();
            out.write("badFormat");
            out.flush();
            config.reload();
            String pw = config.getUser("badFormat");
            assertNull(pw);
        }

    }


}
