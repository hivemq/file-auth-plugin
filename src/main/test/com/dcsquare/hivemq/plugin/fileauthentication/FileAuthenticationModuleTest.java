package com.dcsquare.hivemq.plugin.fileauthentication;

import com.dcsquare.hivemq.plugin.fileauthentication.exception.ConfigurationFileNotFoundException;
import com.google.common.base.Optional;
import org.apache.commons.configuration.AbstractConfiguration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.io.FileUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.File;

import static org.junit.Assert.assertEquals;

/**
 * @author Christian Goetz
 */
public class FileAuthenticationModuleTest {

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void test_configuration_file_not_found() throws Exception {
        File tempFolder = testFolder.getRoot();

        FileAuthenticationModuleForTest fileAuthenticationModule = new FileAuthenticationModuleForTest(tempFolder);
        expectedException.expect(ConfigurationFileNotFoundException.class);
        expectedException.expectMessage("fileAuthConfiguration.properties was not found in plugin folder:");
        fileAuthenticationModule.getPluginConfiguration();

    }

    @Test
    public void test_credential_file_not_found() throws Exception {
        File tempFolder = testFolder.getRoot();
        final File file = testFolder.newFile("fileAuthConfiguration.properties");
        final String credentialFile = "credentials.properties";
        FileUtils.writeStringToFile(file, "filename=" + credentialFile);

        FileAuthenticationModuleForTest fileAuthenticationModule = new FileAuthenticationModuleForTest(tempFolder);
        expectedException.expect(ConfigurationFileNotFoundException.class);
        expectedException.expectMessage("Credentials file " + credentialFile + " was not found in plugin folder:");
        fileAuthenticationModule.getConfigurations().get();

    }

    @Test
    public void test_size_of_configuration() throws Exception {
        File tempFolder = testFolder.getRoot();
        final File file = testFolder.newFile("fileAuthConfiguration.properties");
        FileUtils.writeStringToFile(file, "filename=credentials.properties");
        testFolder.newFile("credentials.properties");

        FileAuthenticationModuleForTest fileAuthenticationModule = new FileAuthenticationModuleForTest(tempFolder);
        final Iterable<? extends AbstractConfiguration> abstractConfigurations = fileAuthenticationModule.getConfigurations().get();

        int size = 0;
        for (AbstractConfiguration abstractConfiguration : abstractConfigurations) {
            size++;
        }

        assertEquals(size, 2);
    }

    class FileAuthenticationModuleForTest extends FileAuthenticationModule {

        File file;

        @Override
        AbstractConfiguration getReloadablePropertiesConfiguration(Optional<String> filename, int interval) {
            return new PropertiesConfiguration();
        }

        FileAuthenticationModuleForTest(File file) {
            this.file = file;
        }

        @Override
        File getPluginFolder() {
            return file;
        }
    }

}
