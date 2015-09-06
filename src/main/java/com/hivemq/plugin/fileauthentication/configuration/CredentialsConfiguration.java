package com.hivemq.plugin.fileauthentication.configuration;

import com.hivemq.spi.services.PluginExecutorService;

import javax.inject.Inject;
import java.io.File;

/**
 * @author Christian Götz
 */
public class CredentialsConfiguration extends ReloadingPropertiesReader {

    private final String filename;
    private final int reloadSeconds;

    @Inject
    public CredentialsConfiguration(final PluginExecutorService pluginExecutorService, String filename, int reloadSeconds) {
        super(pluginExecutorService);

        this.filename = filename;
        this.reloadSeconds = reloadSeconds;
    }

    public String getUser(String username) {
        return properties.getProperty(username);
    }

    @Override
    public String getFilename() {
        return "plugins" + File.separator + filename;
    }

    @Override
    public int getReloadIntervalinSeconds() {
        return reloadSeconds;
    }
}