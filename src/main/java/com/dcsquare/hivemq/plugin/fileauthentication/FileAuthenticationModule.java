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

package com.dcsquare.hivemq.plugin.fileauthentication;

import com.dcsquare.hivemq.plugin.fileauthentication.exception.ConfigurationFileNotFoundException;
import com.dcsquare.hivemq.plugin.fileauthentication.exception.ConfigurationInitializationException;
import com.dcsquare.hivemq.spi.HiveMQPluginModule;
import com.dcsquare.hivemq.spi.PluginEntryPoint;
import com.dcsquare.hivemq.spi.config.Configurations;
import com.dcsquare.hivemq.spi.plugin.meta.Information;
import com.dcsquare.hivemq.spi.util.PathUtils;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.inject.Provider;
import org.apache.commons.configuration.AbstractConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

/**
 * Plugin Configuration Class
 *
 * @author Christian Goetz
 */
@Information(name = "File Authentication Plugin", version = "2.0.1")
public class FileAuthenticationModule extends HiveMQPluginModule {

    private String reloadIntervalProperty = "reloadCredentialsInterval.seconds";

    /**
     * Specifies the configuration files used by the plugin in order to inform HiveMQ core, which files should be loaded.
     *
     * @return all configuration files used by this plugin.
     */
    @Override
    public Provider<Iterable<? extends AbstractConfiguration>> getConfigurations() {
        return new Provider<Iterable<? extends AbstractConfiguration>>() {
            @Override
            public Iterable<? extends AbstractConfiguration> get() {
                final ArrayList<AbstractConfiguration> abstractConfigurations = new ArrayList<AbstractConfiguration>();

                PropertiesConfiguration fileAuthConfiguration = getPluginConfiguration();

                final Optional<String> filename = Optional.fromNullable(fileAuthConfiguration.getString("filename"));
                if (filename.isPresent() && new File(getPluginFolder(), filename.get()).exists()) {
                    final int interval = fileAuthConfiguration.getInt(reloadIntervalProperty, 10);

                    abstractConfigurations.add(getReloadablePropertiesConfiguration(filename, interval));
                    abstractConfigurations.add(fileAuthConfiguration);
                    return abstractConfigurations;
                } else {
                    throw new ConfigurationFileNotFoundException("Credentials file " + filename.get() + " was not found in plugin folder:" + getPluginFolder().getAbsolutePath());
                }
            }
        };
    }

    /**
     * Creates new reloadable properties configuration for credential file.
     * <p/>
     * It was extracted for being able to override it in the test cases.
     *
     * @param filename credential file name
     * @param interval reload interval
     * @return reloadable properties configuration
     */
    @VisibleForTesting
    AbstractConfiguration getReloadablePropertiesConfiguration(Optional<String> filename, int interval) {
        return Configurations.newReloadablePropertiesConfiguration(filename.get(), interval, TimeUnit.SECONDS);
    }

    /**
     * Creates properties configuration for fileAuthConfiguration.properties
     * <p/>
     * It was extracted for being able to override it in the test cases.
     *
     * @return PropertiesConfiguration of configuration file fileAuthConfiguration.properties
     */
    @VisibleForTesting
    PropertiesConfiguration getPluginConfiguration() {
        PropertiesConfiguration fileAuthConfiguration = null;

        final File file = new File(getPluginFolder(), "fileAuthConfiguration.properties");
        if (!file.exists()) {
            throw new ConfigurationFileNotFoundException("fileAuthConfiguration.properties was not found in plugin folder:" + getPluginFolder().getAbsolutePath());
        }
        try {
            fileAuthConfiguration = new PropertiesConfiguration(file);
        } catch (ConfigurationException e) {
            throw new ConfigurationInitializationException(e.getMessage());
        }
        return fileAuthConfiguration;
    }

    /**
     * This method returns the HiveMQ plugin folder.
     * It was extracted for being able to override it in the test cases.
     *
     * @return plugin folder
     */
    @VisibleForTesting
    File getPluginFolder() {
        return PathUtils.getPluginFolder();
    }

    @Override
    protected void configurePlugin() {

    }

    /**
     * Returns the entry point class.
     *
     * @return {@link FileAuthMain}
     */
    @Override
    protected Class<? extends PluginEntryPoint> entryPointClass() {
        return FileAuthMain.class;
    }
}
