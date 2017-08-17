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

package com.hivemq.plugin.fileauthentication.configuration;

import com.google.common.base.Optional;
import com.hivemq.plugin.fileauthentication.callbacks.CredentialChangeCallback;
import com.hivemq.plugin.fileauthentication.exception.ConfigurationFileNotFoundException;
import com.hivemq.spi.config.SystemInformation;
import com.hivemq.spi.services.PluginExecutorService;
import com.hivemq.spi.services.configuration.ValueChangedCallback;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * This reads a property file and provides some utility methods for working with {@link Properties}
 *
 * @author Christoph Schäbel
 * @author Christian Götz
 */
@Singleton
public class Configuration extends ReloadingPropertiesReader {

    /**
     *  Default for the reloadinterval for the .property files in seconds
     */
    private static final String DEFAULT_VALUE_RELOAD = "10";

    /**
     * Default for the time credentials are cached in seconds
     */
    private static final String DEFAULT_VALUE_CACHING_TIME = "10";

    /**
     * Default for the number of Hashing Iterations
     */
    private static final String DEFAULT_VALUE_HASHING_ITERATIONS = "100";


    private final PluginExecutorService pluginExecutorService;
    private final SystemInformation systemInformation;
    private RestartListener listener;
    private CredentialsConfiguration credentialsConfiguration;
    private int previousCredentialsHash;
    private final List<CredentialChangeCallback> callbacks;


    @Inject
    public Configuration(final PluginExecutorService pluginExecutorService, SystemInformation systemInformation) {
        super(pluginExecutorService, systemInformation);
        this.pluginExecutorService = pluginExecutorService;
        this.systemInformation = systemInformation;
        this.callbacks = new ArrayList<>();

        init();

        final ValueChangedCallback callback = new ValueChangedCallback() {
            @Override
            public void valueChanged(final Object newValue) {
                if (listener != null) {
                    listener.restart();
                }
            }
        };

        addCallback("filename", callback);
        addCallback("reloadCredentialsInterval.seconds", callback);
        addCallback("passwordHashing.enabled", callback);
        addCallback("passwordHashing.iterations", callback);
        addCallback("passwordHashing.algorithm", callback);
        addCallback("passwordHashingSalt.separationChar", callback);
        addCallback("passwordHashingSalt.enabled", callback);
        addCallback("passwordHashingSalt.isFirst", callback);
        addCallback("cachingTime.seconds", callback);
        addCallback("cacheSize", callback);


        //for the CredentialChangedCallback
        pluginExecutorService.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                if (credentialsChanged()) {
                    for (CredentialChangeCallback callback : callbacks) {
                        callback.onCredentialChange();
                    }
                }
            }
        }, 10, getReloadInterval(), TimeUnit.SECONDS);
    }

    @PostConstruct
    public void postConstruct() {

        final Optional<String> filename = Optional.fromNullable(getCredentialsFilename());
        if (filename.isPresent() && new File(systemInformation.getConfigFolder(), filename.get()).exists()) {
            credentialsConfiguration = new CredentialsConfiguration(pluginExecutorService, getCredentialsFilename(), getReloadInterval(),systemInformation);
            credentialsConfiguration.init();
        } else {
            throw new ConfigurationFileNotFoundException("Credentials file " + filename.get() + " was not found in plugin folder:" + systemInformation.getPluginFolder().getAbsolutePath());
        }
    }

    public String getCredentialsFilename() {
        return properties.getProperty("filename", "credentials.properties");
    }

    public int getReloadInterval() {
        return Integer.parseInt(properties.getProperty("reloadCredentialsInterval.seconds", DEFAULT_VALUE_RELOAD));
    }

    public int getCachingTime() {
        return Integer.parseInt(properties.getProperty("cachingTime.seconds", DEFAULT_VALUE_CACHING_TIME));
    }

    public int getCacheSize() {
        return Integer.parseInt(properties.getProperty("cacheSize", "1000"));
    }

    public boolean isHashed() {
        return Boolean.parseBoolean(properties.getProperty("passwordHashing.enabled", "true"));
    }

    public int getHashingIterations() {
        return Integer.parseInt(properties.getProperty("passwordHashing.iterations", DEFAULT_VALUE_HASHING_ITERATIONS));
    }

    public String getHashingAlgorithm() {
        return properties.getProperty("passwordHashing.algorithm", "SHA-512");
    }

    public String getSeparationChar() {
        return properties.getProperty("passwordHashingSalt.separationChar", "$");
    }

    public boolean isSalted() {
        return Boolean.parseBoolean(properties.getProperty("passwordHashingSalt.enabled", "true"));
    }

    public boolean isSaltFirst() {
        return Boolean.parseBoolean(properties.getProperty("passwordHashingSalt.isFirst", "true"));
    }

    public String getUser(String username) {
        return credentialsConfiguration.getUser(username);
    }

    @Override
    public String getFilename() {
        return "fileAuthConfiguration.properties";
    }


    /**
     * redundant to the getReloadIntervall() - method. Not removed due to compability-issues
     * @return the interval for the reloads of the credentials-informations in seconds
     */
    @Override
    public int getReloadIntervalinSeconds() {
        return getReloadInterval();
    }

    public void setRestartListener(final RestartListener listener) {
        this.listener = listener;
    }

    public static interface RestartListener {

        public void restart();

    }

    /**
     * @param newCallback the {@link CredentialChangeCallback} that should be performed after credential got changed
     * @return true: callback was registered successfully, otherwise false
     */
    public boolean addCallback(CredentialChangeCallback newCallback) {

        if (newCallback == null)
            throw new NullPointerException("null isnt allowed as Callback");

        if (!this.callbacks.contains(newCallback)) {
            this.callbacks.add(newCallback);
            return true;
        }
        return false;

    }

    /**
     * compares the hashCodes of the current and the previous credentialsConfiguration
     *
     * @return true: the hashCode changed, so likely the credentialInformation changed, false in case it hasn´t changed
     */
    private boolean credentialsChanged() {
        boolean changed;

        if (this.previousCredentialsHash != credentialsConfiguration.hashCode()) {
            changed = true;
        } else {
            changed = false;
        }
        previousCredentialsHash = credentialsConfiguration.hashCode();
        return changed;
    }


}
