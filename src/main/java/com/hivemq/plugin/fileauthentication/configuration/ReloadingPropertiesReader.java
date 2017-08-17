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

import com.google.common.collect.Lists;
import com.google.common.collect.MapDifference;
import com.google.common.collect.Maps;
import com.hivemq.spi.annotations.NotNull;
import com.hivemq.spi.config.SystemInformation;
import com.hivemq.spi.services.PluginExecutorService;
import com.hivemq.spi.services.configuration.ValueChangedCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * @author Christoph Schäbel
 */
public abstract class ReloadingPropertiesReader {

    private static final Logger log = LoggerFactory.getLogger(Configuration.class);

    private final PluginExecutorService pluginExecutorService;
    private final SystemInformation systemInformation;
    protected Properties properties;
    protected Map<String, List<ValueChangedCallback<String>>> callbacks = Maps.newHashMap();
    private File file;

    public ReloadingPropertiesReader(final PluginExecutorService pluginExecutorService, final SystemInformation systemInformation) {
        this.pluginExecutorService = pluginExecutorService;
        this.systemInformation = systemInformation;
    }

    public void init() {

        this.file = new File(systemInformation.getConfigFolder(), getFilename());

        try {
            properties = new Properties();
            properties.load(new FileReader(file));
        } catch (IOException e) {
            log.error("Not able to load configuration file {}", file.getAbsolutePath());
        }

        pluginExecutorService.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                reload();
            }
        }, 10, getReloadIntervalinSeconds(), TimeUnit.SECONDS);
    }

    @NotNull
    public abstract String getFilename();

    @NotNull
    public abstract int getReloadIntervalinSeconds();

    /**
     * Reloads the specified .properties file
     */
    public void reload() {

        Map<String, String> oldValues = getCurrentValues();
        try {
            final FileReader fileReader = new FileReader(file);
            replaceProperties(fileReader);

            Map<String, String> newValues = getCurrentValues();
            logChanges(oldValues, newValues);

        } catch (IOException e) {
            log.debug("Not able to reload configuration file {}", this.file.getAbsolutePath());
        }
    }

    public void replaceProperties(final FileReader fileReader) throws IOException {
        try {
            final Properties props = new Properties();
            props.load(fileReader);
            properties = props;
        } finally {
            fileReader.close();
        }
    }

    public void addCallback(final String propertyName, final ValueChangedCallback<String> changedCallback) {

        if (!callbacks.containsKey(propertyName)) {
            callbacks.put(propertyName, Lists.<ValueChangedCallback<String>>newArrayList());
        }

        callbacks.get(propertyName).add(changedCallback);
    }

    private Map<String, String> getCurrentValues() {
        Map<String, String> values = Maps.newHashMap();
        for (String key : properties.stringPropertyNames()) {
            values.put(key, properties.getProperty(key));
        }
        return values;
    }

    private void logChanges(final Map<String, String> oldValues, final Map<String, String> newValues) {
        final MapDifference<String, String> difference = Maps.difference(oldValues, newValues);

        for (Map.Entry<String, MapDifference.ValueDifference<String>> stringValueDifferenceEntry : difference.entriesDiffering().entrySet()) {
            log.debug("Plugin configuration {} changed from {} to {}",
                    stringValueDifferenceEntry.getKey(), stringValueDifferenceEntry.getValue().leftValue(),
                    stringValueDifferenceEntry.getValue().rightValue());

            if (callbacks.containsKey(stringValueDifferenceEntry.getKey())) {
                for (ValueChangedCallback<String> callback : callbacks.get(stringValueDifferenceEntry.getKey())) {
                    callback.valueChanged(stringValueDifferenceEntry.getValue().rightValue());
                }
            }
        }

        for (Map.Entry<String, String> stringStringEntry : difference.entriesOnlyOnLeft().entrySet()) {
            log.debug("Plugin configuration {} removed", stringStringEntry.getKey(), stringStringEntry.getValue());
        }

        for (Map.Entry<String, String> stringStringEntry : difference.entriesOnlyOnRight().entrySet()) {
            log.debug("Plugin configuration {} added: {}", stringStringEntry.getValue(), stringStringEntry.getValue());
        }
    }

    @NotNull
    public Properties getProperties() {
        return properties;
    }


}
