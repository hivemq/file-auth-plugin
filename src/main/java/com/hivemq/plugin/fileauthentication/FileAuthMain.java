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

package com.hivemq.plugin.fileauthentication;

import com.hivemq.plugin.fileauthentication.authentication.FileAuthenticator;
import com.hivemq.spi.PluginEntryPoint;
import com.hivemq.spi.callback.registry.CallbackRegistry;
import com.google.inject.Inject;

import javax.annotation.PostConstruct;

/**
 * Plugin Entry Point
 * Initializes the callback.
 *
 * @author Christian Goetz
 */
public class FileAuthMain extends PluginEntryPoint {

    FileAuthenticator fileAuthenticator;
    CallbackRegistry callbackRegistry;

    /**
     * Inject callback class and callback registry
     * <p/>
     * Injection of callback registry was favoured against {@link com.hivemq.plugin.fileauthentication.FileAuthMain#getCallbackRegistry()}
     * because then it can be replaced in testing.
     *
     * @param fileAuthenticator implementation of OnAuthenticationCallback
     * @param callbackRegistry  callback registry
     */
    @Inject
    public FileAuthMain(FileAuthenticator fileAuthenticator, CallbackRegistry callbackRegistry) {
        this.fileAuthenticator = fileAuthenticator;
        this.callbackRegistry = callbackRegistry;
    }

    /**
     * Add callback after injection took place.
     */
    @PostConstruct
    public void postConstruct() {
        callbackRegistry.addCallback(fileAuthenticator);
    }
}
