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

package com.hivemq.plugin.fileauthentication.authentication;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.inject.Inject;
import com.hivemq.plugin.fileauthentication.configuration.Configuration;
import com.hivemq.plugin.fileauthentication.exception.PasswordFormatException;
import com.hivemq.plugin.fileauthentication.util.HashSaltUtil;
import com.hivemq.spi.aop.cache.Cached;
import com.hivemq.spi.callback.CallbackPriority;
import com.hivemq.spi.callback.exception.AuthenticationException;
import com.hivemq.spi.callback.security.OnAuthenticationCallback;
import com.hivemq.spi.security.ClientCredentialsData;

import java.util.concurrent.TimeUnit;

/**
 * This class is a implementation of OnAuthenticationCallback.
 * It is responsible of verifying the provided username/password against the credential file.
 *
 * @author Christian Goetz
 */
public class FileAuthenticator implements OnAuthenticationCallback {

    private Configuration configurations;

    private boolean isHashed;
    private boolean isSalted;
    private boolean isFirst;
    private String separationChar;
    private String algorithm;
    private int iterations;

    private PasswordComparator passwordComparator;


    /**
     * The configuration and {@link PasswordComparator} is injected, using Guice.
     *
     * @param configurations     object, which holds all properties read from the specified configuration files in {@link com.hivemq.plugin.fileauthentication.FileAuthenticationModule}
     * @param passwordComparator instance of the class {@link PasswordComparator}
     */
    @Inject
    public FileAuthenticator(final Configuration configurations, PasswordComparator passwordComparator) {

        this.configurations = configurations;
        this.passwordComparator = passwordComparator;

        loadConfig();

        configurations.setRestartListener(new Configuration.RestartListener() {
            @Override
            public void restart() {
                loadConfig();
            }
        });

    }

    private void loadConfig() {
        isHashed = configurations.isHashed();
        iterations = configurations.getHashingIterations();
        algorithm = configurations.getHashingAlgorithm();
        separationChar = configurations.getSeparationChar();
        isSalted = configurations.isSalted();
        isFirst = configurations.isSaltFirst();
    }


    /**
     * Method which checks username/password from credential file against the provided username/password
     *
     * @param clientCredentialsData holds all data about the connecting client
     * @return true, if the credentials are ok, false otherwise.
     * @throws AuthenticationException
     */
    @Override
    @Cached(timeToLive = 5, timeUnit = TimeUnit.MINUTES)
    public Boolean checkCredentials(ClientCredentialsData clientCredentialsData) throws AuthenticationException {

        final Optional<String> usernameOptional = clientCredentialsData.getUsername();
        final Optional<String> passwordOptional = clientCredentialsData.getPassword();

        if (usernameOptional.isPresent() && passwordOptional.isPresent()) {

            final String username = usernameOptional.get();
            final String password = passwordOptional.get();

            final Optional<String> hashedPasswordOptional = Optional.fromNullable(configurations.getUser(username));

            if (!hashedPasswordOptional.isPresent()) {
                return false;
            }

            final String hashedPassword = hashedPasswordOptional.get();

            if (!isHashed) {
                return passwordComparator.validatePlaintextPassword(hashedPassword, password);
            }

            if (!isSalted) {
                return passwordComparator.validateHashedPassword(algorithm, password, hashedPassword, iterations);
            }

            final HashedSaltedPassword hashedSaltedPassword;
            try {
                hashedSaltedPassword = getHashAndSalt(hashedPassword);
            } catch (PasswordFormatException e) {
                return false;
            }

            return passwordComparator.validateHashedAndSaltedPassword(
                    algorithm,
                    password,
                    hashedSaltedPassword.getHash(),
                    iterations,
                    hashedSaltedPassword.getSalt());
        } else {
            return false;
        }

    }

    /**
     * Calls the {@link HashSaltUtil} to retrieve salt and hash from the property string
     * <p/>
     * It was extracted for being able to override it in the test cases.
     *
     * @param hashedPassword string containing hash, salt and separator
     * @return {@link HashedSaltedPassword} with hash and salt
     * @throws PasswordFormatException thrown when the string is in an unsupported format
     */
    @VisibleForTesting
    HashedSaltedPassword getHashAndSalt(String hashedPassword) throws PasswordFormatException {
        return HashSaltUtil.retrieve(isFirst, separationChar, hashedPassword);
    }

    /**
     * Priority of the callback implementation.
     * This is important if more than one {@link OnAuthenticationCallback} implementations is available.
     *
     * @return priority.
     */
    @Override
    public int priority() {
        return CallbackPriority.HIGH;
    }
}
