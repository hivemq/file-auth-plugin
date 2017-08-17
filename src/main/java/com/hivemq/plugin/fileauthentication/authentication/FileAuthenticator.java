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
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.inject.Inject;
import com.hivemq.plugin.fileauthentication.callbacks.CredentialChangeCallback;
import com.hivemq.plugin.fileauthentication.configuration.Configuration;
import com.hivemq.plugin.fileauthentication.exception.PasswordFormatException;
import com.hivemq.plugin.fileauthentication.util.HashSaltUtil;
import com.hivemq.spi.callback.CallbackPriority;
import com.hivemq.spi.callback.security.OnAuthenticationCallback;
import com.hivemq.spi.security.ClientCredentialsData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * This class is a implementation of OnAuthenticationCallback.
 * It is responsible of verifying the provided username/password against the credential file.
 *
 * @author Christian Goetz
 */
public class FileAuthenticator implements OnAuthenticationCallback {

    private static final Logger log = LoggerFactory.getLogger(FileAuthenticator.class);
    private Configuration configurations;

    private boolean isHashed;
    private boolean isSalted;
    private boolean isFirst;
    private String separationChar;
    private String algorithm;
    private int iterations;
    private int cachingTimeInSeconds;
    private int cacheSize;

    private LoadingCache<ClientCredentialWrapper, Boolean> cache;
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
                changeCache();
            }
        });

        configurations.addCallback(new CredentialChangeCallback() {
            @Override
            public void onCredentialChange() {
                log.info("Credential cache is invalidated");
                cache.invalidateAll();
            }
        });


        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(cachingTimeInSeconds, TimeUnit.SECONDS)
                .maximumSize(cacheSize)
                .build(
                        new CacheLoader<ClientCredentialWrapper, Boolean>() {
                            @Override
                            public Boolean load(ClientCredentialWrapper wrap) throws Exception {
                                return checkCredentialsForCaching(wrap.getClientCredentialsData());
                            }
                        });
        log.info("Cache created with settings: cacheTime:{}, cacheSize:{}", this.cachingTimeInSeconds, this.cacheSize);
    }


    /**
     * Can be used to change the settings on the cache after the properties were changed
     * Pls note that all entries will be removed as a consequence
     */
    private void changeCache() {
        log.info("Cache was changed to new settings: cacheTime:{}, cacheSize:{}", this.cachingTimeInSeconds, this.cacheSize);
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(cachingTimeInSeconds, TimeUnit.SECONDS)
                .maximumSize(cacheSize)
                .build(
                        new CacheLoader<ClientCredentialWrapper, Boolean>() {
                            @Override
                            public Boolean load(ClientCredentialWrapper wrap) throws Exception {
                                return checkCredentialsForCaching(wrap.getClientCredentialsData());
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
        cachingTimeInSeconds = configurations.getCachingTime();
        cacheSize = configurations.getCacheSize();

        log.debug("File Authentication Configuration:");
        log.debug("hashed: {}", isHashed);
        log.debug("salted: {}", isSalted);
        log.debug("salt first: {}", isFirst);
        log.debug("iterations: {}", iterations);
        log.debug("algorithm: {}", algorithm);
        log.debug("separationChar: {}", separationChar);
        log.debug("cachingTimeInSeconds: {}", cachingTimeInSeconds);
        log.debug("cachingSize: {}", cacheSize);

    }


    /**
     * Method which checks username/password from credential file against the provided username/password using a cache
     *
     * @param clientCredentialsData holds all data about the connecting client
     * @return true, if the credentials are ok, false otherwise.
     */
    @Override
    public Boolean checkCredentials(final ClientCredentialsData clientCredentialsData) {
        try {
            return this.cache.get(new ClientCredentialWrapper(clientCredentialsData));
        } catch (ExecutionException e) {
            log.error("Unable to load from Cache", e);
            return false;
        }
    }

    /**
     * Method which checks username/password from credential file against the provided username/password, it is used by
     * the load method of the cache, if entry is absent
     *
     * @param clientCredentialsData holds all data about the connecting client
     * @return true, if the credentials are ok, false otherwise
     */
    private Boolean checkCredentialsForCaching(final ClientCredentialsData clientCredentialsData) {
        log.trace("Checking user name and password for client with IP {}, client identifier '{}' and username '{}'",
                clientCredentialsData.getInetAddress().or(InetAddress.getLoopbackAddress()).getHostAddress(),
                clientCredentialsData.getClientId(), clientCredentialsData.getUsername().or("NONE"));
        final Optional<String> usernameOptional = clientCredentialsData.getUsername();
        final Optional<String> passwordOptional = clientCredentialsData.getPassword();

        if (!usernameOptional.isPresent()) {
            log.debug("No username is present for client with IP {} and client identifier '{}'. Denying access.",
                    clientCredentialsData.getInetAddress().or(InetAddress.getLoopbackAddress()).getHostAddress(),
                    clientCredentialsData.getClientId());

            return false;
        }

        if (!passwordOptional.isPresent()) {
            log.debug("No password is present for client with IP {}, client identifier '{}' and username '{}'. Denying access.",
                    clientCredentialsData.getInetAddress().or(InetAddress.getLoopbackAddress()).getHostAddress(),
                    clientCredentialsData.getClientId(), clientCredentialsData.getUsername().or("NONE"));

            return false;
        }

        if (usernameOptional.isPresent() && passwordOptional.isPresent()) {

            final String username = usernameOptional.get();
            final String password = passwordOptional.get();

            final Optional<String> hashedPasswordOptional = Optional.fromNullable(configurations.getUser(username));

            if (!hashedPasswordOptional.isPresent()) {
                log.debug("No password is present for username '{}' in the config file. Denying access.", username);
                return false;
            }

            final String hashedPassword = hashedPasswordOptional.get();

            if (!isHashed) {
                final boolean granted = passwordComparator.validatePlaintextPassword(hashedPassword, password);
                log.debug("Plaintext password validation for client with IP {}, client identifier '{}' and username '{}' was {}.",
                        clientCredentialsData.getInetAddress().or(InetAddress.getLoopbackAddress()).getHostAddress(),
                        clientCredentialsData.getClientId(), username, granted ? "successful" : "not successful");
                return granted;
            }

            if (!isSalted) {
                final boolean granted = passwordComparator.validateHashedPassword(algorithm, password, hashedPassword, iterations);
                log.debug("Hashed password validation (without salt) for client with IP {}, client identifier '{}' and username '{}' was {}.",
                        clientCredentialsData.getInetAddress().or(InetAddress.getLoopbackAddress()).getHostAddress(),
                        clientCredentialsData.getClientId(), username, granted ? "successful" : "not successful");
                return granted;
            }

            final HashedSaltedPassword hashedSaltedPassword;
            try {
                hashedSaltedPassword = getHashAndSalt(hashedPassword);
            } catch (PasswordFormatException e) {
                return false;
            }

            final boolean granted = passwordComparator.validateHashedAndSaltedPassword(
                    algorithm,
                    password,
                    hashedSaltedPassword.getHash(),
                    iterations,
                    hashedSaltedPassword.getSalt());

            log.debug("Hashed password validation (with salt) for client with IP {}, client identifier '{}' and username '{}' was {}.",
                    clientCredentialsData.getInetAddress().or(InetAddress.getLoopbackAddress()).getHostAddress(),
                    clientCredentialsData.getClientId(), username, granted ? "successful" : "not successful");
            return granted;
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
    HashedSaltedPassword getHashAndSalt(final String hashedPassword) throws PasswordFormatException {
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


    /**
     * this is a wrapper-class for the ClientCredential
     * it is essentiell because the guave Cache used or caching needs a correct implemented version of equals and hasCode to work
     */
    private final static class ClientCredentialWrapper {

        private final ClientCredentialsData clientCredentialsData;


        private ClientCredentialWrapper(ClientCredentialsData clientCredentialsData) {
            this.clientCredentialsData = clientCredentialsData;
        }

        ClientCredentialsData getClientCredentialsData() {
            return clientCredentialsData;
        }


        /**
         * BEWARE equality is only based on Username and Password!
         *
         * @param o the object to be compared with
         * @return true if username and password are equal AND both not null
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ClientCredentialWrapper that = (ClientCredentialWrapper) o;

            if (!this.clientCredentialsData.getUsername().isPresent()) return false;
            if (!that.clientCredentialsData.getUsername().isPresent()) return false;
            if (!this.clientCredentialsData.getPassword().isPresent()) return false;
            if (!that.clientCredentialsData.getPassword().isPresent()) return false;

            if (!this.clientCredentialsData.getUsername().get().equals(that.clientCredentialsData.getUsername().get()))
                return false;
            if (!this.clientCredentialsData.getPassword().get().equals(that.clientCredentialsData.getPassword().get()))
                return false;

            return true;
        }

    }


}
