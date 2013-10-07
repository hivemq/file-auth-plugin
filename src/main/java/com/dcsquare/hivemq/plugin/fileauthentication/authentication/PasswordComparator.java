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

package com.dcsquare.hivemq.plugin.fileauthentication.authentication;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.digest.config.SimpleDigesterConfig;
import org.jasypt.salt.FixedStringSaltGenerator;
import org.jasypt.util.password.ConfigurablePasswordEncryptor;

/**
 * In this class the provided password is validated against the password in the file
 *
 * @author Dominik Obermaier
 * @author Christian Goetz
 */
public class PasswordComparator {

    /**
     * Using BouncyCastle as security provider
     */
    private final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    /**
     * Validates a salted and hashed password
     *
     * @param algorithm     used hash algorithm
     * @param plainPassword plaintext password provided from the client
     * @param passwordHash  hash read from the credential file
     * @param iterations    iterations used during the hashing
     * @param salt          salt read from the credential file
     * @return true if the hashes match, otherwise false
     */
    public boolean validateHashedAndSaltedPassword(final String algorithm,
                                                   final String plainPassword,
                                                   final String passwordHash,
                                                   final int iterations,
                                                   final String salt) {

        final ConfigurablePasswordEncryptor configurablePasswordEncryptor = getEncryptor(algorithm, iterations, salt);

        return configurablePasswordEncryptor.checkPassword(plainPassword, passwordHash);
    }

    /**
     * Validates a hashed password
     *
     * @param algorithm     used hash algorithm
     * @param plainPassword plaintext password provided from the client
     * @param passwordHash  hash read from the credential file
     * @param iterations    iterations used during the hashing
     * @return true if the hashes match, otherwise false
     */
    public boolean validateHashedPassword(final String algorithm,
                                          final String plainPassword,
                                          final String passwordHash,
                                          final int iterations) {
        return validateHashedAndSaltedPassword(algorithm, plainPassword, passwordHash, iterations, null);

    }

    /**
     * Validates a plaintext password
     *
     * @param filePassword   plaintext password in the file
     * @param clientPassword plaintext password provided by the client
     * @return true if the hashes match, otherwise false
     */
    public boolean validatePlaintextPassword(final String filePassword,
                                             final String clientPassword) {
        return filePassword.equals(clientPassword);
    }

    /**
     * This initializes the jasypt password encryptor with the correct parameters
     *
     * @param algorithm  used hash algorithm
     * @param iterations iterations which should be used
     * @param salt       salt which should be used
     * @return jasypt password encrypter
     */
    private ConfigurablePasswordEncryptor getEncryptor(final String algorithm, final int iterations, final String salt) {
        final ConfigurablePasswordEncryptor encryptor = new ConfigurablePasswordEncryptor();

        final SimpleDigesterConfig config = new SimpleDigesterConfig();
        config.setProvider(PROVIDER);
        config.setAlgorithm(algorithm);
        config.setIterations(iterations);

        if (salt != null) {
            final FixedStringSaltGenerator saltGenerator = new FixedStringSaltGenerator();
            saltGenerator.setSalt(salt);
            config.setSaltGenerator(saltGenerator);
            config.setSaltSizeBytes(salt.length());
        }

        encryptor.setConfig(config);
        return encryptor;
    }

}
