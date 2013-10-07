package com.dcsquare.hivemq.plugin.fileauthentication.exception;

/**
 * This exception is thrown if something did go wrong during the initialization of the configurations.
 *
 * @author Christian Goetz
 */
public class ConfigurationInitializationException extends RuntimeException {
    public ConfigurationInitializationException(String message) {
        super(message);
    }
}
