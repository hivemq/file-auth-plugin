package com.dcsquare.hivemq.plugin.fileauthentication;

import com.dcsquare.hivemq.plugin.fileauthentication.authentication.FileAuthenticator;
import com.dcsquare.hivemq.spi.callback.registry.CallbackRegistry;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author Christian Goetz
 */
public class FileAuthMainTest {

    @Mock
    CallbackRegistry callbackRegistry;

    @Mock
    FileAuthenticator fileAuthenticator;

    @Before
    public void setUp() throws Exception {
        initMocks(this);
    }

    @Test
    public void test_callback_is_added() throws Exception {

        FileAuthMain fileAuthMain = new FileAuthMain(fileAuthenticator, callbackRegistry);
        fileAuthMain.postConstruct();

        verify(callbackRegistry).addCallback(fileAuthenticator);
    }
}
