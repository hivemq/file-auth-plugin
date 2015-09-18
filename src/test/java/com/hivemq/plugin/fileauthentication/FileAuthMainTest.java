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
import com.hivemq.spi.callback.registry.CallbackRegistry;
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
