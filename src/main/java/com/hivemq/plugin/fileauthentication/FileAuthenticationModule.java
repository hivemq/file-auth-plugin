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

import com.hivemq.spi.HiveMQPluginModule;
import com.hivemq.spi.PluginEntryPoint;
import com.hivemq.spi.plugin.meta.Information;

/**
 * Plugin Configuration Class
 *
 * @author Christian Goetz
 */
@Information(name = "File Authentication Plugin", version = "3.1.1", author = "dc-square GmbH")
public class FileAuthenticationModule extends HiveMQPluginModule {


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
