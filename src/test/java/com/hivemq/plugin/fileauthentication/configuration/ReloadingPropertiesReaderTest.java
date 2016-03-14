package com.hivemq.plugin.fileauthentication.configuration;

import junit.framework.TestCase;

import java.io.FileReader;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Lukas Brandl
 */
public class ReloadingPropertiesReaderTest extends TestCase {

    public void test_file_reader_closed() throws Exception {
        final TestReloadingPropertiesReader reader = new TestReloadingPropertiesReader();
        final FileReader fileReader = mock(FileReader.class);
        reader.replaceProperties(fileReader);
        verify(fileReader).close();
    }

    private static class TestReloadingPropertiesReader extends ReloadingPropertiesReader {

        public TestReloadingPropertiesReader() {
            super(null);
        }

        @Override
        public String getFilename() {
            return "Test";
        }

        @Override
        public int getReloadIntervalinSeconds() {
            return 0;
        }
    }
}