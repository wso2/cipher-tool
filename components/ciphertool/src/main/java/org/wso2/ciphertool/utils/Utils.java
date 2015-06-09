/**
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.ciphertool.utils;

import java.io.*;
import java.util.Properties;

public class Utils {

    /**
     * Retrieve value from command-line
     */
    public static String getValueFromConsole(String msg) {
        Console console;
        char[] value;
        if ((console = System.console()) != null && (value = console.readPassword("[%s]", msg)) != null) {
            return String.valueOf(value);
        }
        return "";
    }

    /**
     * read values from property file
     *
     * @param fileName file name
     * @return Properties
     */
    public static Properties loadProperties(String fileName) {
        Properties properties = new Properties();
        String carbonHome = System.getProperty(Constants.CARBON_HOME);
        String filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator +
                          Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR +
                          File.separator + fileName;

        File file = new File(filePath);
        if (!file.exists()) {
            //ToDO : Check if we need to print an error and exit if file doesnot exist
            return properties;
        }

        InputStream in = null;
        try {
            in = new FileInputStream(file);
            properties.load(in);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at :" + filePath;
            System.err.println(msg + " Error : " + e.getMessage());
            return properties;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                    System.err.println("Error while closing input stream");
                }
            }
        }
        return properties;
    }

    /**
     * returns the configuration file
     *
     * @param fileName file name
     * @return File
     */
    public static File getConfigFile(String fileName) {

        String carbonHome = System.getProperty(Constants.CARBON_HOME);
        String filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                          File.separator + fileName;
        File configFile = new File(filePath);
        if (!configFile.exists()) {
            filePath = carbonHome + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.SECURITY_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.AXIS2_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.TOMCAT_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.ETC_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.DATA_SOURCE_DIRECTORY + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath =
                    carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.DEPLOYMENT_DIR +
                    File.separator + Constants.SERVER_DIR + File.separator + Constants.USERSTORE_DIR + File.separator +
                    fileName;
            configFile = new File(filePath);
        }

        return configFile;
    }

    public static void writeToPropertyFile(Properties properties, String fileName) {
        String filePath = System.getProperty(Constants.CARBON_HOME) + File.separator + Constants.REPOSITORY_DIR +
                          File.separator + Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR +
                          File.separator + fileName;
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(filePath);
            properties.store(fileOutputStream, null);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at : " + filePath;
            System.err.println(msg + " Error : " + e.getMessage());
        } finally {
            try {
                if (fileOutputStream != null) {
                    fileOutputStream.close();
                }
            } catch (IOException e) {
                System.err.println("Error while closing output stream");
            }
        }
    }
}
