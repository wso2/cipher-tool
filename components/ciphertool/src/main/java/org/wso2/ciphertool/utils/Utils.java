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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.wso2.ciphertool.exception.CipherToolException;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.*;
import java.util.Properties;

public class Utils {

    /**
     * Retrieve value from command-line
     */
    public static String getValueFromConsole(String msg, boolean isPassword) {
        Console console = System.console();
        if (console!= null) {
            if (isPassword) {
                char[] password;
                if ((password = console.readPassword("[%s]", msg)) != null) {
                    return String.valueOf(password);
                }
            } else {
                String value;
                if ((value = console.readLine("[%s]", msg)) != null) {
                    return value;
                }
            }
        }
        throw new CipherToolException("String cannot be null");
    }

    /**
     * read values from property file
     *
     * @param filePath file path
     * @return Properties
     */
    public static Properties loadProperties(String filePath) {
        Properties properties = new Properties();
        File file = new File(filePath);
        if (!file.exists()) {
            return properties;
        }

        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file);
            properties.load(inputStream);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at :" + filePath;
            throw new CipherToolException(msg + " Error : " + e.getMessage());
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
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

        String homeFolder = System.getProperty(Constants.HOME_FOLDER);
        String filePath = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                          File.separator + fileName;
        File configFile = new File(filePath);
        if (!configFile.exists()) {
            filePath = homeFolder + File.separator  + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.SECURITY_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.AXIS2_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.TOMCAT_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.ETC_DIR + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                       File.separator + Constants.DATA_SOURCE_DIRECTORY + File.separator + fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            filePath =
                    homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.DEPLOYMENT_DIR +
                    File.separator + Constants.SERVER_DIR + File.separator + Constants.USERSTORE_DIR + File.separator +
                    fileName;
            configFile = new File(filePath);
        }

        if (!configFile.exists()) {
            throw new CipherToolException("Cannot find file : " + fileName);
        }

        return configFile;
    }

    /**
     * writees the properties into a file
     * @param properties
     * @param filePath
     */
    public static void writeToPropertyFile(Properties properties, String filePath) {
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(filePath);
            properties.store(fileOutputStream, null);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at : " + filePath;
            throw new CipherToolException(msg + " Error : " + e.getMessage());
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

    /**
     * retrieve the value for the given xpath from the file
     * @param element
     * @param xPath
     * @return
     */
    public static String getValueFromXPath(Element element, String xPath) {
        String nodeValue = null;
        try {
            XPathFactory xpf = XPathFactory.newInstance();
            XPath xp = xpf.newXPath();
            XPathExpression xPathExpression = xp.compile(xPath);
            Node text = (Node) xPathExpression.evaluate(element, XPathConstants.NODE);
            if (text != null) {
                nodeValue = text.getTextContent();
            }
        } catch (XPathExpressionException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        }
        return nodeValue;
    }

    /**
     * Write to the Secret-conf.properties
     */
    public static void writeToSecureConfPropertyFile() {
        Properties properties = new Properties();

        String keyStoreFile = System.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY);
        String keyType = System.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY);
        String aliasName = System.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY);

        properties
                .setProperty(Constants.SecureVault.CARBON_SECRET_PROVIDER, Constants.SecureVault.SECRET_PROVIDER_CLASS);
        properties.setProperty(Constants.SecureVault.SECRET_REPOSITORIES, "file");
        properties.setProperty(Constants.SecureVault.SECRET_FILE_PROVIDER,
                               Constants.SecureVault.SECRET_FILE_BASE_PROVIDER_CLASS);
        properties.setProperty(Constants.SecureVault.SECRET_FILE_LOCATION, System.getProperty(
                Constants.SecureVault.SECRET_FILE_LOCATION));

        properties.setProperty(Constants.SecureVault.KEYSTORE_LOCATION, keyStoreFile);
        properties.setProperty(Constants.SecureVault.KEYSTORE_TYPE, keyType);
        properties.setProperty(Constants.SecureVault.KEYSTORE_ALIAS, aliasName);
        properties.setProperty(Constants.SecureVault.KEYSTORE_STORE_PASSWORD,
                               Constants.SecureVault.IDENTITY_STORE_PASSWORD);
        properties.setProperty(Constants.SecureVault.KEYSTORE_STORE_SECRET_PROVIDER,
                               Constants.SecureVault.CARBON_DEFAULT_SECRET_PROVIDER);
        properties
                .setProperty(Constants.SecureVault.KEYSTORE_KEY_PASSWORD, Constants.SecureVault.IDENTITY_KEY_PASSWORD);
        properties.setProperty(Constants.SecureVault.KEYSTORE_KEY_SECRET_PROVIDER,
                               Constants.SecureVault.CARBON_DEFAULT_SECRET_PROVIDER);

        writeToPropertyFile(properties, System.getProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY));

        System.out.println("\nSecret Configurations are written to the property file successfully\n");
    }

    /**
     * Set the system properties
     */
    public static void setSystemProperties() {

        String osName = System.getProperty(Constants.OS_NAME);
        File file;
        if (!osName.toLowerCase().contains("win")) {
            file = new File("." + File.separator + ".." + File.separator);
        } else {
            file = new File("." + File.separator);
        }

        String homeFolder;
        try {
            homeFolder = file.getCanonicalFile().toString();
        } catch (IOException e) {
            throw new CipherToolException("Error while calculating HOME_FOLDER directory location ", e);
        }

        String keyStoreFile, keyType, keyAlias, secretConfPropFile, secretConfFile, cipherTextPropFile,
                cipherToolPropFile;

        //Verify if this is WSO2 envirnoment
        String carbonConfigFile = homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator
                                  + Constants.CONF_DIR + File.separator + Constants.CARBON_CONFIG_FILE;
        File carbonXML = new File(carbonConfigFile);
        if (carbonXML.exists()) {
            //WSO2 Envirnoment
            try {
                DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                Document document = docBuilder.parse(carbonConfigFile);

                keyStoreFile = Utils.getValueFromXPath(document.getDocumentElement(),
                                                       Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_XPATH);
                keyStoreFile = homeFolder + keyStoreFile.substring((keyStoreFile.indexOf('}')) + 1);
                System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY, keyStoreFile);
                keyType = Utils.getValueFromXPath(document.getDocumentElement(),
                                                  Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_XPATH);
                keyAlias = Utils.getValueFromXPath(document.getDocumentElement(),
                                                   Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_XPATH);

                secretConfFile = homeFolder + File.separator + Constants.REPOSITORY_DIR +
                                 File.separator + Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR +
                                 File.separator + Constants.SECRET_PROPERTY_FILE;
                cipherTextPropFile = Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR + File.separator +
                                     Constants.SECURITY_DIR + File.separator + Constants.CIPHER_TEXT_PROPERTY_FILE;
                cipherToolPropFile =
                        homeFolder + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                        File.separator + Constants.SECURITY_DIR + File.separator + Constants.CIPHER_TOOL_PROPERTY_FILE;

            } catch (ParserConfigurationException e) {
                throw new CipherToolException(
                        "Error reading primary key Store details from " + Constants.CARBON_CONFIG_FILE + " file ", e);
            } catch (SAXException e) {
                throw new CipherToolException(
                        "Error reading primary key Store details from " + Constants.CARBON_CONFIG_FILE + " file ", e);
            } catch (IOException e) {
                throw new CipherToolException(
                        "Error reading primary key Store details from " + Constants.CARBON_CONFIG_FILE + " file ", e);
            }
        } else {
            file = new File("." + File.separator);
            try {
                homeFolder = file.getCanonicalFile().toString();
            } catch (IOException e) {
                throw new CipherToolException("Error while calculating HOME_FOLDER directory location ", e);
            }

            String nonCarbonConfigFile =
                    homeFolder + System.getProperty("config.properties.dir", File.separator + Constants.CONF_DIR) +
                    File.separator + Constants.CIPHER_TOOL_CONFIG_PROPERTY_FILE;

            Properties nonCarbonConfigProp = Utils.loadProperties(nonCarbonConfigFile);
            if (nonCarbonConfigProp.size() <= 0) {
                throw new CipherToolException("Cipher-tool-config.properties cannot be empty");
            }

            keyStoreFile = nonCarbonConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY);
            keyType = nonCarbonConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY);
            keyAlias = nonCarbonConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY);
            secretConfPropFile = nonCarbonConfigProp.getProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY);
            secretConfFile = homeFolder + File.separator + secretConfPropFile;
            cipherTextPropFile = nonCarbonConfigProp.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY);
            cipherToolPropFile = nonCarbonConfigProp.getProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY);
        }

        if (keyStoreFile.trim().isEmpty()) {
            throw new CipherToolException("KeyStore file path cannot be empty");
        }
        if (keyAlias == null || keyAlias.trim().isEmpty()) {
            throw new CipherToolException("Key alias cannot be empty");
        }

        System.setProperty(Constants.HOME_FOLDER, homeFolder);
        System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY, keyStoreFile);
        System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY, keyType);
        System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY, keyAlias);
        System.setProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY, secretConfFile);
        System.setProperty(Constants.SecureVault.SECRET_FILE_LOCATION, cipherTextPropFile);
        System.setProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY,
                           homeFolder + File.separator + cipherTextPropFile);
        System.setProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY, cipherToolPropFile);
    }
}
