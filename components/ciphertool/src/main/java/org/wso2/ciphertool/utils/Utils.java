/**
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class Utils {

    /**
     * Retrieve value from command-line
     */
    public static String getValueFromConsole(String msg, boolean isPassword) {
        Console console = System.console();
        if (console != null) {
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
     * @return Properties properties
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
     * @return File file
     */
    public static String getConfigFilePath(String fileName) {

        String homeFolder = System.getProperty(Constants.HOME_FOLDER);
        Path filePath = Paths.get(homeFolder, fileName);
        if (!Files.exists(filePath)) {
            filePath = Paths.get(fileName);
            if (!Files.exists(filePath)) {
                throw new CipherToolException("Cannot find file : " + fileName);
            }
        }


        return filePath.toAbsolutePath().toString();
    }

    /**
     * writees the properties into a file
     *
     * @param properties properties
     * @param filePath   filepath
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
     *
     * @param element element
     * @param xPath   xpath
     * @return value from xpath
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
        String keyStoreFile, keyType, keyAlias, secretConfPropFile, secretConfFile, cipherTextPropFile,
                cipherToolPropFile;

        String homeFolder = System.getProperty(Constants.CARBON_HOME);

        //Verify if this is WSO2 environment
        Path path = Paths.get(homeFolder, Constants.REPOSITORY_DIR, Constants.CONF_DIR, Constants.CARBON_CONFIG_FILE);

        if (Files.exists(path)) {
            //WSO2 Environment
            try {
                DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                Document document = docBuilder.parse(path.toAbsolutePath().toString());

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

            Path standaloneConfigPath =
                    Paths.get(homeFolder, Constants.CONF_DIR, Constants.CIPHER_STANDALONE_CONFIG_PROPERTY_FILE);
            if (!Files.exists(standaloneConfigPath)) {
                throw new CipherToolException(
                        "File, " + standaloneConfigPath + " does not exist.");
            }
            Properties standaloneConfigProp = Utils.loadProperties(standaloneConfigPath.toAbsolutePath().toString());
            if (standaloneConfigProp.size() <= 0) {
                throw new CipherToolException(
                        "File, " + Constants.CIPHER_STANDALONE_CONFIG_PROPERTY_FILE + " cannot be empty");
            }

            keyStoreFile = standaloneConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY);
            keyType = standaloneConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY);
            keyAlias = standaloneConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY);
            secretConfPropFile = standaloneConfigProp.getProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY);
            secretConfFile = homeFolder + File.separator + secretConfPropFile;
            cipherTextPropFile = standaloneConfigProp.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY);
            cipherToolPropFile = standaloneConfigProp.getProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY);
        }

        if (keyStoreFile.trim().isEmpty()) {
            throw new CipherToolException("KeyStore file path cannot be empty");
        }
        if (keyAlias == null || keyAlias.trim().isEmpty()) {
            throw new CipherToolException("Key alias cannot be empty");
        }

        System.setProperty(Constants.HOME_FOLDER, homeFolder);
        System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY, getConfigFilePath(keyStoreFile));
        System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY, keyType);
        System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY, keyAlias);
        System.setProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY, secretConfFile);
        System.setProperty(Constants.SecureVault.SECRET_FILE_LOCATION, cipherTextPropFile);
        System.setProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY, getConfigFilePath(cipherTextPropFile));
        System.setProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY, getConfigFilePath(cipherToolPropFile));
    }
}
