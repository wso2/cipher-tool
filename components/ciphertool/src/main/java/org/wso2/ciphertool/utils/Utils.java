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
     * @param filePath file path
     * @return Properties
     */
    public static Properties loadProperties(String filePath) {
        Properties properties = new Properties();
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
            throw new CipherToolException(msg + " Error : " + e.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                    throw new CipherToolException("Error while closing input stream");
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
                throw new CipherToolException("Error while closing output stream");
            }
        }
    }

    public static String getPrimaryKeyInfo(Element element, String xPath) {
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

    public static void setSystemProperties(String carbonHome) {
        System.setProperty(Constants.CARBON_HOME, carbonHome);
        String nonCarbonConfigFile = carbonHome + System.getProperty("config.properties.dir",
                                                                     Constants.REPOSITORY_DIR + File.separator +
                                                                     Constants.CONF_DIR + File.separator +
                                                                     Constants.SECURITY_DIR) + File.separator +
                                     Constants.CIPHER_TOOL_CONFIG_PROPERTY_FILE;
        Properties nonCarbonConfigProp = Utils.loadProperties(nonCarbonConfigFile);
        String carbonConfigFile = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator
                                  + Constants.CONF_DIR + File.separator + Constants.CARBON_CONFIG_FILE;
        String keyStoreFile, keyType, keyAlias;
        try {
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document document = docBuilder.parse(carbonConfigFile);

            keyStoreFile = nonCarbonConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY);
            if (keyStoreFile == null) {
                keyStoreFile = Utils.getPrimaryKeyInfo(document.getDocumentElement(),
                                                       Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_XPATH);
                keyStoreFile = carbonHome + keyStoreFile.substring((keyStoreFile.indexOf('}')) + 1);
                System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY, keyStoreFile);
            }
            System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_PROPERTY, keyStoreFile);

            keyType = nonCarbonConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY);
            if (keyType == null) {
                keyType = Utils.getPrimaryKeyInfo(document.getDocumentElement(),
                                                  Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_XPATH);
                if (keyType == null) {
                    throw new CipherToolException("KeyStore Type can not be null");
                }
            }
            System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_PROPERTY, keyType);

            keyAlias = nonCarbonConfigProp.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY);
            if (keyAlias == null) {
                keyAlias = Utils.getPrimaryKeyInfo(document.getDocumentElement(),
                                                   Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_XPATH);
            }
            System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_PROPERTY, keyAlias);

        } catch (ParserConfigurationException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (SAXException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (IOException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        }

        String secretConfPropFile = nonCarbonConfigProp.getProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY);
        String secretConfFile, cipherTextPropFile, cipherToolPropFile;
        if (secretConfPropFile == null) {
            secretConfFile = System.getProperty(Constants.CARBON_HOME) + File.separator + Constants.REPOSITORY_DIR +
                             File.separator + Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR +
                             File.separator + Constants.SECRET_PROPERTY_FILE;
            cipherTextPropFile = Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR + File.separator +
                                 Constants.SECURITY_DIR + File.separator + Constants.CIPHER_TEXT_PROPERTY_FILE;
            cipherToolPropFile =
                    carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR +
                    File.separator + Constants.SECURITY_DIR + File.separator + Constants.CIPHER_TOOL_PROPERTY_FILE;
        } else {
            secretConfFile = System.getProperty(Constants.CARBON_HOME) + File.separator + secretConfPropFile;
            cipherTextPropFile = nonCarbonConfigProp.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY);
            cipherToolPropFile = nonCarbonConfigProp.getProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY);
        }
        System.setProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY, secretConfFile);
        System.setProperty(Constants.SecureVault.SECRET_FILE_LOCATION, cipherTextPropFile);
        System.setProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY,
                           carbonHome + File.separator + cipherTextPropFile);
        System.setProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY, cipherToolPropFile);
    }
}
