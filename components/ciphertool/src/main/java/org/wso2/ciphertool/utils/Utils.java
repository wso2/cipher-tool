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

import net.consensys.cava.toml.Toml;
import net.consensys.cava.toml.TomlParseResult;
import net.consensys.cava.toml.TomlTable;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.wso2.ciphertool.exception.CipherToolException;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.xml.XMLConstants;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

public class Utils {

    private static boolean primaryKeyStore = true;
    private static final String BACKSLASH = "\\";
    private static final String FORWARDSLASH = "/";

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
        // Normalize paths for windows.
        // This should avoid inconsistencies between paths defined with \ and / in windows OS
        homeFolder = homeFolder.replace(BACKSLASH, FORWARDSLASH);
        fileName = fileName.replace(BACKSLASH, FORWARDSLASH);
        if (fileName.startsWith(homeFolder)) {
            fileName = fileName.substring(homeFolder.length(), fileName.length());
        }
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

        String keyStoreFile = System.getProperty(Constants.KEY_LOCATION_PROPERTY);
        String keyType = System.getProperty(Constants.KEY_TYPE_PROPERTY);
        String aliasName = System.getProperty(Constants.KEY_ALIAS_PROPERTY);
        String enable = System.getProperty(Constants.SecureVault.ENABLE_SEC_VAULT, "true");

        properties.setProperty(Constants.SecureVault.ENABLE_SEC_VAULT, enable);
        properties.setProperty(Constants.SecureVault.CARBON_SECRET_PROVIDER,
                Constants.SecureVault.SECRET_PROVIDER_CLASS);
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
        // This property is referred by the FileBaseSecretRepository for decryption.
        String algorithm = System.getProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        if (algorithm != null) {
            properties.setProperty(Constants.SecureVault.SECRET_FILE_ALGORITHM, algorithm);
        }

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
        boolean hasConfigInRepository = true;
        if (!Files.exists(path)) {
        	//Try WSO2 EI alternate path
        	path = Paths.get(homeFolder, Constants.CONF_DIR, Constants.CARBON_CONFIG_FILE);
        	hasConfigInRepository = false;
        }

        if (Files.exists(path)) {
            //WSO2 Environment
            try {
                DocumentBuilder docBuilder = getSecuredDocumentBuilder(false);
                Document document = docBuilder.parse(path.toAbsolutePath().toString());

                keyStoreFile = Utils.getValueFromXPath(document.getDocumentElement(),
                            Constants.InternalKeyStore.KEY_LOCATION_XPATH);
                //Use InternalKeyStore if it exists, else use the Primary keystore
                if (keyStoreFile != null) {
                    keyType = Utils.getValueFromXPath(document.getDocumentElement(),
                            Constants.InternalKeyStore.KEY_TYPE_XPATH);
                    keyAlias = Utils.getValueFromXPath(document.getDocumentElement(),
                            Constants.InternalKeyStore.KEY_ALIAS_XPATH);
                    primaryKeyStore = false;
                } else {
                    keyStoreFile = Utils.getValueFromXPath(document.getDocumentElement(),
                            Constants.PrimaryKeyStore.KEY_LOCATION_XPATH);
                    keyType = Utils.getValueFromXPath(document.getDocumentElement(),
                            Constants.PrimaryKeyStore.KEY_TYPE_XPATH);
                    keyAlias = Utils.getValueFromXPath(document.getDocumentElement(),
                            Constants.PrimaryKeyStore.KEY_ALIAS_XPATH);
                }

                keyStoreFile = resolveKeyStorePath(keyStoreFile, homeFolder);
                System.setProperty(Constants.KEY_LOCATION_PROPERTY, keyStoreFile);
                String keyStoreName = ((Utils.isPrimaryKeyStore()) ? "Primary" : "Internal");

                System.out.println("\nEncrypting using " + keyStoreName + " KeyStore.");
                System.out.println("{type: " + keyType + ", alias: " + keyAlias + ", path: " + keyStoreFile + "}\n");

                if (hasConfigInRepository) {
	                secretConfFile = Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR + File.separator +
	                                 Constants.SECURITY_DIR + File.separator + Constants.SECRET_PROPERTY_FILE;
	                cipherTextPropFile = Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR + File.separator +
	                                     Constants.SECURITY_DIR + File.separator + Constants.CIPHER_TEXT_PROPERTY_FILE;
	                cipherToolPropFile = Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR + File.separator +
	                                     Constants.SECURITY_DIR + File.separator + Constants.CIPHER_TOOL_PROPERTY_FILE;
                } else {
	                secretConfFile = Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR + File.separator +
	                                 Constants.SECRET_PROPERTY_FILE;
		            cipherTextPropFile = Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR + File.separator +
		                                 Constants.CIPHER_TEXT_PROPERTY_FILE;
		            cipherToolPropFile = Constants.CONF_DIR + File.separator + Constants.SECURITY_DIR + File.separator +
		                                 Constants.CIPHER_TOOL_PROPERTY_FILE;
                }

                secretConfFile = Paths.get(homeFolder, secretConfFile).toString();

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

            keyStoreFile = standaloneConfigProp.getProperty(Constants.KEY_LOCATION_PROPERTY);
            keyType = standaloneConfigProp.getProperty(Constants.KEY_TYPE_PROPERTY);
            keyAlias = standaloneConfigProp.getProperty(Constants.KEY_ALIAS_PROPERTY);

            secretConfFile = standaloneConfigProp.getProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY);
            cipherTextPropFile = standaloneConfigProp.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY);
            cipherToolPropFile = standaloneConfigProp.getProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY);
            
            if (!Paths.get(secretConfFile).isAbsolute()) {
                secretConfFile = Paths.get(homeFolder, standaloneConfigProp.getProperty(Constants
                        .SECRET_PROPERTY_FILE_PROPERTY)).toString();
            }
        }

        if (keyStoreFile.trim().isEmpty()) {
            throw new CipherToolException("KeyStore file path cannot be empty");
        }
        if (keyAlias == null || keyAlias.trim().isEmpty()) {
            throw new CipherToolException("Key alias cannot be empty");
        }

        System.setProperty(Constants.HOME_FOLDER, homeFolder);
        System.setProperty(Constants.KEY_LOCATION_PROPERTY, getConfigFilePath(keyStoreFile));
        System.setProperty(Constants.KEY_TYPE_PROPERTY, keyType);
        System.setProperty(Constants.KEY_ALIAS_PROPERTY, keyAlias);
        System.setProperty(Constants.SECRET_PROPERTY_FILE_PROPERTY, secretConfFile);
        System.setProperty(Constants.SecureVault.SECRET_FILE_LOCATION, cipherTextPropFile);
        System.setProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY, getConfigFilePath(cipherTextPropFile));
        System.setProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY, getConfigFilePath(cipherToolPropFile));
    }

    /**
     * Returns whether it's a primary or an internal keystore
     */
    public static boolean isPrimaryKeyStore() {
        return primaryKeyStore;
    }

    /**
     * Resolve absolute path of the keystore
     */
    public static String resolveKeyStorePath(String keyStorePath, String homeFolder) {
        // Check whether it's a relative path and is inside {carbon.home}.
        if (keyStorePath.contains("}")) {
            keyStorePath = getAbsolutePathWithCarbonHome(keyStorePath, homeFolder);
        }
        return keyStorePath;
    }
    private static String getAbsolutePathWithCarbonHome(String keyStorePath, String homeFolder) {
        // Append carbon.home location to the relative path.
        return homeFolder + keyStorePath.substring((keyStorePath.indexOf('}')) + 1);
    }

    /**
     * Get deployment toml file path
     *
     * @return  deployment file path
     */
    public static String getDeploymentFilePath() {
        String configFilePath = System.getProperty(Constants.DEPLOYMENT_CONFIG_FILE_PATH);
        if (StringUtils.isEmpty(configFilePath)) {
            configFilePath = Paths.get(System.getProperty(Constants.CARBON_CONFIG_DIR_PATH),
                             Constants.DEPLOYMENT_TOML_FILE).toString();
        }
       return configFilePath;
    }
    /**
     * encrypt the plain text password
     *
     * @param cipher        init cipher
     * @param plainTextPwd  plain text password
     * @return encrypted password
     */
    public static String doEncryption(Cipher cipher, String plainTextPwd) {
        String encodedValue;
        try {
            byte[] encryptedPassword = cipher.doFinal(plainTextPwd.getBytes(Charset.forName(Constants.UTF8)));
            encodedValue = DatatypeConverter.printBase64Binary(encryptedPassword);
        } catch (BadPaddingException e) {
            throw new CipherToolException("Error encrypting password ", e);
        } catch (IllegalBlockSizeException e) {
            throw new CipherToolException("Error encrypting password ", e);
        }
        System.out.println("\nEncryption is done Successfully\n");
        return encodedValue;
    }

    /**
     * Read toml file and return list of secrets
     *
     * @param configFilePath    file path to deployment toml
     * @return      Map of secrets
     */
    public static Map<String, String> getSecreteFromConfiguration(String configFilePath) {
        Map<String, String> context = new LinkedHashMap<>();
        try {
            TomlParseResult result = Toml.parse(Paths.get(configFilePath));
            if (result.hasErrors()) {
                throw new CipherToolException("Error while parsing TOML config file");
            }
            TomlTable table = result.getTable(Constants.SECRET_PROPERTY_MAP_NAME);
            if (table != null) {
                table.dottedKeySet().forEach(key -> context.put(key, table.getString(key)));
            }

        } catch (IOException e) {
            System.out.println("Error parsing file " + configFilePath + e.toString());
            return context;
        }

        return context;
    }

    /**
     * Read unencrypted value from [secrets] section in deployment toml file
     *
     * @param value key to read
     * @return  unencrypted value
     */
    public static String getUnEncryptedValue(String value) {

        String[] unEncryptedRefs = StringUtils.substringsBetween(value, Constants.SECTION_PREFIX,
                                                                 Constants.SECTION_SUFFIX);
        if (unEncryptedRefs != null && unEncryptedRefs.length == 1) {
            return unEncryptedRefs[0];
        } else {
            return null;
        }
    }

    /**
     * This method provides a secured document builder which will secure XXE attacks.
     *
     * @param setIgnoreComments whether to set setIgnoringComments in DocumentBuilderFactory.
     * @return DocumentBuilder
     * @throws ParserConfigurationException
     */
    public static DocumentBuilder getSecuredDocumentBuilder(boolean setIgnoreComments) throws
            ParserConfigurationException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setIgnoringComments(setIgnoreComments);
        documentBuilderFactory.setNamespaceAware(false);
        documentBuilderFactory.setExpandEntityReferences(false);
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        documentBuilder.setEntityResolver(new EntityResolver() {
            @Override
            public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
                throw new SAXException("Possible XML External Entity (XXE) attack. Skip resolving entity");
            }
        });
        return documentBuilder;
    }
}
