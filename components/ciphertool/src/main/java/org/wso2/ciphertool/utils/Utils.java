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

import com.google.gson.Gson;
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
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

public class Utils {

    private static boolean primaryKeyStore = true;

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
     * Retrieve the value for the given configuration from the following order of files.
     * 1. deployment.toml
     * 2. default.json
     * 3. carbon.xml
     *
     * @param config        Configuration value.
     * @param key           Key of the configuration value in default.json.
     * @param defaultMap    Map that contains values from default.json.
     * @param element       Element.
     * @param xPath         Xpath.
     * @return Configuration value.
     */
    public static String getValueFromConfigs(String config, String key, Map<String, Object> defaultMap,
                                             Element element, String xPath) {

        String value = config;
        try {
            // If the value is empty in deployment.toml, read from default.json
            if (StringUtils.isBlank(value)) {
                value = defaultMap.get(key).toString();
            }
            // If the value is given as a reference, read from default.json
            if (value.startsWith("$ref")) {
                // Read the value between the curly braces as the reference
                // e.g. $ref{<reference>} -> <reference>
                String reference = value.substring(value.indexOf('{') + 1, value.indexOf('}'));
                return defaultMap.get(reference).toString();
            }
            return value;
        // Throw NullPointerException if the value is not available in default.json
        } catch (NullPointerException e) {
            // Read from carbon.xml if default.json is not available
            System.err.println("Invalid value " + key + " " + e);
            return Utils.getValueFromXPath(element, xPath);
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
            Map<String, String> internalKeystoreMap = Utils.getKeystoreFromConfiguration(getDeploymentFilePath(),
                    Constants.INTERNAL_KEYSTORE_PROPERTY_MAP_NAME);
            Map<String, String> primaryKeystoreMap = Utils.getKeystoreFromConfiguration(getDeploymentFilePath(),
                    Constants.PRIMARY_KEYSTORE_PROPERTY_MAP_NAME);
            Map<String, Object> defaultConfigMap = Utils.getJSONConfiguration(getDefaultJSONFilePath());
            try {
                DocumentBuilder docBuilder = getSecuredDocumentBuilder(false);
                Document document = docBuilder.parse(path.toAbsolutePath().toString());

                keyStoreFile = internalKeystoreMap.get(Constants.KEY_FILE_NAME);
                //Use InternalKeyStore if it exists, else use the Primary keystore
                if (StringUtils.isNotBlank(keyStoreFile)) {
                    keyType = Utils.getValueFromConfigs(
                            internalKeystoreMap.get(Constants.KEY_TYPE),
                            Constants.KEYSTORE_INTERNAL_TYPE, defaultConfigMap,
                            document.getDocumentElement(), Constants.InternalKeyStore.KEY_TYPE_XPATH);
                    keyAlias = Utils.getValueFromConfigs(
                            internalKeystoreMap.get(Constants.KEY_ALIAS),
                            Constants.KEYSTORE_INTERNAL_ALIAS, defaultConfigMap,
                            document.getDocumentElement(), Constants.InternalKeyStore.KEY_ALIAS_XPATH);
                    primaryKeyStore = false;
                } else {
                    keyStoreFile = Utils.getValueFromConfigs(
                            primaryKeystoreMap.get(Constants.KEY_FILE_NAME),
                            Constants.KEYSTORE_PRIMARY_FILE_NAME, defaultConfigMap,
                            document.getDocumentElement(), Constants.PrimaryKeyStore.KEY_LOCATION_XPATH);
                    keyType = Utils.getValueFromConfigs(
                            primaryKeystoreMap.get(Constants.KEY_TYPE),
                            Constants.KEYSTORE_PRIMARY_TYPE, defaultConfigMap,
                            document.getDocumentElement(), Constants.PrimaryKeyStore.KEY_TYPE_XPATH);
                    keyAlias = Utils.getValueFromConfigs(
                            primaryKeystoreMap.get(Constants.KEY_ALIAS),
                            Constants.KEYSTORE_PRIMARY_ALIAS, defaultConfigMap,
                            document.getDocumentElement(), Constants.PrimaryKeyStore.KEY_ALIAS_XPATH);
                }

                keyStoreFile = resolveKeyStorePath(keyStoreFile, homeFolder, defaultConfigMap);
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
     * Resolve path of the keystore.
     *
     * @param keyStorePath  path of the keystore
     * @param homeFolder    path of the IS_HOME
     * @param defaultMap    map that contains values from default.json
     * @return  resolved path of the keystore
     */
    public static String resolveKeyStorePath(String keyStorePath, String homeFolder, Map<String, Object> defaultMap) {

        String path = keyStorePath;
        try {
            if (StringUtils.isEmpty(path)) {
                return path;
            }
            // If the value is given as a reference, read from default.json
            if (path.startsWith("$ref")) {
                // Read the value between the curly braces as the reference
                // e.g. $ref{<reference>} -> <reference>
                String reference = path.substring(path.indexOf('{') + 1, path.indexOf('}'));
                path = defaultMap.get(reference).toString();
            }
            // Check whether it's a relative path and is inside {carbon.home}.
            if (path.contains("}")) {
                path = getAbsolutePathWithCarbonHome(path, homeFolder);
                // Check whether it only contains the file name (when retrieved from toml)
            } else if (!path.startsWith(homeFolder)) {
                path = Paths.get(homeFolder, Constants.REPOSITORY_DIR,
                        Constants.RESOURCES_DIR, Constants.SECURITY_DIR, path).toString();
            }
            return path;
        } catch (InvalidPathException e) {
            throw new CipherToolException("Error while resolving the keystore path: " + path, e);
        }
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
     * Get default.json file path.
     *
     * @return Default JSON file path.
     */
    public static Path getDefaultJSONFilePath() {

        String homeFolder = System.getProperty(Constants.CARBON_HOME);
        try {
            return Paths.get(homeFolder, Constants.REPOSITORY_DIR,
                    Constants.RESOURCES_DIR, Constants.CONF_DIR, Constants.DEFAULT_JSON_FILE);
        } catch (InvalidPathException e) {
            System.out.println("Error while resolving the default.json file path" + e.toString());
        }
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
     * Read toml file and return a map of keystore data.
     *
     * @param configFilePath    File path to deployment toml.
     * @param keystoreName      Name of the keystore.
     * @return      Map of keystore data.
     */
    public static Map<String, String> getKeystoreFromConfiguration(String configFilePath, String keystoreName) {

        Map<String, String> context = new LinkedHashMap<>();
        try {
            TomlParseResult result = Toml.parse(Paths.get(configFilePath));
            if (result.hasErrors()) {
                throw new CipherToolException("Error while parsing TOML config file");
            }
            TomlTable table = result.getTable(keystoreName);
            if (table != null) {
                table.dottedKeySet().forEach(key -> context.put(key, table.getString(key)));
            }
        // Returns an empty map if the deployment toml is not found.
        } catch (IOException e) {
            System.out.println("Error parsing file " + configFilePath + e.toString());
        }
        return context;
    }

    /**
     * Read from default.json file and return a map of data.
     *
     * @param jsonFilePath  File path to json file.
     * @return  Map of data.
     */
    public static Map<String, Object> getJSONConfiguration(Path jsonFilePath) {

        Gson gson = new Gson();
        Map<String, Object> map = new HashMap<>();

        try (Reader reader = Files.newBufferedReader(jsonFilePath)) {
            map = gson.fromJson(reader, Map.class);
        // Returns an empty map if the default json file is not found.
        } catch (IOException e) {
            System.out.println("Error parsing file " + jsonFilePath  + " " + e);
        }
        return map;
    }

    /**
     * Read unencrypted value from [secrets] section in deployment toml file
     *
     * @param value key to read
     * @return  unencrypted value
     */
    public static String getUnEncryptedValue(String value) {

        if (!value.contains(Constants.SECTION_PREFIX) || !value.contains(Constants.SECTION_SUFFIX)) {
            return null;
        }
        String unEncryptedValue = StringUtils.substring(value, value.indexOf(Constants.SECTION_PREFIX) + 1,
                value.lastIndexOf(Constants.SECTION_SUFFIX));
        return StringUtils.isNotEmpty(unEncryptedValue) ? unEncryptedValue : null;
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
