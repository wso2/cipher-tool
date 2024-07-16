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
package org.wso2.ciphertool;


import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.ciphertool.cipher.AsymmetricCipher;
import org.wso2.ciphertool.cipher.CipherFactory;
import org.wso2.ciphertool.cipher.CipherMode;
import org.wso2.ciphertool.cipher.SymmetricCipher;
import org.wso2.ciphertool.exception.CipherToolException;
import org.wso2.ciphertool.utils.Constants;
import org.wso2.ciphertool.utils.KeyStoreUtil;
import org.wso2.ciphertool.utils.Utils;
import org.xml.sax.SAXException;

import javax.crypto.SecretKey;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import static org.wso2.ciphertool.utils.Utils.getSecuredDocumentBuilder;

public class CipherTool {

    private static Map<String, String> configFileXpathMap = new HashMap<String, String>();
    private static Map<String, String> aliasPasswordMap = new HashMap<String, String>();

    public static void main(String[] args) {

        initialize(args);
        KeyStore keyStore = KeyStoreUtil.getKeyStore();
        CipherMode cipherMode = CipherFactory.createCipher(keyStore);
        if (Constants.TRUE.equals(System.getProperty(Constants.CONFIGURE))) {
            File deploymentTomlFile = new File(Utils.getDeploymentFilePath());
            if (deploymentTomlFile.exists()) {
                Map<String, String> secretMap = Utils.getSecreteFromConfiguration(Utils.getDeploymentFilePath());
                for (Map.Entry<String, String> entry : secretMap.entrySet()) {
                    String key = entry.getKey();
                    String value = Utils.getUnEncryptedValue(entry.getValue());
                    if (StringUtils.isNotEmpty(value)) {
                        String encryptedValue = cipherMode.doEncryption(value);
                        secretMap.replace(key, encryptedValue);
                    }
                }
                updateDeploymentConfigurationWithEncryptedKeys(secretMap);
            } else {
                loadXpathValuesAndPasswordDetails();
                secureVaultConfigTokens();
                encryptCipherTextFile(cipherMode);
            }
            Utils.writeToSecureConfPropertyFile();
        } else if (Constants.TRUE.equals(System.getProperty(Constants.ROTATE))) {
            String oldAlias  = System.getProperty(Constants.OLD_KEY_ALIAS);
            if (StringUtils.isBlank(oldAlias)) {
                throw new CipherToolException(
                        Constants.Error.PARAMETER_REQUIRED_FOR_ROTATE_MODE.getMessage(Constants.OLD_KEY_ALIAS));
            }
            CipherMode oldCipherMode = isSymmetricKey(oldAlias, keyStore)
                    ? new SymmetricCipher(keyStore, oldAlias) : new AsymmetricCipher(keyStore, oldAlias);
            File deploymentTomlFile = new File(Utils.getDeploymentFilePath());
            if (deploymentTomlFile.exists()) {
                Map<String, String> secretMap = Utils.getSecreteFromConfiguration(Utils.getDeploymentFilePath());
                for (Map.Entry<String, String> entry : secretMap.entrySet()) {
                    String key = entry.getKey();
                    String oldEncryptedValue = Utils.getEncryptedValue(entry.getValue());
                    if (StringUtils.isNotEmpty(oldEncryptedValue)) {
                        String value = oldCipherMode.doDecryption(oldEncryptedValue);
                        if (StringUtils.isNotEmpty(value)) {
                            String encryptedValue = cipherMode.doEncryption(value);
                            secretMap.replace(key, encryptedValue);
                        }
                    }
                }
                updateDeploymentConfigurationWithEncryptedKeys(secretMap);
            } else {
                throw new CipherToolException(Constants.Error.TOML_NOT_FOUND.getMessage(deploymentTomlFile));
            }
            Utils.writeToSecureConfPropertyFile();
        } else if (Constants.TRUE.equals(System.getProperty(Constants.CHANGE))) {
            changePassword(cipherMode);
        } else {
            encryptedValue(cipherMode);
        }
    }

    /**
     * init the mode of operation of cipher tool using command line argument
     *
     * @param args command line arguments
     */
    private static void initialize(String[] args) {
        for (String arg : args) {
            if (arg.equals("-help")) {
                printHelp();
                System.exit(0);
            } else if (arg.substring(0, 2).equals("-D")) {
                String propertyName;
                final String property = propertyName = arg.substring(2);
                String value = null;
                final int index = property.indexOf("=");
                if (index != -1) {
                    propertyName = property.substring(0, index);
                    value = property.substring(index + 1);
                }
                if ((Constants.CONFIGURE).equals(propertyName)) {
                    System.setProperty(property, Constants.TRUE);
                } else if ((Constants.CHANGE).equals(propertyName)) {
                    System.setProperty(property, Constants.TRUE);
                } else if ((Constants.SYMMETRIC).equals(propertyName)) {
                    System.setProperty(property, Constants.TRUE);
                } else if (Constants.ROTATE.equals(propertyName)) {
                    System.setProperty(property, Constants.TRUE);
                } else if (Constants.OLD_KEY_ALIAS.equals(propertyName)) {
                    if (!StringUtils.isBlank(value)) {
                        System.setProperty(Constants.OLD_KEY_ALIAS, value);
                    }
                } else if ((Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY).equals(propertyName)) {
                    if (!StringUtils.isBlank(value)) {
                        System.setProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY, value);
                    } else {
                        System.out.println("Invalid transformation algorithm provided. The default transformation algorithm will be used");
                    }
                } else if (propertyName.length() >= 8 && (Constants.CONSOLE_PASSWORD_PARAM).equals(propertyName.substring(0, 8))) {
                    System.setProperty(Constants.KEYSTORE_PASSWORD, property.substring(9));
                } else {
                    System.out.println("This option is not defined!");
                    System.exit(-1);
                }
            }
        }
        Utils.setSystemProperties();
    }

    /**
     * print the help on command line
     */
    private static void printHelp() {

        System.out.println("\n---------Cipher Tool Help---------\n");
        System.out.println("By default, CipherTool can be used for creating encrypted value for given plain text using RSA algorithm\n");
        System.out.println("Options :\n");

        System.out.println("\t-Dconfigure\t\t This option would allow user to secure plain text passwords in carbon " +
                           "configuration files. CipherTool will replace all the passwords listed in " +
                           "cipher-text.properties file with encrypted values and modify related password elements " +
                           "in the configuration files with secret alias names. Also secret-conf.properties file is " +
                           "modified with the default configuration data");

        System.out.println("\t-Dchange\t\t This option would allow user to change the specific password which has " +
                           "been secured\n");
        System.out.println("\t-Drotate\t\t This option is used to rotate the existing encrypted values to a new secret " +
                "alias. Requires providing the old alias.\n");
        System.out.println("\t-Dsymmetric\t\t This option allows the user to use symmetric encryption for creating " +
                "encrypted values. It can be used with -Dconfigure, -Dchange, or -Drotate.\n");
        System.out.println("\t-Dold.alias=<Old secret alias>\t This specifies the old alias used in rotate mode.");
        System.out.println("\t-Dpassword=<password>\t This option would allow user to provide the password as a " +
                           "command line argument. NOTE: Providing the password in command line arguments list is " +
                           "not recommended.\n");
        System.out.println("\t-Dorg.wso2.CipherTransformation=<Transformation algorithm>\t This option would allow user to encrypt plain text " +
                "using the given transformation algorithm. Ex: -Dorg.wso2.CipherTransformation=RSA/ECB/OAEPwithSHA1andMGF1Padding\n");
    }

    /**
     * Encrypt text retrieved from Console.
     *
     * @param cipherMode Cipher mode (asymmetric or symmetric).
     */
    private static void encryptedValue(CipherMode cipherMode) {
        String firstPassword = Utils.getValueFromConsole("Enter Plain Text Value : ", true);
        String secondPassword = Utils.getValueFromConsole("Please Enter Value Again : ", true);

        if (!firstPassword.isEmpty() && firstPassword.equals(secondPassword)) {
            String encryptedText = cipherMode.doEncryption(firstPassword);
            System.out.println("\nEncrypted value is : \n" + encryptedText + "\n");
        } else {
            throw new CipherToolException("Error : Password does not match");
        }
    }

    /**
     * loads the secret alias, config filename and xpath
     */
    private static void loadXpathValuesAndPasswordDetails() {
        Properties cipherToolProperties =
                Utils.loadProperties(System.getProperty(Constants.CIPHER_TOOL_PROPERTY_FILE_PROPERTY));
        for (Object key : cipherToolProperties.keySet()) {
            String passwordAlias = (String) key;
            configFileXpathMap.put(passwordAlias, cipherToolProperties.getProperty(passwordAlias));
        }

        Properties cipherTextProperties =
                Utils.loadProperties(System.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY));
        for (Object key : cipherTextProperties.keySet()) {
            String passwordAlias = (String) key;
            aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
        }
    }

    /**
     * write the XML syntax to the configuration files, to show that the password is secured.
     */
    private static void secureVaultConfigTokens() {
        for (Map.Entry<String, String> entry : configFileXpathMap.entrySet()) {
            String unprocessedXpath = entry.getValue();
            String encryptParamKey = "", XPath;
            int endofFilePath = unprocessedXpath.indexOf("//");
            if (endofFilePath < 0) {
                throw new CipherToolException("XPath is not defined for " + entry.getKey());
            }
            String fileName = unprocessedXpath.substring(0, endofFilePath);
            if (unprocessedXpath.indexOf(",") > 0) {
                if ((unprocessedXpath.substring(unprocessedXpath.indexOf(",") + 1)).trim().equals("true") &&
                    unprocessedXpath.charAt(unprocessedXpath.indexOf(",") - 1) == ']') {
                    encryptParamKey = unprocessedXpath
                            .substring(unprocessedXpath.lastIndexOf('[') + 2, unprocessedXpath.indexOf(",") - 1);
                }
                XPath = unprocessedXpath.substring(endofFilePath, unprocessedXpath.indexOf(","));
            } else {
                XPath = unprocessedXpath.substring(endofFilePath);
            }
            tokenToConfigFile(fileName, XPath, entry.getKey(), encryptParamKey);
        }
    }

    /**
     * write the XML syntax to the configuration file,
     *
     * @param fileName        file name
     * @param xPath           Xpath value of the element that needs to be modified
     * @param secretAlias     alias name for the element value
     * @param encryptParamKey If this value is not Empty then its corresponding value to "password"
     */
    private static void tokenToConfigFile(String fileName, String xPath, String secretAlias, String encryptParamKey) {
        if (xPath != null && !xPath.equals("") && secretAlias != null && !secretAlias.equals("")) {
            String filePath = Utils.getConfigFilePath(fileName);
            try {
                DocumentBuilder docBuilder = getSecuredDocumentBuilder(false);
                Document doc = docBuilder.parse(filePath);
                Node rootNode = doc.getDocumentElement();
                Node secretNamespaceNode = doc.createAttribute(Constants.SecureVault.NS_PREFIX);
                secretNamespaceNode.setTextContent(Constants.SecureVault.NS);
                rootNode.getAttributes().setNamedItem(secretNamespaceNode);
                Node secretProviderNode = doc.createAttribute(Constants.SecureVault.ATTRIBUTE);
                secretProviderNode.setTextContent(Constants.SecureVault.SECRET_PROVIDER_CLASS);

                XPathFactory xpf = XPathFactory.newInstance();
                XPath xp = xpf.newXPath();
                XPathExpression xpathEx = xp.compile(xPath);
                NodeList securedNodes = (NodeList) xpathEx.evaluate(doc.getDocumentElement(), XPathConstants.NODESET);
                if (securedNodes != null && securedNodes.getLength() > 0) {
                    for (int i = 0; i < securedNodes.getLength(); i++) {
                        Node secretAliasNode = doc.createAttribute(Constants.SecureVault.ALIAS);
                        secretAliasNode.setTextContent(secretAlias);
                        Node node = securedNodes.item(i);
                        if (node != null) {
                            if (!encryptParamKey.isEmpty()) {
                                node.getAttributes().getNamedItem(encryptParamKey)
                                    .setNodeValue(Constants.SecureVault.PASSWORD);
                            } else {
                                node.setTextContent(Constants.SecureVault.PASSWORD);
                            }
                            node.getAttributes().setNamedItem(secretAliasNode);
                        }
                    }
                } else {
                    throw new CipherToolException(
                            "Element for secret alias '" + secretAlias + "' can not be found in " +
                            fileName + " file or You have entered invalid Xpath value");
                }
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                Transformer transformer = transformerFactory.newTransformer();
                DOMSource source = new DOMSource(doc);
                StreamResult result = new StreamResult(new File(filePath));
                transformer.transform(source, result);
            } catch (ParserConfigurationException e) {
                throw new CipherToolException(
                        "Error writing protected token [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (XPathExpressionException e) {
                throw new CipherToolException(
                        "Error writing protected token  [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (TransformerException e) {
                throw new CipherToolException(
                        "Error writing protected token [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (SAXException e) {
                throw new CipherToolException(
                        "Error writing protected token  [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (IOException e) {
                throw new CipherToolException(
                        "Error writing protected token  [" + secretAlias + "] to " + fileName + " file ", e);
            }

            System.out.println("Protected Token [" + secretAlias + "] is updated in " + fileName + " successfully\n");
        }
    }

    /**
     * Encrypt plain text password defined in cipher-text.properties file. If not read password from command-line and
     * save to cipher-text.properties
     *
     * @param cipherMode Cipher mode (asymmetric or symmetric).
     */
    private static void encryptCipherTextFile(CipherMode cipherMode) {
        Properties properties = new Properties();
        for (Map.Entry<String, String> entry : aliasPasswordMap.entrySet()) {
            String value = entry.getValue();
            if (value != null && !value.equals("")) {
                if (value.contains("[") && value.indexOf("]") > 0) {
                    value = value.substring(value.indexOf("[") + 1, value.indexOf("]"));
                    value = cipherMode.doEncryption(value);
                }
            } else {
                value = getPasswordFromConsole(entry.getKey(), cipherMode);
            }
            properties.setProperty(entry.getKey(), value);
        }

        Utils.writeToPropertyFile(properties, System.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY));
    }

    /**
     * returns the encrypted value entered via the Console for the given Secret Alias
     * @param key key
     * @param cipherMode Cipher mode (asymmetric or symmetric).
     * @return encrypted value
     */
    private static String getPasswordFromConsole(String key, CipherMode cipherMode) {
        String firstPassword = Utils.getValueFromConsole("Enter Password of Secret Alias - '" + key + "' : ", true);
        String secondPassword = Utils.getValueFromConsole("Please Enter Password Again : ", true);
        if (!firstPassword.isEmpty() && firstPassword.equals(secondPassword)) {
            String encryptedValue = cipherMode.doEncryption(firstPassword);
            aliasPasswordMap.put(key, encryptedValue);
            return encryptedValue;
        } else {
            throw new CipherToolException("Error : Password does not match");
        }
    }

    /**
     * Use to change a specific password.
     *
     * @param cipherMode Cipher mode (asymmetric or symmetric).
     */
    private static void changePassword(CipherMode cipherMode) {
        Properties cipherTextProperties = Utils.loadProperties(System.getProperty(
                Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY));
        List<String> keyValueList = new ArrayList<String>();
        int i = 1;
        for (Object key : cipherTextProperties.keySet()) {
            String passwordAlias = (String) key;
            aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
            keyValueList.add(passwordAlias);
            System.out.println("[" + i++ + "] " + passwordAlias);
        }
        boolean isModified = false;
        String value;
        while (!(value = Utils.getValueFromConsole(
                "Please enter the Number which is corresponding to the Password that is needed be changed "
                        + "[Press Enter to Skip] : ", false)).isEmpty()) {
            if (!value.trim().equals("")) {
                String selectedPasswordAlias = keyValueList.get(Integer.parseInt(value.trim()) - 1);
                String newEncryptedValue = getPasswordFromConsole(selectedPasswordAlias, cipherMode);
                aliasPasswordMap.put(selectedPasswordAlias, newEncryptedValue);
                isModified = true;
            }
        }

        if (isModified) {
            cipherTextProperties.putAll(aliasPasswordMap);
            Utils.writeToPropertyFile(cipherTextProperties,
                    System.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY));

            File deploymentTomlFile = new File(Utils.getDeploymentFilePath());
            if (deploymentTomlFile.exists()) {
                Map<String, String> secretMap = Utils.getSecreteFromConfiguration(Utils.getDeploymentFilePath());
                for (Map.Entry<String, String> entry : secretMap.entrySet()) {
                    String encryptedValue = cipherTextProperties.getProperty(entry.getKey());
                    String key = entry.getKey();
                    if (StringUtils.isNotEmpty(encryptedValue)) {
                        secretMap.replace(key, encryptedValue);
                    }
                }
                updateDeploymentConfigurationWithEncryptedKeys(secretMap);
            }
        }
    }

    private static void updateDeploymentConfigurationWithEncryptedKeys(Map<String, String> encryptedKeyMap)
            throws CipherToolException {
        try {
            List<String> lines = Files.readAllLines(Paths.get(Utils.getDeploymentFilePath()));
            try (BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(new
                 FileOutputStream(Utils.getDeploymentFilePath()), StandardCharsets.UTF_8))) {
                boolean found = false;
                for (String line : lines) {
                    if (found) {
                        if (line.matches("[.+]")) {
                            found = false;
                        } else {
                            StringTokenizer stringTokenizer = new StringTokenizer(line,
                                                                                  Constants.KEY_VALUE_SEPERATOR);
                            if (stringTokenizer.hasMoreTokens()) {
                                String key = stringTokenizer.nextToken();
                                String value = encryptedKeyMap.get(key.trim());
                                line = key.concat(" = \"").concat(value).concat("\"");
                            }
                        }
                    } else {
                        if (Constants.SECRETS_SECTION.equals(line.trim())) {
                            found = true;
                        }
                    }
                    bufferedWriter.write(line);
                    bufferedWriter.newLine();
                }
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            throw new CipherToolException("Error while writing encrypted values into deployment file", e);
        }
    }

    /**
     * Checks if the key associated with the given alias in the provided keystore is a symmetric key.
     *
     * @param keyAlias the alias of the key to be checked.
     * @param keystore the keystore containing the key.
     * @return true if the key is a symmetric key, false otherwise.
     * @throws CipherToolException if there is an error initializing the cipher or retrieving the key
     */
    private static boolean isSymmetricKey(String keyAlias, KeyStore keystore) {
        try {
            Key key = keystore.getKey(keyAlias, KeyStoreUtil.getKeystorePassword().toCharArray());
            // Check if the key is symmetric or not.
            if (key instanceof SecretKey) {
                return true;
            }
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        } catch (UnrecoverableKeyException e) {
            throw new CipherToolException("Error retrieving key associated with alias : " + keyAlias, e);
        }
        return false;
    }
}
