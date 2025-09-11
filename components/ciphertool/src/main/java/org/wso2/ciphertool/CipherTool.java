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
import org.wso2.ciphertool.exception.CipherToolException;
import org.wso2.ciphertool.utils.Constants;
import org.wso2.ciphertool.utils.KeyStoreUtil;
import org.wso2.ciphertool.utils.TomlParser;
import org.wso2.ciphertool.utils.Utils;
import org.xml.sax.SAXException;

import javax.crypto.Cipher;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.*;
import java.io.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static org.wso2.ciphertool.utils.Utils.getSecuredDocumentBuilder;

public class CipherTool {

    private static final Map<String, String> configFileXpathMap = new HashMap<String, String>();
    private static final Map<String, String> aliasPasswordMap = new HashMap<String, String>();
    private static String providerName;

    public static void main(String[] args) {
        TomlParser tomlContentHolder = new TomlParser();
        initialize(args, tomlContentHolder);
        Cipher cipher = KeyStoreUtil.initializeCipher(providerName);
        if (System.getProperty(Constants.CONFIGURE) != null &&
                System.getProperty(Constants.CONFIGURE).equals(Constants.TRUE)) {
            if (tomlContentHolder.isFileExist()) {
                Map<String, String> secretMap = tomlContentHolder.getSecrets();
                for (Map.Entry<String, String> entry : secretMap.entrySet()) {
                    String key = entry.getKey();
                    String value = Utils.getUnEncryptedValue(entry.getValue());
                    if (StringUtils.isNotEmpty(value)) {
                        String encryptedValue = Utils.doEncryption(cipher, value);
                        secretMap.replace(key, encryptedValue);
                    }
                }
                updateDeploymentConfigurationWithEncryptedKeys(secretMap);
            } else {
                loadXpathValuesAndPasswordDetails();
                secureVaultConfigTokens();
                encryptCipherTextFile(cipher);
            }
            Utils.writeToSecureConfPropertyFile();
        } else if (System.getProperty(Constants.CHANGE) != null &&
                System.getProperty(Constants.CHANGE).equals(Constants.TRUE)) {
            changePassword(cipher, tomlContentHolder);
        } else {
            encryptedValue(cipher);
        }
    }

    /**
     * init the mode of operation of cipher tool using command line argument
     *
     * @param args command line arguments
     */
    private static void initialize(String[] args, TomlParser tomlContentHolder) {
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
                } else if ((Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY).equals(propertyName)) {
                    setProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY, value,
                            "Invalid transformation algorithm provided. " +
                                    "The default transformation algorithm (RSA) will be used");
                } else if (propertyName.equalsIgnoreCase(Constants.JCEProviders.SECURITY_JCE_PROVIDER)) {
                    if (StringUtils.isNotBlank(value) || Objects.requireNonNull(value).
                            equalsIgnoreCase(Constants.JCEProviders.BOUNCY_CASTLE_PROVIDER) ||
                            value.equalsIgnoreCase(Constants.JCEProviders.BOUNCY_CASTLE_FIPS_PROVIDER)) {
                        providerName = value;
                        KeyStoreUtil.addJceProvider(providerName);
                    } else {
                        System.out.println("Invalid JCE provider provided!");
                    }
                } else if ((Constants.CONSOLE_PASSWORD_PARAM).equals(propertyName)) {
                    setProperty(Constants.KEYSTORE_PASSWORD, value, "Invalid KeyStore password provided!");
                } else {
                    System.out.println("This option is not defined!");
                    System.exit(-1);
                }
            }
        }
        // Avoid setting system properties if initiated by an external program.
        if (!Boolean.getBoolean(Constants.SET_EXTERNAL_SYSTEM_PROPERTY)) {
            Utils.setSystemProperties(tomlContentHolder);
        }
    }

    private static void setProperty(String key, String value, String msg) {
        if (!StringUtils.isBlank(value)) {
            System.setProperty(key, value);
        } else {
            System.out.println(msg);
        }
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
        System.out.println("\t-Dpassword=<password>\t This option would allow user to provide the password as a " +
                           "command line argument. NOTE: Providing the password in command line arguments list is " +
                           "not recommended.\n");
        System.out.println("\t-Dorg.wso2.CipherTransformation=<Transformation algorithm>\t This option would allow user to encrypt plain text " +
                "using the given transformation algorithm. Ex: -Dorg.wso2.CipherTransformation=RSA/ECB/OAEPwithSHA1andMGF1Padding\n");
    }

    /**
     * encrypt text retrieved from Console
     *
     * @param cipher cipher
     */
    private static void encryptedValue(Cipher cipher) {
        String firstPassword = Utils.getValueFromConsole("Enter Plain Text Value : ", true);
        String secondPassword = Utils.getValueFromConsole("Please Enter Value Again : ", true);

        if (!firstPassword.isEmpty() && firstPassword.equals(secondPassword)) {
            String encryptedText = Utils.doEncryption(cipher, firstPassword);
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
                        "Transformation error occurred while writing protected token [" + secretAlias + "] to file: " +
                                fileName, e);
            } catch (SAXException e) {
                throw new CipherToolException(
                        "XML parsing error occurred while writing protected token [" + secretAlias + "] to file: " +
                                fileName, e);
            } catch (IOException e) {
                throw new CipherToolException(
                        "I/O error occurred while writing protected token [" + secretAlias + "] to file: " +
                                fileName, e);
            }

            System.out.println("Protected Token [" + secretAlias + "] is updated in " + fileName + " successfully\n");
        }
    }

    /**
     * Encrypt plain text password defined in cipher-text.properties file. If not read password from command-line and
     * save to cipher-text.properties
     *
     * @param cipher cipher
     */
    private static void encryptCipherTextFile(Cipher cipher) {
        Properties properties = new Properties();
        for (Map.Entry<String, String> entry : aliasPasswordMap.entrySet()) {
            String value = entry.getValue();
            if (value != null && !value.equals("")) {
                if (value.contains("[") && value.indexOf("]") > 0) {
                    value = value.substring(value.indexOf("[") + 1, value.indexOf("]"));
                    value = Utils.doEncryption(cipher, value);
                }
            } else {
                value = getPasswordFromConsole(entry.getKey(), cipher);
            }
            properties.setProperty(entry.getKey(), value);
        }

        Utils.writeToPropertyFile(properties, System.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY));
    }

    /**
     * returns the encrypted value entered via the Console for the given Secret Alias
     * @param key key
     * @param cipher cipher
     * @return encrypted value
     */
    private static String getPasswordFromConsole(String key, Cipher cipher) {
        String firstPassword = Utils.getValueFromConsole("Enter Password of Secret Alias - '" + key + "' : ", true);
        String secondPassword = Utils.getValueFromConsole("Please Enter Password Again : ", true);
        if (!firstPassword.isEmpty() && firstPassword.equals(secondPassword)) {
            String encryptedValue = Utils.doEncryption(cipher, firstPassword);
            aliasPasswordMap.put(key, encryptedValue);
            return encryptedValue;
        } else {
            throw new CipherToolException("Error : Password does not match");
        }
    }

    /**
     * use to change an specific password.
     */
    private static void changePassword(Cipher cipher, TomlParser tomlContentHolder) {
        File deploymentTomlFile = new File(Utils.getDeploymentFilePath());
        List<String> keyValueList = new ArrayList<String>();
        if (deploymentTomlFile.exists()) {
            Map<String, String> secretMap = tomlContentHolder.getSecrets();
            int i = 1;
            for (Map.Entry<String, String> entry : secretMap.entrySet()) {
                aliasPasswordMap.put(entry.getKey(), entry.getValue());
                keyValueList.add(entry.getKey());
                System.out.println("[" + i++ + "] " + entry.getKey());
            }
        } else {
            throw new CipherToolException("deployment.toml file not found on the path " +
                                          deploymentTomlFile.getAbsolutePath());
        }
        boolean isModified = false;
        String value;
        while (!(value = Utils.getValueFromConsole(
                "Please enter the Number which is corresponding to the Password that is needed be changed "
                        + "[Press Enter to Skip] : ", false)).isEmpty()) {
            if (!value.trim().equals("")) {
                String selectedPasswordAlias = keyValueList.get(Integer.parseInt(value.trim()) - 1);
                String newEncryptedValue = getPasswordFromConsole(selectedPasswordAlias, cipher);
                aliasPasswordMap.put(selectedPasswordAlias, newEncryptedValue);
                isModified = true;
            }
        }

        if (isModified) {
            updateDeploymentConfigurationWithEncryptedKeys(aliasPasswordMap);
        }
    }

    private static void updateDeploymentConfigurationWithEncryptedKeys(Map<String, String> encryptedKeyMap)
            throws CipherToolException {
        try {
            List<String> lines = Files.readAllLines(Paths.get(Utils.getDeploymentFilePath()));
            try (BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(
                    Files.newOutputStream(Paths.get(Utils.getDeploymentFilePath())), StandardCharsets.UTF_8))) {
                boolean found = false;
                for (String line : lines) {
                    boolean isLineCommented = line.trim().matches("^#.*");
                    if (found && !isLineCommented) {
                        if (line.matches("\\[.+\\]")) {
                            found = false;
                        } else {
                            StringTokenizer stringTokenizer = new StringTokenizer(line,
                                                                                  Constants.KEY_VALUE_SEPERATOR);
                            if (stringTokenizer.hasMoreTokens()) {
                                String key = stringTokenizer.nextToken();
                                String value = encryptedKeyMap.get(key.trim());
                                line = key.concat("= \"").concat(value).concat("\"");
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
}
