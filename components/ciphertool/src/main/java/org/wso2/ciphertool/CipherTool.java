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

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.ciphertool.exception.CipherToolException;
import org.wso2.ciphertool.utils.Constants;
import org.wso2.ciphertool.utils.KeyStoreUtil;
import org.wso2.ciphertool.utils.Utils;
import org.xml.sax.SAXException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.*;
import java.io.*;

import java.nio.charset.Charset;
import java.util.*;

public class CipherTool {

    private static Map<String, String> configFileXpathMap = new HashMap<String, String>();
    private static Map<String, String> aliasPasswordMap = new HashMap<String, String>();

    public static void main(String[] args) {

        initialize(args);
        Cipher cipher = KeyStoreUtil.initializeCipher();
        if (System.getProperty(Constants.CONFIGURE) != null &&
            System.getProperty(Constants.CONFIGURE).equals(Constants.TRUE)) {
            loadXpathValuesAndPasswordDetails();
            secureVaultConfigTokens();
            encryptCipherTextFile(cipher);
            Utils.writeToSecureConfPropertyFile();
        } else if (System.getProperty(Constants.CHANGE) != null &&
                   System.getProperty(Constants.CHANGE).equals(Constants.TRUE)) {
            changePassword(cipher);
        } else {
            encryptedValue(cipher);
        }
    }

    /**
     * init the mode of operation of cipher tool using command line argument
     *
     * @param args command line arguments
     */
    private static void initialize(String[] args) {
        String property;
        for (String arg : args) {
            if (arg.equals("-help")) {
                printHelp();
                System.exit(0);
            } else if (arg.substring(0, 2).equals("-D")) {
                property = arg.substring(2);
                if (property.equals(Constants.CONFIGURE)) {
                    System.setProperty(property, Constants.TRUE);
                } else if (property.equals(Constants.CHANGE)) {
                    System.setProperty(property, Constants.TRUE);
                } else if (property.length() >= 8 && property.substring(0, 8).equals(Constants.CONSOLE_PASSWORD_PARAM)) {
                    System.setProperty(Constants.KEYSTORE_PASSWORD, property.substring(9));
                } else {
                    System.out.println("This option is not define!");
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
        System.out.println("By default, CipherTool can be used for creating encrypted value for given plaint text\n");
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
            String encryptedText = doEncryption(cipher, firstPassword);
            System.out.println("\nEncrypted value is : \n" + encryptedText + "\n");
        } else {
            throw new CipherToolException("Error : Password does not match");
        }
    }

    /**
     * encrypt the plain text password
     *
     * @param cipher        init cipher
     * @param plainTextPwd  plain text password
     * @return encrypted password
     */
    private static String doEncryption(Cipher cipher, String plainTextPwd) {
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
            if (configFileXpathMap.containsKey(passwordAlias)) {
                aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
            } else {
                throw new CipherToolException("XPath value for secret alias '" + passwordAlias + "' cannot be found.");
            }
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
                DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
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
     * @param cipher cipher
     */
    private static void encryptCipherTextFile(Cipher cipher) {
        Properties properties = new Properties();
        for (Map.Entry<String, String> entry : aliasPasswordMap.entrySet()) {
            String value = entry.getValue();
            if (value != null && !value.equals("")) {
                if (value.contains("[") && value.indexOf("]") > 0) {
                    value = value.substring(value.indexOf("[") + 1, value.indexOf("]"));
                    value = doEncryption(cipher, value);
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
            String encryptedValue = doEncryption(cipher, firstPassword);
            aliasPasswordMap.put(key, encryptedValue);
            return encryptedValue;
        } else {
            throw new CipherToolException("Error : Password does not match");
        }
    }

    /**
     * use to change an specific password.
     */
    private static void changePassword(Cipher cipher) {
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
                String newEncryptedValue = getPasswordFromConsole(selectedPasswordAlias, cipher);
                aliasPasswordMap.put(selectedPasswordAlias, newEncryptedValue);
                isModified = true;
            }
        }

        if (isModified) {
            cipherTextProperties.putAll(aliasPasswordMap);
            Utils.writeToPropertyFile(cipherTextProperties,
                                      System.getProperty(Constants.CIPHER_TEXT_PROPERTY_FILE_PROPERTY));
        }
    }
}