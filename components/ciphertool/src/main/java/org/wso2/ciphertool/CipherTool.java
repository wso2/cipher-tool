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

import java.util.*;

public class CipherTool {

    private static Map<String, String> configFileXpathMap = new HashMap<String, String>();
    private static Map<String, String> aliasPasswordMap = new HashMap<String, String>();

    public static void main(String[] args) {

        initialize(args);
        Cipher cipher = KeyStoreUtil.initializeCipher();
//        if (System.getProperty(Constants.CONFIGURE) != null && System.getProperty(Constants.CONFIGURE).equals("true")) {
            loadXpathValuesAndPasswordDetails();
            secureVaultConfigTokens();
            encryptCipherTextFile(cipher);
            writeToSecureConfPropertyFile();
//        } else if (System.getProperty(Constants.CHANGE) != null &&
//                   System.getProperty(Constants.CHANGE).equals("true")) {
//            changePassword(cipher);
//        } else {
//            encryptedValue(cipher);
//        }
    }

    /**
     * init the mode of operation of cipher tool using command line argument
     *
     * @param args command line arguments
     */
    private static void initialize(String[] args) {
        String osName = System.getProperty(Constants.OS_NAME);
        File file;
        if (!osName.toLowerCase().contains("win")) {
            file = new File("." + File.separator + ".." + File.separator);
        } else {
            file = new File("." + File.separator);
        }

        String carbonHome;
        try {
            carbonHome = file.getCanonicalFile().toString();
        } catch (IOException e) {
            throw new CipherToolException("IOError while calculating CARBON_HOME directory location ", e);
        }

        carbonHome = "/home/nira/wso2/AS/wso2as-6.0.0-SNAPSHOT"; //ToDo : This is for testing

        String property;
        for (String arg : args) {
            if (arg.equals("-help")) {
                printHelp();
                System.exit(0);
            } else if (arg.substring(0, 2).equals("-D")) {
                property = arg.substring(2);
                if (property.equals(Constants.CONFIGURE)) {
                    System.setProperty(property, "true");
                } else if (property.equals(Constants.CHANGE)) {
                    System.setProperty(property, "true");
                } else if (property.equals(Constants.KEYSTORE_PASSWORD)) {
                    property = arg.substring(11);
                    System.setProperty(Constants.KEYSTORE_PASSWORD, property);
                } else {
                    System.out.println("This option is not define!");
                    System.exit(0);
                }
            }
        }

        if (carbonHome == null || carbonHome.isEmpty()) {
            System.out.println("\nCARBON_HOME is not properly set. Please Enter CARBON_HOME again : ");
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            try {
                carbonHome = input.readLine();
            } catch (IOException e) {
                throw new CipherToolException("IOError reading command line inputs  ", e);
            } finally {
                try {
                    input.close();
                } catch (IOException e) {
                    System.err.println("Error while closing input stream");
                }
            }
        }

        System.setProperty(Constants.CARBON_HOME, carbonHome);
    }

    /**
     * print the help on command line
     */
    private static void printHelp() {

        System.out.println("\n---------Cipher Tool Help---------\n");
        System.out.println("By default, CipherTool can be used for creating encrypted value for given plaint text\n");
        System.out.println("Options :\n");

        System.out.println("\t-Dconfigure\t\t This option would allow user to secure plain text passwords in carbon " +
                           "configuration files. CipherTool replace all the password listed in " +
                           "cipher-text.properties file with encrypted values and modify related password elements " +
                           "in the configuration files with secret alias names. Also secret-conf.properties file is " +
                           "modified with the default configuration data");

        System.out.println("\t-Dchange\t\t This option would allow user to change the specific password which has " +
                           "been secured\n");
        System.out.println("\t-Dpassword=<password>\t This option would allow user to provide the password as a " +
                           "command line argument. NOTE: Providing the password in command line arguments list is " +
                           "not recommended.\n");
    }

    private static void encryptedValue(Cipher cipher) {
        String firstPassword = Utils.getValueFromConsole("Enter Plain Text Value : ");
        String secondPassword = Utils.getValueFromConsole("Please Enter Value Again : ");

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
     * @param plainTextPass plain text password
     * @return encrypted password
     */
    private static String doEncryption(Cipher cipher, String plainTextPass) {
        String encodedValue;
        try {
            byte[] plainTextPassByte = plainTextPass.getBytes();
            byte[] encryptedPassword = cipher.doFinal(plainTextPassByte);
            encodedValue = DatatypeConverter.printBase64Binary(encryptedPassword);
        } catch (BadPaddingException e) {
            throw new CipherToolException("Error encrypting password ", e);
        } catch (IllegalBlockSizeException e) {
            throw new CipherToolException("Error encrypting password ", e);
        }
        System.out.println("\nEncryption is done Successfully\n");
        return encodedValue;
    }

    private static void loadXpathValuesAndPasswordDetails() {
        Properties cipherToolProperties = Utils.loadProperties(Constants.CIPHER_TOOL_PROPERTY_FILE);
        for (Object key : cipherToolProperties.keySet()) {
            String passwordAlias = (String) key;
            configFileXpathMap.put(passwordAlias, cipherToolProperties.getProperty(passwordAlias));
        }

        Properties cipherTextProperties = Utils.loadProperties(Constants.CIPHER_PROPERTY_FILE);
        for (Object key : cipherTextProperties.keySet()) {
            String passwordAlias = (String) key;
            if (configFileXpathMap.containsKey(passwordAlias)) {
                aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
            } else {
                System.out.println("XPath value for secret alias '" + passwordAlias +
                                   "' cannot be found. Please enter XPath manually: ");
                String buffer1, buffer2;
                BufferedReader input1 = new BufferedReader(new InputStreamReader(System.in));
                try {
                    buffer1 = input1.readLine();
                } catch (IOException e) {
                    throw new CipherToolException("IOError reading command line inputs  ", e);
                }

                System.out.println("Please enter configuration file : ");
                BufferedReader input2 = new BufferedReader(new InputStreamReader(System.in));
                try {
                    buffer2 = input2.readLine();
                } catch (IOException e) {
                    throw new CipherToolException("IOError reading command line inputs  ", e);
                }

                if (buffer1 != null && !buffer1.trim().equals("") && buffer2 != null &&
                    !buffer2.trim().equals("")) {
                    configFileXpathMap.put(passwordAlias, buffer1.trim() + buffer2.trim());
                    aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
                }
            }
        }
    }

    /**
     * write the XML syntax to the configuration files, to show that the password is secured.
     */
    private static void secureVaultConfigTokens() {
        for (String key : configFileXpathMap.keySet()) {
            String unprocessedXpath = configFileXpathMap.get(key);
            boolean capitalLetter = false;
            String XPath;
            String fileName = unprocessedXpath.substring(0, unprocessedXpath.indexOf("//"));
            if (unprocessedXpath.indexOf(",") > 0) {
                if ((unprocessedXpath.substring(unprocessedXpath.indexOf(",") + 1)).trim().equals("true")) {
                    capitalLetter = true;
                }
                XPath = unprocessedXpath.substring(unprocessedXpath.indexOf("//"), unprocessedXpath.indexOf(","));
            } else {
                XPath = unprocessedXpath.substring(unprocessedXpath.indexOf("//"));
            }
            tokenToConfigFile(fileName, XPath, key, capitalLetter);
        }
    }

    /**
     * write the XML syntax to the configuration file,
     *
     * @param fileName      file name
     * @param xPath         Xpath value of the element that needs to be modified
     * @param secretAlias   alias name for the element value
     * @param capitalLetter element name is started with Capital letter or not
     */
    private static void tokenToConfigFile(String fileName, String xPath, String secretAlias, boolean capitalLetter) {
        if (xPath != null && !xPath.equals("") && secretAlias != null && !secretAlias.equals("")) {
            File configFile = Utils.getConfigFile(fileName);
            if (!configFile.exists()) {
                return;
            }
            String filePath = configFile.getPath();
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
                            node.setTextContent(Constants.SecureVault.PASSWORD);
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
                        "IOError writing protected token  [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (TransformerException e) {
                throw new CipherToolException(
                        "Error writing protected token [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (SAXException e) {
                throw new CipherToolException(
                        "Error writing protected token  [" + secretAlias + "] to " + fileName + " file ", e);
            } catch (IOException e) {
                throw new CipherToolException(
                        "IOError writing protected token  [" + secretAlias + "] to " + fileName + " file ", e);
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
        for (String key : aliasPasswordMap.keySet()) {
            String value = aliasPasswordMap.get(key);
            if (value != null && !value.equals("")) {
                if (value.contains("[") && value.indexOf("]") > 0) {
                    value = value.substring(value.indexOf("[") + 1, value.indexOf("]"));
                    aliasPasswordMap.put(key, doEncryption(cipher, value));
                }
            } else {
                getPasswordFromConsole(key, cipher);
            }
        }

        Properties properties = new Properties();
        for (String key : aliasPasswordMap.keySet()) {
            properties.setProperty(key, aliasPasswordMap.get(key));
        }
        Utils.writeToPropertyFile(properties, Constants.CIPHER_PROPERTY_FILE);
    }

    public static void getPasswordFromConsole(String key, Cipher cipher) {
        String firstPassword = Utils.getValueFromConsole("Enter Password of Secret Alias - '" + key + "' : ");
        String secondPassword = Utils.getValueFromConsole("Please Enter Password Again : ");
        if (!firstPassword.isEmpty() && firstPassword.equals(secondPassword)) {
            aliasPasswordMap.put(key, doEncryption(cipher, firstPassword));
        } else {
            throw new CipherToolException("Error : Password does not match");
        }
    }

    private static void writeToSecureConfPropertyFile() {
        Properties properties = new Properties();

        String keyStoreFile = System.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_XPATH);
        String keyType = System.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_XPATH);
        String aliasName = System.getProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_XPATH);

        properties
                .setProperty(Constants.SecureVault.CARBON_SECRET_PROVIDER, Constants.SecureVault.SECRET_PROVIDER_CLASS);
        properties.setProperty(Constants.SecureVault.SECRET_REPOSITORIES, "file");
        properties.setProperty(Constants.SecureVault.SECRET_FILE_PROVIDER,
                               Constants.SecureVault.SECRET_FILE_BASE_PROVIDER_CLASS);
        properties.setProperty(Constants.SecureVault.SECRET_FILE_LOCATION,
                               Constants.REPOSITORY_DIR + File.separator + Constants.CONF_DIR + File.separator +
                               Constants.SECURITY_DIR + File.separator + Constants.CIPHER_PROPERTY_FILE);
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

        Utils.writeToPropertyFile(properties, Constants.SECRET_PROPERTY_FILE);

        System.out.println("\nSecret Configurations are written to the property file successfully\n");
    }

    /**
     * use to change an specific password.
     */
    private static void changePassword(Cipher cipher) {
        Properties cipherTextProperties = Utils.loadProperties(Constants.CIPHER_PROPERTY_FILE);
        List<String> keyValueList = new ArrayList<String>();
        int i = 1;
        for (Object key : cipherTextProperties.keySet()) {
            String passwordAlias = (String) key;
            aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
            keyValueList.add(passwordAlias);
            System.out.println("[" + i + "] " + passwordAlias);
            i++;
        }
        while (true) {
            System.out.println("\nPlease enter the Number which is corresponding to " +
                               "the Password that is needed be changed [Press Enter to Skip] :");
            String buffer;
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            try {
                buffer = input.readLine();
            } catch (IOException e) {
                throw new CipherToolException("IOError reading command line inputs  ", e);
            }

            if (buffer != null && !buffer.trim().equals("")) {
                String selectedPasswordAlias = keyValueList.get(Integer.parseInt(buffer.trim()) - 1);
                getPasswordFromConsole(selectedPasswordAlias, cipher);
            } else {
                break;
            }
        }
    }
}