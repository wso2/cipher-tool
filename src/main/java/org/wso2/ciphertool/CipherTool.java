/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.ciphertool;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * This is a command-line tool for encrypt password of configuration file. This class reads password
 * from command line, encrypt and then write encrypted values to cipher-text.properties file
 */
public class CipherTool {

    private static Map<String, String> aliasXpathMap = new HashMap<String, String>();
    private static Map<String, String> configFileXpathMap = new HashMap<String, String>();
    private static Map<String, String> aliasPasswordMap = new HashMap<String, String>();
    private static String carbonHome;
    private static Cipher cipher;

    public static void main(String[] args) {

        init(args);
        cipher = initCipher();
        if (System.getProperty("configure") != null && System.getProperty("configure").equals("true")) {
            loadXpathValuesAndPasswordDetails();
            writeSecureVaultConfigTokens();
            createEncryptedValues();
            writeEncryptedValues();
            writeConfigurations();
        } else if (System.getProperty("change") != null && System.getProperty("change").equals("true")) {
            changePassword();
        } else {
            createEncryptedValue();
        }
    }

    /**
     * init the mode of operation of cipher tool using command line argument
     *
     * @param args command line arguments
     */
    private static void init(String[] args) {

        String osName = System.getProperty("os.name");
        File file;
        if (osName.toLowerCase().indexOf("win") == -1) {
            file = new File("." + File.separator + ".." + File.separator);
        } else {
            file = new File("." + File.separator);
        }

        try {
            System.setProperty("carbon.home", file.getCanonicalFile().toString());
        } catch (IOException e) {
            handleException("IOError while calculating CARBON_HOME directory location ", e);
        }

        for (String arg : args) {
            if (arg.equals("-help")) {
                printHelp();
                System.exit(0);
            } else if (arg.equals("-Dchange")) {
                String property = arg.substring(2);
                System.setProperty(property, "true");
            } else if (arg.equals("-Dconfigure")) {
                String property = arg.substring(2);
                System.setProperty(property, "true");
            } else if (arg.startsWith("-Dpassword=")) {
                String property = arg.substring(11);
                System.setProperty("password", property);
            }
        }


        carbonHome = System.getProperty("carbon.home");
        if (carbonHome == null || carbonHome.equals("")) {
            System.out.println("\nCARBON_HOME is not properly set. Please Enter CARBON_HOME again : ");
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            try {
                carbonHome = input.readLine();
            } catch (IOException e) {
                handleException("IOError reading command line inputs  ", e);
            } finally {
                try {
                    input.close();
                } catch (IOException e) {
                    System.err.println("Error while closing input stream");
                }
            }
        }
    }

    /**
     * print the help on command line
     */
    private static void printHelp() {

        System.out.println("\n---------Cipher Tool Help---------\n");
        System.out.println("By default, CipherTool can be used for creating encrypted value for given plaint text\n");
        System.out.println("Options :\n");

        System.out.println("\t-Dconfigure\t\t This option would allow user to secure plain text passwords in carbon configuration files." +
                           " CipherTool replace all " +
                           "the password listed in cipher-text.properties file with encrypted values " +
                           "and modify related password elements in the configuration files with secret alias names. " +
                           "Also secret-conf.properties file is modified with the default configuration data");

        System.out.println("\t-Dchange\t\t This option would allow user to change the specific password " +
                           "which has been secured\n");

        System.out.println("\t-Dpassword=<password>\t This option would allow user to provide the password as a command line " +
                           "argument. NOTE: Providing the password in command line arguments list is not recommended.\n");
    }

    /**
     * init the Cipher for encryption using the primary key store of carbon server
     *
     * @return cipher
     */
    private static Cipher initCipher() {

        String keyStoreFile = null;
        String keyType = null;
        String aliasName = null;
        String password = null;
        String provider = null;
        Cipher cipher = null;

        keyStoreFile = getPrimaryKeyStoreData(CipherToolConstants.PrimaryKeyStore
                                                      .PRIMARY_KEY_LOCATION);
        keyStoreFile = carbonHome + keyStoreFile.substring((keyStoreFile
                                                                    .indexOf('}')) + 1);

        File keyStore = new File(keyStoreFile);

        if (!keyStore.exists()) {
            handleException("Primary Key Store Can not be found at Default location");
        }
        keyType = getPrimaryKeyStoreData(CipherToolConstants.PrimaryKeyStore
                                                 .PRIMARY_KEY_TYPE);
        aliasName = getPrimaryKeyStoreData(CipherToolConstants.PrimaryKeyStore
                                                   .PRIMARY_KEY_ALIAS);
        if (System.getProperty("password") != null && System.getProperty("password").toString().length() > 0) {
            password = System.getProperty("password");
        } else {
            password = carbonKeyPasswordReader();
        }

        try {
            KeyStore primaryKeyStore = getKeyStore(keyStoreFile, password, keyType, provider);
            java.security.cert.Certificate certs = primaryKeyStore.getCertificate(aliasName);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, certs);
        } catch (InvalidKeyException e) {
            handleException("Error initializing Cipher ", e);
        } catch (NoSuchAlgorithmException e) {
            handleException("Error initializing Cipher ", e);
        } catch (KeyStoreException e) {
            handleException("Error initializing Cipher ", e);
        } catch (NoSuchPaddingException e) {
            handleException("Error initializing Cipher ", e);
        }

        System.out.println("\nPrimary KeyStore of Carbon Server is initialized Successfully\n");

        return cipher;
    }

    /**
     * encrypt the plain text password
     *
     * @param cipher        init cipher
     * @param plainTextPass plain text password
     * @return encrypted password
     */
    private static String doEncryption(Cipher cipher, String plainTextPass) {
        String encodedValue = null;
        try {
            byte[] plainTextPassByte = plainTextPass.getBytes();
            byte[] encryptedPassword = cipher.doFinal(plainTextPassByte);
            BASE64Encoder  encoder  = new BASE64Encoder();
            encodedValue = encoder.encode(encryptedPassword);
        } catch (BadPaddingException e) {
            handleException("Error encrypting password ", e);
        } catch (IllegalBlockSizeException e) {
            handleException("Error encrypting password ", e);
        }
         System.out.println("\nEncryption is done Successfully\n");
        return encodedValue;
    }

    /**
     * Print encrypted value for given plain text
     */
    private static void createEncryptedValue() {

         System.out.println("By default, CipherTool can be used for creating encrypted value for given plain text." +
                 " For more options visit help  ./ciphertool.sh -help or ./ciphertool.bat -help\n");
        Console console;
        char[] password;
        String firstPassword = null;
        String secondPassword = null;
        if ((console = System.console()) != null &&
            (password = console.readPassword("[%s]",
                                             "Enter Plain text value :")) != null) {
            firstPassword = String.valueOf(password);
        }

        if ((console = System.console()) != null &&
            (password = console.readPassword("[%s]",
                                             "Please Enter value Again :")) != null) {
            secondPassword = String.valueOf(password);
        }

        if (firstPassword != null && secondPassword != null && !firstPassword.equals("")
            && firstPassword.equals(secondPassword)) {
            String encryptedText = doEncryption(cipher, firstPassword);
            System.out.println("\nEncrypted value is : \n" + encryptedText + "\n");
        } else {
            handleException("Error : Password does not match");
        }


    }

    /**
     * get primary key store data by reading carbon.xml file
     *
     * @param xpath Xpath value for each entry
     * @return String value of data related to Xpath
     */
    private static String getPrimaryKeyStoreData(String xpath) {

        String nodeValue = null;
        try {
            String carbonConfigFile = carbonHome + File.separator +
                                      CipherToolConstants.REPOSITORY_DIR + File.separator + CipherToolConstants.CONF_DIR
                                      + File.separator + CipherToolConstants.CARBON_CONFIG_FILE;

            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document doc = docBuilder.parse(carbonConfigFile);

            XPathFactory xpf = XPathFactory.newInstance();
            XPath xp = xpf.newXPath();
            XPathExpression xpathEx = xp.compile(xpath);
            Node text = (Node) xpathEx.evaluate(doc.getDocumentElement(), XPathConstants.NODE);
            if (text != null) {
                nodeValue = text.getTextContent();
            }
        } catch (ParserConfigurationException e) {
            handleException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (SAXException e) {
            handleException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (XPathExpressionException e) {
            handleException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (IOException e) {
            handleException("IOError reading primary key Store details from carbon.xml file ", e);
        }
        return nodeValue;
    }

    /**
     * get the primary key store instant
     *
     * @param location      location of key store
     * @param storePassword password of key store
     * @param storeType     key store type
     * @param provider      key store provider
     * @return KeyStore instant
     */
    private static KeyStore getKeyStore(String location, String storePassword,
                                        String storeType,
                                        String provider) {

        File keyStoreFile = new File(location);
        if (!keyStoreFile.exists()) {
            handleException("KeyStore can not be found at ' " + keyStoreFile + " '");
        }
        if (storePassword == null) {
            handleException("KeyStore password can not be null");
        }
        if (storeType == null) {
            handleException("KeyStore Type can not be null");
        }
        BufferedInputStream bufferedInputStream = null;
        try {
            bufferedInputStream = new BufferedInputStream(new FileInputStream(keyStoreFile));
            KeyStore keyStore;
            if (provider != null) {
                keyStore = KeyStore.getInstance(storeType, provider);
            } else {
                keyStore = KeyStore.getInstance(storeType);
            }
            keyStore.load(bufferedInputStream, storePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (IOException e) {
            handleException("IOError loading keyStore from ' " + location + " ' ", e);
        } catch (NoSuchAlgorithmException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (CertificateException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (NoSuchProviderException e) {
            handleException("Error loading keyStore from ' " + location + " ' ", e);
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException ignored) {
                     System.err.println("Error while closing input stream");
                }
            }
        }
        return null;
    }

    /**
     * write the XML syntax to the configuration files, to show that the password is secured.
     */
    private static void writeSecureVaultConfigTokens() {

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

            writeTokenToConfigFile(fileName, XPath, key, capitalLetter);
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
    private static void writeTokenToConfigFile(String fileName, String xPath, String secretAlias,
                                               boolean capitalLetter) {



        if (xPath != null && !xPath.equals("") && secretAlias != null && !secretAlias.equals("")) {
            File configFile;
            try {
                String filePath = carbonHome + File.separator + CipherToolConstants.REPOSITORY_DIR
                                  + File.separator + CipherToolConstants.CONF_DIR + File.separator + fileName;

                configFile = new File(filePath);

                if (!configFile.exists()) {
                    filePath = carbonHome + fileName;
                    configFile = new File(filePath);
                }


                if (!configFile.exists()) {
                    filePath = carbonHome + File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                        CipherToolConstants.CONF_DIR + File.separator +
                        CipherToolConstants.SECURITY_DIR + File.separator + fileName;
                    configFile = new File(filePath);
                }


                if (!configFile.exists()) {
                    filePath = carbonHome + File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                            CipherToolConstants.CONF_DIR + File.separator +
                            CipherToolConstants.AXIS2_DIR + File.separator + fileName;
                    configFile = new File(filePath);
                }


                if (!configFile.exists()) {
                    filePath = carbonHome +  File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                            CipherToolConstants.CONF_DIR + File.separator +
                            CipherToolConstants.TOMCAT_DIR + File.separator + fileName;
                    configFile = new File(filePath);
                }


                if (!configFile.exists()) {
                    filePath = carbonHome +  File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                            CipherToolConstants.CONF_DIR + File.separator +
                            CipherToolConstants.ETC_DIR + File.separator + fileName;
                    configFile = new File(filePath);
                }

                if (!configFile.exists()) {
                    filePath = carbonHome +  File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                            CipherToolConstants.CONF_DIR + File.separator +
                            CipherToolConstants.DATA_SOURCE_DIRECTORY + File.separator + fileName;
                    configFile = new File(filePath);
                }

                if (!configFile.exists()) {
                    filePath = carbonHome +  File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                            CipherToolConstants.DEPLOYMENT_DIR + File.separator + CipherToolConstants.SERVER_DIR+
                            File.separator + CipherToolConstants.USERSTORE_DIR + File.separator + fileName;
                    configFile = new File(filePath);
                }

                if (!configFile.exists()) {
                    return;
                }

                DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                Document doc = docBuilder.parse(filePath);
                Node rootNode = doc.getDocumentElement();
                Node secretNamespaceNode = doc.createAttribute(CipherToolConstants.SECURE_VAULT_NS_PREFIX);
                secretNamespaceNode.setTextContent(CipherToolConstants.SECURE_VAULT_NS);
                rootNode.getAttributes().setNamedItem(secretNamespaceNode);
                Node secretProviderNode = doc.createAttribute(CipherToolConstants.SECURE_VAULT_ATTRIBUTE);
                secretProviderNode.setTextContent(CipherToolConstants.SECRET_PROVIDER);

                XPathFactory xpf = XPathFactory.newInstance();
                XPath xp = xpf.newXPath();
                XPathExpression xpathEx = xp.compile(xPath);
                NodeList securedNodes = (NodeList) xpathEx.evaluate(doc.getDocumentElement(),
                                                                            XPathConstants.NODESET);
                if (securedNodes != null && securedNodes.getLength() > 0) {
                    for(int i = 0; i< securedNodes.getLength(); i++){
                        Node secretAliasNode = doc.createAttribute(CipherToolConstants.SECURE_VAULT_ALIAS);
                        secretAliasNode.setTextContent(secretAlias);
                        Node node = securedNodes.item(i);
                        if(node != null){
                            node.setTextContent("password");
                            node.getAttributes().setNamedItem(secretAliasNode);
                        }
                    }
                } else {
                    handleException("Element for secret alias '" + secretAlias + "' can not be found in " +
                                    fileName + " file or You have entered invalid Xpath value");
                }
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                DOMSource source = new DOMSource(doc);
                StreamResult result = new StreamResult(new File(filePath));
                transformer.transform(source, result);

            } catch (ParserConfigurationException e) {
                handleException("Error writing protected token ["+ secretAlias +"] to " +
                        fileName + " file ", e);
            } catch (TransformerException e) {
                handleException("Error writing protected token ["+ secretAlias +"] to " +
                        fileName + " file ", e);
            } catch (SAXException e) {
                handleException("Error writing protected token  ["+ secretAlias +"] to " +
                        fileName + " file ", e);
            } catch (IOException e) {
                handleException("IOError writing protected token  ["+ secretAlias +"] to " +
                        fileName + " file ", e);
            } catch (XPathExpressionException e) {
                handleException("IOError writing protected token  ["+ secretAlias +"] to " +
                        fileName +" file ", e);
            }

             System.out.println("Protected Token [" +secretAlias +"] is updated in " + fileName +
                     " successfully\n");
        }
    }

    /**
     * Read password from command line inputs
     *
     * @param key secure alias of password
     * @return Password
     */
    private static String passwordReader(String key) {

        Console console;
        char[] password;
        String firstPassword = null;
        String secondPassword = null;
        if ((console = System.console()) != null &&
            (password = console.readPassword("[%s]",
                                 "Enter Password of Secret Alias - '" + key + "' :")) != null) {
            firstPassword = String.valueOf(password);
        }

        if ((console = System.console()) != null &&
            (password = console.readPassword("[%s]",
                                             "Please Enter Password Again :")) != null) {
            secondPassword = String.valueOf(password);
        }

        if (firstPassword != null && secondPassword != null && !firstPassword.equals("")
            && firstPassword.equals(secondPassword)) {
            return firstPassword;
        } else {
            return null;
        }
    }

    /**
     * Read primary key store password of carbon sever from command-line
     *
     * @return password
     */
    protected static String carbonKeyPasswordReader() {
        Console console;
        char[] password;
        if ((console = System.console()) != null &&
            (password = console.readPassword("[%s]",
                         "Please Enter Primary KeyStore Password of Carbon Server : ")) != null) {
            return String.valueOf(password);
        }
        return null;
    }

    /**
     * check whether the configuration file already has been secured
     *
     * @param firstNode     Root element of configuration file
     * @param capitalLetter element name is started with Capital letter or not
     * @return true of false
     */
    private static boolean isSecureVaultNodeExist(Node firstNode, boolean capitalLetter) {

        for (int i = 0; i < firstNode.getChildNodes().getLength(); i++) {
            if (capitalLetter) {
                if (firstNode.getChildNodes().item(i).getNodeName().equals(CipherToolConstants.
                                                                           SECURE_VAULT_CAPITAL)) {
                    return true;
                }
            } else {
                if (firstNode.getChildNodes().item(i).getNodeName().equals(CipherToolConstants.
                                                                           SECURE_VAULT_SIMPLE)) {
                    return true;
                }
            }

        }
        return false;
    }

    /**
     * create encrypted values for plain text password defined in cipher-text.properties file.. if not
     * read password from command-line
     */
    private static void createEncryptedValues() {

        for (String key : aliasPasswordMap.keySet()) {
            String value = aliasPasswordMap.get(key);
            if (value != null && !value.equals("")) {
                if (value.indexOf("[") >= 0 && value.indexOf("]") > 0) {
                    value = value.substring(value.indexOf("[") + 1, value.indexOf("]"));
                    aliasPasswordMap.put(key, doEncryption(cipher, value));
                }

            } else {
                value = passwordReader(key);
                if (value != null) {
                    aliasPasswordMap.put(key, doEncryption(cipher, value));
                } else {
                    handleException("Error : Password does not match");
                }
            }
        }
    }

    /**
     * write encrypted values to the cipher-text.properties
     */
    private static void writeEncryptedValues() {

        Properties properties = new Properties();
        for (String key : aliasPasswordMap.keySet()) {
            properties.setProperty(key, aliasPasswordMap.get(key));
        }
        writeProperties(properties, CipherToolConstants.CIPHER_PROPERTY_FILE);
    }

    /**
     * write default configurations (primary key store of carbon server is used) to the secret-config file
     */
    private static void writeConfigurations() {

        Properties properties = new Properties();

        String keyStoreFile = getPrimaryKeyStoreData(CipherToolConstants.PrimaryKeyStore
                                                             .PRIMARY_KEY_LOCATION);
        keyStoreFile = carbonHome + keyStoreFile.substring((keyStoreFile.indexOf('}')) + 1);
        String keyType = getPrimaryKeyStoreData(CipherToolConstants.PrimaryKeyStore
                                                        .PRIMARY_KEY_TYPE);
        String aliasName = getPrimaryKeyStoreData(CipherToolConstants.PrimaryKeyStore
                                                          .PRIMARY_KEY_ALIAS);

        properties.setProperty("carbon.secretProvider", CipherToolConstants.SECRET_PROVIDER);
        properties.setProperty("secretRepositories", "file");
        properties.setProperty("secretRepositories.file.provider",
                       "org.wso2.securevault.secret.repository.FileBaseSecretRepositoryProvider");
        properties.setProperty("secretRepositories.file.location", "repository" + File.separator +
                    "conf" + File.separator + "security" + File.separator +"cipher-text.properties");
        properties.setProperty("keystore.identity.location", keyStoreFile);
        properties.setProperty("keystore.identity.type", keyType);
        properties.setProperty("keystore.identity.alias", aliasName);
        properties.setProperty("keystore.identity.store.password", "identity.store.password");
        properties.setProperty("keystore.identity.store.secretProvider",
                CipherToolConstants.CARBON_DEFAULT_SECRET_PROVIDER);
        properties.setProperty("keystore.identity.key.password", "identity.key.password");
        properties.setProperty("keystore.identity.key.secretProvider",
                CipherToolConstants.CARBON_DEFAULT_SECRET_PROVIDER);

        writeProperties(properties, CipherToolConstants.SECRET_PROPERTY_FILE);

        System.out.println("\nSecret Configurations are written to the property file successfully\n");
    }


    /**
     * load xpath values for corresponding secret alias defined in the cipher-text.properties
     * Some of the Xpath value has been hard coded as constants
     */
    private static void loadXpathValuesAndPasswordDetails() {

        aliasXpathMap.put(CipherToolConstants.PasswordAlias.SSL_KEY,
                          CipherToolConstants.ProtectedPasswordXpath.SSL_KEY_PASSWORD);

        aliasXpathMap.put(CipherToolConstants.PasswordAlias.PRIMARY_PRIVATE_KEY,
                          CipherToolConstants.ProtectedPasswordXpath.PRIMARY_PRIVATE_KEY_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.PRIMARY_KEY_STORE,
                          CipherToolConstants.ProtectedPasswordXpath.PRIMARY_KEY_STORE_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.PRIMARY_TRUST_STORE,
                          CipherToolConstants.ProtectedPasswordXpath.PRIMARY_TRUST_STORE_PASSWORD);

        aliasXpathMap.put(CipherToolConstants.PasswordAlias.LISTENER_KEY,
                          CipherToolConstants.ProtectedPasswordXpath.LISTENER_KEY_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.LISTENER_TRUST_STORE,
                          CipherToolConstants.ProtectedPasswordXpath.LISTENER_TRUST_STORE_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.LISTENER_KEY_STORE,
                          CipherToolConstants.ProtectedPasswordXpath.LISTENER_KEY_STORE_PASSWORD);

        aliasXpathMap.put(CipherToolConstants.PasswordAlias.SENDER_KEY,
                          CipherToolConstants.ProtectedPasswordXpath.SENDER_KEY_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.SENDER_KEY_STORE,
                          CipherToolConstants.ProtectedPasswordXpath.SENDER_KEY_STORE_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.SENDER_TRUST_STORE,
                          CipherToolConstants.ProtectedPasswordXpath.SENDER_TRUST_STORE_PASSWORD);

        aliasXpathMap.put(CipherToolConstants.PasswordAlias.USER_DB,
                          CipherToolConstants.ProtectedPasswordXpath.USER_DB_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.USER_STORE_CONNECTION,
                          CipherToolConstants.ProtectedPasswordXpath.USER_STORE_CONNECTION_PASSWORD);
        aliasXpathMap.put(CipherToolConstants.PasswordAlias.ADMIN,
                          CipherToolConstants.ProtectedPasswordXpath.ADMIN_PASSWORD);

        aliasXpathMap.put(CipherToolConstants.PasswordAlias.SENDER_EMAIL,
                          CipherToolConstants.ProtectedPasswordXpath.SENDER_EMAIL_PASSWORD);

        Properties cipherToolProperties = loadProperties(CipherToolConstants.CIPHER_TOOL_PROPERTY_FILE);
        for (Object key : cipherToolProperties.keySet()) {
            String passwordAlias = (String) key;
            aliasXpathMap.put(passwordAlias, cipherToolProperties.getProperty(passwordAlias));
        }

        Properties cipherTextProperties = loadProperties(CipherToolConstants.CIPHER_PROPERTY_FILE);

        for (Object key : cipherTextProperties.keySet()) {
            String passwordAlias = (String) key;
            if (aliasXpathMap.containsKey(passwordAlias)) {
                String unprocessedXpath = aliasXpathMap.get(passwordAlias);
                configFileXpathMap.put(passwordAlias, unprocessedXpath);
                aliasPasswordMap.put(passwordAlias, cipherTextProperties.getProperty(passwordAlias));
            } else {
                System.out.println("XPath value for secret alias '" + passwordAlias + "' " +
                                            "can not be found " + "Please enter XPath manually : ");
                String buffer1 = null;
                String buffer2 = null;
                BufferedReader input1 = new BufferedReader(new InputStreamReader(System.in));
                try {
                    buffer1 = input1.readLine();
                } catch (IOException e) {
                    handleException("IOError reading command line inputs  ", e);
                }

                System.out.println("Please enter configuration file : ");
                BufferedReader input2 = new BufferedReader(new InputStreamReader(System.in));
                try {
                    buffer2 = input2.readLine();
                } catch (IOException e) {
                    handleException("IOError reading command line inputs  ", e);
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
     * use to change an specific password.
     */
    private static void changePassword() {
        Properties cipherTextProperties = loadProperties(CipherToolConstants.CIPHER_PROPERTY_FILE);
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

            String buffer = null;
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            try {
                buffer = input.readLine();
            } catch (IOException e) {
                handleException("IOError reading command line inputs  ", e);
            }

            if (buffer != null && !buffer.trim().equals("")) {
                String selectedPasswordAlias = keyValueList.get(Integer.parseInt(buffer.trim()) - 1);
                String value = passwordReader(selectedPasswordAlias);
                if (value != null) {
                    aliasPasswordMap.put(selectedPasswordAlias, doEncryption(cipher, value));
                } else {
                    handleException("Error : Password does not match");
                }

            } else {
                break;
            }
        }

        writeEncryptedValues();
        System.exit(0);
    }

    /**
     * read values from property file
     *
     * @param fileName file name
     * @return Properties
     */
    private static Properties loadProperties(String fileName) {
        Properties properties = new Properties();
        String filePath = carbonHome + File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                          CipherToolConstants.CONF_DIR + File.separator + CipherToolConstants.SECURITY_DIR +
                          File.separator + fileName;

        File dataSourceFile = new File(filePath);
        if (!dataSourceFile.exists()) {
            return properties;
        }

        InputStream in = null;
        try {
            in = new FileInputStream(dataSourceFile);
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
     * writes property values to file
     *
     * @param properties properties
     * @param fileName   FileName
     */
    private static void writeProperties(Properties properties, String fileName) {

        String filePath = carbonHome + File.separator + CipherToolConstants.REPOSITORY_DIR + File.separator +
                          CipherToolConstants.CONF_DIR + File.separator + CipherToolConstants.SECURITY_DIR +
                          File.separator + fileName;

        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(filePath);
            properties.store(fileOutputStream, null);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at :" + filePath;
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


    protected static void handleException(String msg, Exception e) {
        throw new CipherToolException(msg, e);
    }

    protected static void handleException(String msg) {
        throw new CipherToolException(msg);
    }
}
