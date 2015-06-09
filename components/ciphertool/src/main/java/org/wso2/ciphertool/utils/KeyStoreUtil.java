/**
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreUtil {

    public static Cipher initializeCipher() {

        Cipher cipher;
        String carbonHome = System.getProperty(Constants.CARBON_HOME);
        String carbonConfigFile = carbonHome + File.separator + Constants.REPOSITORY_DIR + File.separator
                                  + Constants.CONF_DIR + File.separator + Constants.CARBON_CONFIG_FILE;
        String keyStoreFile, keyType, aliasName;

        try {
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document document = docBuilder.parse(carbonConfigFile);

            keyStoreFile = getPrimaryKeyInfo(document.getDocumentElement(),
                                             Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_XPATH);
            keyStoreFile = carbonHome + keyStoreFile.substring((keyStoreFile.indexOf('}')) + 1);
            System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_LOCATION_XPATH, keyStoreFile);
            File keyStore = new File(keyStoreFile);
            if (!keyStore.exists()) {
                throw new CipherToolException("Primary Key Store Can not be found at Default location");
            }

            keyType = getPrimaryKeyInfo(document.getDocumentElement(),
                                        Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_XPATH);
            System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_TYPE_XPATH, keyType);
            if (keyType == null) {
                throw new CipherToolException("KeyStore Type can not be null");
            }

            aliasName = getPrimaryKeyInfo(document.getDocumentElement(),
                                          Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_XPATH);
            System.setProperty(Constants.PrimaryKeyStore.PRIMARY_KEY_ALIAS_XPATH, aliasName);
        } catch (ParserConfigurationException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (SAXException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        } catch (IOException e) {
            throw new CipherToolException("Error reading primary key Store details from carbon.xml file ", e);
        }

        String password;
        if (System.getProperty(Constants.KEYSTORE_PASSWORD) != null &&
            System.getProperty(Constants.KEYSTORE_PASSWORD).length() > 0) {
            password = System.getProperty(Constants.KEYSTORE_PASSWORD);
        } else {
            password = Utils.getValueFromConsole("Please Enter Primary KeyStore Password of Carbon Server : ");
        }
        password = "wso2carbon"; //ToDo : This is for testing
        if (password == null) {
            throw new CipherToolException("KeyStore password can not be null");
        }

        KeyStore primaryKeyStore = getKeyStore(keyStoreFile, password, keyType);
        try {
            Certificate certs = primaryKeyStore.getCertificate(aliasName);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, certs);
        } catch (KeyStoreException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        } catch (NoSuchPaddingException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        } catch (InvalidKeyException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        }

        System.out.println("\nPrimary KeyStore of Carbon Server is initialized Successfully\n");
        return cipher;
    }

    private static String getPrimaryKeyInfo(Element element, String xPath) {

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

    private static KeyStore getKeyStore(String location, String storePassword, String storeType) {
        BufferedInputStream bufferedInputStream = null;
        try {
            bufferedInputStream = new BufferedInputStream(new FileInputStream(location));
            KeyStore keyStore = KeyStore.getInstance(storeType);
            keyStore.load(bufferedInputStream, storePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (IOException e) {
            throw new CipherToolException("IOError loading keyStore from ' " + location + " ' ", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (CertificateException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException ignored) {
                    System.err.println("Error while closing input stream");
                }
            }
        }
    }
}
