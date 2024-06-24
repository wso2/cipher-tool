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

import org.wso2.ciphertool.exception.CipherToolException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreUtil {

    /**
     * Initializes the Cipher
     * @return cipher cipher
     */
    public static Cipher initializeCipher() {
        Cipher cipher;
        String keyStoreName = ((Utils.isPrimaryKeyStore()) ? "Primary" : "Internal");
        String keyStoreFile = System.getProperty(Constants.KEY_LOCATION_PROPERTY);
        String keyType = System.getProperty(Constants.KEY_TYPE_PROPERTY);
        String keyAlias = System.getProperty(Constants.KEY_ALIAS_PROPERTY);
        String password;
        if (System.getProperty(Constants.KEYSTORE_PASSWORD) != null &&
            System.getProperty(Constants.KEYSTORE_PASSWORD).length() > 0) {
            password = System.getProperty(Constants.KEYSTORE_PASSWORD);
        } else {
            password = Utils.getValueFromConsole("Please Enter " + keyStoreName + " KeyStore Password of Carbon Server : ", true);
        }
        if (password == null) {
            throw new CipherToolException("KeyStore password can not be null");
        }

        KeyStore primaryKeyStore = getKeyStore(keyStoreFile, password, keyType);
        try {
            Certificate certs = primaryKeyStore.getCertificate(keyAlias);
            String cipherTransformation = System.getProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
            if (cipherTransformation != null) {
                cipher = Cipher.getInstance(cipherTransformation);
            } else {
                cipher = Cipher.getInstance("RSA");
            }
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

        System.out.println("\n" + keyStoreName + " KeyStore of Carbon Server is initialized Successfully\n");
        return cipher;
    }

    public static KeyStore getKeyStore(String location, String storePassword, String storeType) {
        BufferedInputStream bufferedInputStream = null;
        try {
            bufferedInputStream = new BufferedInputStream(new FileInputStream(location));
            KeyStore keyStore = KeyStore.getInstance(storeType);
            keyStore.load(bufferedInputStream, storePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (IOException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } catch (CertificateException e) {
            throw new CipherToolException("Error loading keyStore from ' " + location + " ' ", e);
        } finally {
            if (bufferedInputStream != null) {
                try {
                    bufferedInputStream.close();
                } catch (IOException e) {
                    System.err.println("Error while closing input stream");
                }
            }
        }
    }
}
