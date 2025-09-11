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

import org.apache.commons.lang3.StringUtils;
import org.wso2.ciphertool.exception.CipherToolException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreUtil {

    /**
     * Initializes the Cipher
     * @return cipher cipher
     */
    public static Cipher initializeCipher(String providerName) {
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
            password = Utils.getValueFromConsole("Please Enter " + keyStoreName +
                    " KeyStore Password of Carbon Server : ", true);
        }
        if (password == null) {
            throw new CipherToolException("KeyStore password can not be null");
        }

        KeyStore primaryKeyStore = getKeyStore(keyStoreFile, password, keyType, providerName);
        try {
            Certificate certs = primaryKeyStore.getCertificate(keyAlias);
            String cipherTransformation = System.getProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
            String provider = getPreferredJceProvider(providerName);
            if (cipherTransformation != null) {
                if (provider != null) {
                    cipher = Cipher.getInstance(cipherTransformation, provider);
                } else {
                    cipher = Cipher.getInstance(cipherTransformation);
                }
            } else {
                if (provider != null) {
                    cipher = Cipher.getInstance("RSA", provider);
                } else {
                    cipher = Cipher.getInstance("RSA");
                }
            }
            cipher.init(Cipher.ENCRYPT_MODE, certs);
        } catch (KeyStoreException e) {
            throw new CipherToolException("Failed to access the KeyStore while initializing the Cipher", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherToolException("Required cryptographic algorithm is not available in this environment", e);
        } catch (NoSuchPaddingException e) {
            throw new CipherToolException("Requested padding scheme is not available for the Cipher", e);
        } catch (InvalidKeyException e) {
            throw new CipherToolException("Invalid key was provided while initializing the Cipher", e);
        } catch (NoSuchProviderException e) {
            throw new CipherToolException("Specified security provider is not available in this environment", e);
        }

        System.out.println("\n" + keyStoreName + " KeyStore of Carbon Server is initialized Successfully\n");
        return cipher;
    }

    private static KeyStore getKeyStore(String location, String storePassword, String storeType, String providerName) {
        KeyStore keyStore;
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.
                newInputStream(Paths.get(location)))) {
            String provider = getPreferredJceProvider(providerName);
            if (provider != null) {
                keyStore = KeyStore.getInstance(storeType, provider);
            } else {
                keyStore = KeyStore.getInstance(storeType);
            }
            keyStore.load(bufferedInputStream, storePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            throw new CipherToolException(
                    "KeyStore type is not supported or not initialized properly while loading from '" +
                            location + "'", e);
        } catch (IOException e) {
            throw new CipherToolException(
                    "I/O error occurred while reading the KeyStore from '" + location + "'", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherToolException(
                    "Integrity check algorithm for the KeyStore is not available while loading from '" +
                            location + "'", e);
        } catch (CertificateException e) {
            throw new CipherToolException(
                    "One or more certificates in the KeyStore could not be loaded or parsed from '" +
                            location + "'", e);
        } catch (NoSuchProviderException e) {
            throw new CipherToolException("Specified security provider is not available in this environment", e);
        }
    }

    public static void addJceProvider(String providerName) {
        String jceProvider = getPreferredJceProvider(providerName);
        if (StringUtils.isNotEmpty(jceProvider)) {
            if (Constants.JCEProviders.BOUNCY_CASTLE_FIPS_PROVIDER.equals(jceProvider)) {
                insertJceProvider(Constants.JCEProviders.BC_FIPS_CLASS_NAME);
                System.setProperty(Constants.JCEProviders.FIPS_APPROVED_ONLY, "true");
            } else if (Constants.JCEProviders.BOUNCY_CASTLE_PROVIDER.equals(jceProvider)) {
                insertJceProvider(Constants.JCEProviders.BC_CLASS_NAME);
            }
        }
    }

    private static void insertJceProvider(String jceProviderClassName) {
        try {
            Security.insertProviderAt((Provider) Class.forName(jceProviderClassName).
                    getDeclaredConstructor().newInstance(), 1);
        } catch (InstantiationException e) {
            throw new RuntimeException("Failed to instantiate the class. Ensure it has " +
                    "a public no-argument constructor.", e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Illegal access while creating/using the class. " +
                    "Check visibility modifiers.", e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException("Constructor or method threw an exception during invocation.", e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("The expected method or constructor was not found. " +
                    "Verify method signatures.", e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("The specified class could not be found. Check the " +
                    "fully qualified class name.", e);
        }
    }

    /**
     * Get the preferred JCE provider.
     *
     * @return the preferred JCE provider
     */
    private static String getPreferredJceProvider(String provider) {
        if (provider != null && provider.equalsIgnoreCase(Constants.JCEProviders.BOUNCY_CASTLE_FIPS_PROVIDER)) {
            return Constants.JCEProviders.BOUNCY_CASTLE_FIPS_PROVIDER;
        } else if (provider != null && provider.equalsIgnoreCase(Constants.JCEProviders.BOUNCY_CASTLE_PROVIDER)) {
            return Constants.JCEProviders.BOUNCY_CASTLE_PROVIDER;
        }
        return null;
    }
}
