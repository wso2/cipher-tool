/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.ciphertool.cipher;

import org.apache.commons.lang.StringUtils;
import org.wso2.ciphertool.exception.CipherToolException;
import org.wso2.ciphertool.utils.Constants;
import org.wso2.ciphertool.utils.KeyStoreUtil;
import org.wso2.ciphertool.utils.Utils;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Provides methods for encryption and decryption using asymmetric key algorithms.
 */
public class AsymmetricCipher implements CipherMode {

    private final String keyAlias;
    private final KeyStore keyStore;
    private final Cipher cipher;
    private static final String CIPHER_INIT_ERROR_MESSAGE = "Error initializing Cipher.";
    private static final String GET_KEY_ERROR_MESSAGE = "Error retrieving key associated with alias : ";

    public AsymmetricCipher(KeyStore keyStore, String keyAlias) {

        this.keyStore = keyStore;
        this.keyAlias = keyAlias;
        String cipherTransformation = System.getProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        String algorithm = StringUtils.isNotBlank(cipherTransformation)
                ? cipherTransformation : Constants.RSA;
        try {
            this.cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CipherToolException(CIPHER_INIT_ERROR_MESSAGE, e);
        }
    }

    public AsymmetricCipher(KeyStore keyStore) {

        this(keyStore, System.getProperty(Constants.KEY_ALIAS_PROPERTY));
    }

    /**
     * Encrypt plain text using asymmetric encryption.
     *
     * @param plainText Plain text password.
     * @return Encrypted password.
     */
    @Override
    public String doEncryption(String plainText) {

        try {
            Certificate certs = this.keyStore.getCertificate(this.keyAlias);
            cipher.init(Cipher.ENCRYPT_MODE, certs);
        } catch (KeyStoreException e) {
            throw new CipherToolException(GET_KEY_ERROR_MESSAGE + this.keyAlias, e);
        } catch (InvalidKeyException e) {
            throw new CipherToolException("The provided public cert is invalid.", e);
        }
        return Utils.doEncryption(cipher, plainText);
    }

    @Override
    public String doDecryption(String cipherText) {

        try {
            Key privateKey = this.keyStore.getKey(this.keyAlias, KeyStoreUtil.getKeystorePassword().toCharArray());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        }  catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CipherToolException("The provided private key is invalid.", e);
        } catch (KeyStoreException | UnrecoverableKeyException e) {
            throw new CipherToolException(GET_KEY_ERROR_MESSAGE + this.keyAlias, e);
        }
        return Utils.doDecryption(cipher, Base64.getDecoder().decode(cipherText.getBytes(StandardCharsets.UTF_8)));
    }

}
