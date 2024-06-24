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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.lang3.StringUtils;
import org.wso2.ciphertool.exception.CipherToolException;
import org.wso2.ciphertool.utils.Constants;
import org.wso2.ciphertool.utils.KeyStoreUtil;
import org.wso2.ciphertool.utils.Utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

public class SymmetricCipher implements CipherMode {

    private static final int GCM_IV_LENGTH = 128;
    private static final int GCM_TAG_LENGTH = 128;
    private final Key secretKey;

    public SymmetricCipher() {

        String keyStoreName = ((Utils.isPrimaryKeyStore()) ? "Primary" : "Internal");
        String keyStoreFile = System.getProperty(Constants.KEY_LOCATION_PROPERTY);
        String keyType = System.getProperty(Constants.KEY_TYPE_PROPERTY);
        String password = StringUtils.isNotBlank(System.getProperty(Constants.KEYSTORE_PASSWORD))
                ? System.getProperty(Constants.KEYSTORE_PASSWORD)
                : Utils.getValueFromConsole("Please Enter " + keyStoreName + " KeyStore Password of Carbon Server : ", true);
        if (StringUtils.isBlank(password)) {
            throw new CipherToolException("KeyStore password can not be null");
        }
        KeyStore keyStore = KeyStoreUtil.getKeyStore(keyStoreFile, password, keyType);
        String keyAlias = System.getProperty(Constants.KEY_ALIAS_PROPERTY);
        try {
            this.secretKey = keyStore.getKey(keyAlias, password.toCharArray());
            if (this.secretKey == null) {
                throw new KeyStoreException("Error retrieving key associated with alias : " + keyAlias);
            }
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new CipherToolException("Error initializing Keystore ", e);
        } catch (UnrecoverableKeyException e) {
            throw new CipherToolException("Error retrieving key associated with alias : " + keyAlias, e);
        }
        System.out.println("\n" + keyStoreName + " KeyStore of Carbon Server is initialized Successfully\n");
    }

    /**
     * Encrypt plain text using symmetric encryption.
     *
     * @param plainText Plain text password.
     * @return Encrypted password.
     */
    @Override
    public String doEncryption(String plainText) {

        Cipher cipher;
        String cipherTransformation = System.getProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        cipherTransformation = StringUtils.isNotBlank(cipherTransformation)
                ? cipherTransformation : Constants.AES_GCM_NO_PADDING;
        try {
            cipher = Cipher.getInstance(cipherTransformation);
            if (Constants.AES_GCM_NO_PADDING.equals(cipherTransformation)) {
                byte[] iv = getInitializationVector();
                cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
                String cipherText = Utils.doEncryption(cipher, plainText);
                return createSelfContainedCiphertextWithGCMMode(cipherText, iv);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
                return Utils.doEncryption(cipher, plainText);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        }
    }

    private byte[] getInitializationVector() {

        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }


    private String createSelfContainedCiphertextWithGCMMode(String originalCipher, byte[] iv) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("cipherText", originalCipher);
        jsonObject.addProperty("iv", Base64.getEncoder().encodeToString(iv));
        return Base64.getEncoder().encodeToString(new Gson().toJson(jsonObject).getBytes());
    }
}
