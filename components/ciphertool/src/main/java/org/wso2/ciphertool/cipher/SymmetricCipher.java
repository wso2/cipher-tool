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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.wso2.ciphertool.exception.CipherToolException;
import org.wso2.ciphertool.utils.Constants;
import org.wso2.ciphertool.utils.KeyStoreUtil;
import org.wso2.ciphertool.utils.Utils;

import java.nio.charset.StandardCharsets;
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

/**
 * Provides methods for encryption and decryption using symmetric key algorithms.
 */
public class SymmetricCipher implements CipherMode {

    private static final int GCM_IV_LENGTH = 128;
    private static final int GCM_TAG_LENGTH = 128;
    private final Key secretKey;
    private final Cipher cipher;
    private final String algorithm;

    public SymmetricCipher(KeyStore keyStore, String keyAlias) {

        String cipherTransformation = System.getProperty(Constants.CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        this.algorithm = StringUtils.isNotBlank(cipherTransformation)
                ? cipherTransformation : Constants.AES_GCM_NO_PADDING;
        String password = KeyStoreUtil.getKeystorePassword();
        try {
            this.secretKey = keyStore.getKey(keyAlias, password.toCharArray());
            if (this.secretKey == null) {
                throw new KeyStoreException(Constants.Error.GET_KEY_ERROR_MESSAGE + keyAlias);
            }
            this.cipher = Cipher.getInstance(this.algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CipherToolException(Constants.Error.CIPHER_INIT_ERROR_MESSAGE.getMessage(), e);
        } catch (KeyStoreException | UnrecoverableKeyException e) {
            throw new CipherToolException(Constants.Error.GET_KEY_ERROR_MESSAGE + keyAlias, e);
        }
    }

    public SymmetricCipher(KeyStore keyStore) {

        this(keyStore, System.getProperty(Constants.KEY_ALIAS_PROPERTY));
    }

    /**
     * Encrypt plain text using encryption.
     *
     * @param plainText Plain text password.
     * @return Encrypted password.
     */
    @Override
    public String doEncryption(String plainText) {

        try {
            if (Constants.AES_GCM_NO_PADDING.equals(this.algorithm)) {
                byte[] iv = getInitializationVector();
                cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
                String cipherText = Utils.doEncryption(cipher, plainText);
                return createSelfContainedCiphertextWithGCMMode(cipherText, iv);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
                return Utils.doEncryption(cipher, plainText);
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new CipherToolException(Constants.Error.CIPHER_INIT_ERROR_MESSAGE.getMessage(), e);
        }  catch (InvalidKeyException e) {
            throw new CipherToolException(Constants.Error.INVALID_SECRET_ERROR_MESSAGE.getMessage(), e);
        }
    }

    /**
     * Decrypt encrypted text using encryption.
     *
     * @param cipherText Encrypted password.
     * @return Plain text password.
     */
    @Override
    public String doDecryption(String cipherText) {

        try {
            byte[] encryptedText;
            if (Constants.AES_GCM_NO_PADDING.equals(this.algorithm)) {
                JsonObject jsonObject = getJsonObject(cipherText);
                encryptedText = getValueFromJson(jsonObject, Constants.CIPHERTEXT);
                byte[] iv = getValueFromJson(jsonObject, Constants.IV);
                cipher.init(Cipher.DECRYPT_MODE, this.secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
                encryptedText = Base64.getDecoder().decode(cipherText.getBytes(StandardCharsets.UTF_8));
            }
            return Utils.doDecryption(cipher, encryptedText);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CipherToolException(Constants.Error.CIPHER_INIT_ERROR_MESSAGE.getMessage(), e);
        }  catch (InvalidKeyException e) {
            throw new CipherToolException(Constants.Error.INVALID_SECRET_ERROR_MESSAGE.getMessage(), e);
        }
    }

    private JsonObject getJsonObject(String encryptedText) {

        try {
            String jsonString = new String(Base64.getDecoder().decode(encryptedText));
            return JsonParser.parseString(jsonString).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            throw new CipherToolException(Constants.Error.INVALID_JSON.getMessage());
        }
    }

    private byte[] getValueFromJson(JsonObject jsonObject, String value) {

        JsonElement jsonElement = jsonObject.get(value);
        if (jsonElement == null) {
            throw new CipherToolException(Constants.Error.JSON_VALUE_NOT_FOUND.getMessage(value));
        }
        return Base64.getDecoder().decode(jsonElement.getAsString().getBytes(StandardCharsets.UTF_8));
    }

    private byte[] getInitializationVector() {

        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }


    private String createSelfContainedCiphertextWithGCMMode(String originalCipher, byte[] iv) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty(Constants.CIPHERTEXT, originalCipher);
        jsonObject.addProperty(Constants.IV, Base64.getEncoder().encodeToString(iv));
        return Base64.getEncoder().encodeToString(new Gson().toJson(jsonObject).getBytes());
    }
}
