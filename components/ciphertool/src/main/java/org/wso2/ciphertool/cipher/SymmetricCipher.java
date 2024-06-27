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
import org.wso2.ciphertool.utils.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCipher implements CipherMode {

    private static final int KDF_KEY_SIZE = 256;
    private static final int KDF_ITERATION_COUNT = 65536;
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int GCM_IV_LENGTH = 128;
    private static final int GCM_TAG_LENGTH = 128;
    private final SecretKeySpec secretKeySpec;

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
        if (!isPasswordValid(keyStoreFile, password, keyType)) {
            throw new CipherToolException("Invalid password or corrupted keystore.");
        }
        this.secretKeySpec = deriveKeyFromPassword(password, "AES".getBytes(StandardCharsets.UTF_8));
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
                cipher.init(Cipher.ENCRYPT_MODE, this.secretKeySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
                return doEncryptionWithGCMMode(cipher, plainText, iv);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, this.secretKeySpec);
                return Utils.doEncryption(cipher, plainText);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new CipherToolException("Error initializing Cipher ", e);
        }
    }

    private String doEncryptionWithGCMMode(Cipher cipher, String plaintext, byte[] iv) {

        byte[] cipherText;
        try {
            if (StringUtils.isBlank(plaintext)) {
                cipherText = StringUtils.EMPTY.getBytes();
            } else {
                cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            }
            return createSelfContainedCiphertextWithGCMMode(cipherText, iv);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            String errorMessage = String.format("Error encrypting with algorithm: '%s'.", Constants.AES_GCM_NO_PADDING);
            throw new CipherToolException(errorMessage, e);
        }
    }

    private byte[] getInitializationVector() {

        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }


    private String createSelfContainedCiphertextWithGCMMode(byte[] originalCipher, byte[] iv) {

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("cipherText", Base64.getEncoder().encodeToString(originalCipher));
        jsonObject.addProperty("iv", Base64.getEncoder().encodeToString(iv));
        return Base64.getEncoder().encodeToString(new Gson().toJson(jsonObject).getBytes());
    }

    private boolean isPasswordValid(String keystorePath, String storePassword, String storeType) {

        try (FileInputStream fileInputStream = new FileInputStream(keystorePath)) {
            KeyStore keystore = KeyStore.getInstance(storeType);
            keystore.load(fileInputStream, storePassword.toCharArray());
            return true;
        } catch (IOException e) {
            return false;
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new CipherToolException("Error loading keyStore from ' " + keystorePath + " ' ", e);
        }
    }

    private SecretKeySpec deriveKeyFromPassword(String password, byte[] salt) {

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATION_COUNT, KDF_KEY_SIZE);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CipherToolException("Error deriving key from password", e);
        }
    }
}
