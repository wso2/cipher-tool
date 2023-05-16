/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.ciphertool.userstore;

import com.google.gson.Gson;
import org.apache.axiom.om.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;

/**
 * The class which encrypts data.
 */
public class Encryptor {

    private static final char[] HEX_CHARACTERS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    public static final String CRYPTO_PROVIDER_BC = "BC";
    private static final String DEFAULT_CRYPTO_ALGORITHM = "RSA";
    private static final String DIGEST_ALGORITHM = "SHA-256";

    public String encrypt(String cleartext, CryptoContext cryptoContext) throws Exception {

        Security.insertProviderAt(new BouncyCastleProvider(), 1);


        byte[] cleartextBytes = cleartext.getBytes("UTF-8");
        Cipher cipher;
        Certificate certificate;
        String cipherTransformation = cryptoContext.getAlgorithm();

        certificate = getCertificate(cryptoContext);
        if (cipherTransformation != null) {
            cipher = Cipher.getInstance(cipherTransformation, CRYPTO_PROVIDER_BC);
        } else {
            cipher = Cipher.getInstance(DEFAULT_CRYPTO_ALGORITHM, CRYPTO_PROVIDER_BC);
        }
        cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());

        byte[] cipherText = cipher.doFinal(cleartextBytes);

        if (cipherTransformation != null) {
            cipherText = createSelfContainedCiphertext(cipherText, cipherTransformation, certificate);
        }
        return Base64.encode(cipherText);
    }

    private byte[] createSelfContainedCiphertext(byte[] originalCipher, String transformation, Certificate certificate)
            throws CertificateEncodingException, NoSuchAlgorithmException {

        CipherHolder cipherHolder = new CipherHolder();
        cipherHolder.setCipherText(Base64.encode(originalCipher));
        cipherHolder.setTransformation(transformation);
        cipherHolder.setThumbPrint(calculateThumbprint(certificate, DIGEST_ALGORITHM), DIGEST_ALGORITHM);
        String cipherWithMetadataStr = new Gson().toJson(cipherHolder);

        return cipherWithMetadataStr.getBytes(Charset.defaultCharset());
    }

    private Certificate getCertificate(CryptoContext cryptoContext) throws
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        String filePath = cryptoContext.getKeyStorePath();
        String keyStoreType = cryptoContext.getKeyStoreType();
        String password = cryptoContext.getKeyStorePassword();
        String keyAlias = cryptoContext.getKeyAlias();

        KeyStore store;
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(new File(filePath).getAbsolutePath());
            store = KeyStore.getInstance(keyStoreType);
            store.load(inputStream, password.toCharArray());
            return store.getCertificateChain(keyAlias)[0];
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ignore) {
                }
            }
        }
    }

    private String calculateThumbprint(Certificate certificate, String digest)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        MessageDigest messageDigest = MessageDigest.getInstance(digest);
        messageDigest.update(certificate.getEncoded());
        byte[] digestByteArray = messageDigest.digest();
        StringBuffer strBuffer = new StringBuffer();

        for (int i = 0; i < digestByteArray.length; ++i) {
            int leftNibble = (digestByteArray[i] & 240) >> 4;
            int rightNibble = digestByteArray[i] & 15;
            strBuffer.append(HEX_CHARACTERS[leftNibble]).append(HEX_CHARACTERS[rightNibble]);
        }

        return strBuffer.toString();
    }
}
