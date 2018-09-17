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

/**
 * Context information which are needed for encrypting data.
 */
public class CryptoContext {

    private String keyStorePath;
    private String keyStoreType;
    private String keyAlias;
    private String keyStorePassword;
    private String algorithm;

    public void setKeyStorePath(String keyStorePath) {

        this.keyStorePath = keyStorePath;
    }

    public String getKeyStorePath() {

        return keyStorePath;
    }

    public void setKeyStoreType(String keyStoreType) {

        this.keyStoreType = keyStoreType;
    }

    public String getKeyStoreType() {

        return keyStoreType;
    }

    public void setKeyAlias(String keyAlias) {

        this.keyAlias = keyAlias;
    }

    public String getKeyAlias() {

        return keyAlias;
    }

    public void setKeyStorePassword(String keyStorePassword) {

        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyStorePassword() {

        return keyStorePassword;
    }

    public void setAlgorithm(String algorithm) {

        this.algorithm = algorithm;
    }

    public String getAlgorithm() {

        return algorithm;
    }

    @Override
    public String toString() {

        return "CryptoContext{" +
                "keyStorePath='" + keyStorePath + '\'' +
                ", keyStoreType='" + keyStoreType + '\'' +
                ", keyAlias='" + keyAlias + '\'' +
                ", keyStorePassword='" + keyStorePassword + '\'' +
                ", algorithm='" + algorithm + '\'' +
                '}';
    }
}
