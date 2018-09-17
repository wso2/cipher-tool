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

/**
 * The data structure which stored a ciphertext with context information.
 */
public class CipherHolder {

    private String c;
    private String t = "RSA";
    private String tp;
    private String tpd;

    public CipherHolder() {

    }

    public String getTransformation() {

        return this.t;
    }

    public void setTransformation(String transformation) {

        this.t = transformation;
    }

    public String getCipherText() {

        return this.c;
    }

    public byte[] getCipherBase64Decoded() {

        return Base64.decode(this.c);
    }

    public void setCipherText(String cipher) {

        this.c = cipher;
    }

    public String getThumbPrint() {

        return this.tp;
    }

    public void setThumbPrint(String tp) {

        this.tp = tp;
    }

    public String getThumbprintDigest() {

        return this.tpd;
    }

    public void setThumbprintDigest(String digest) {

        this.tpd = digest;
    }

    public void setCipherBase64Encoded(byte[] cipher) {

        this.c = Base64.encode(cipher);
    }

    public void setThumbPrint(String tp, String digest) {

        this.tp = tp;
        this.tpd = digest;
    }

    public String toString() {

        Gson gson = new Gson();
        return gson.toJson(this);
    }

}
