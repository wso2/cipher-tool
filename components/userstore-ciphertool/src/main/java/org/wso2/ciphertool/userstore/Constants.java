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
 * Constant definitions.
 */
public class Constants {

    public static final String OPTION_NAME_OPERATION = "operation";
    public static final String OPTION_NAME_CLEARTEXT = "cleartext";
    public static final String OPTION_NAME_KEYSTORE = "keystore";
    public static final String OPTION_NAME_KEYSTORE_TYPE = "keystore-type";
    public static final String OPTION_NAME_KEY_ALIAS = "key-alias";
    public static final String OPTION_NAME_KEYSTORE_PASSWORD = "keystore-password";
    public static final String OPTION_NAME_CRYPTO_ALGORITHM = "crypto-algorithm";
    public static final String OPTION_NAME_FILE_PATH = "file";
    public static final String OPTION_NAME_PASSWORD_PATTERN = "password-pattern";
    public static final String OPTION_NAME_REGEX_GROUP = "regex-group";
    public static final String OPTION_NAME_NEW_PASSWORD = "new-password";

    public static final String OPERATION_TYPE_ENCRYPT = "encrypt";
    public static final String OPERATION_TYPE_EXTRACT_PASSWORD = "extract-password";
    public static final String OPERATION_TYPE_REPLACE_PASSWORD = "replace-password";
}
