/**
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.ciphertool.utils;

public class Constants {

    public static final String OS_NAME = "os.name";
    public static final String KEYSTORE_PASSWORD = "keystore.password";
    public static final String CONFIGURE = "configure";
    public static final String CHANGE = "change";
    public static final String CARBON_HOME = "carbon.home";

    public static final String REPOSITORY_DIR = "repository";
    public static final String CONF_DIR = "conf";
    public static final String SECURITY_DIR = "security";
    public static final String AXIS2_DIR = "axis2";
    public static final String TOMCAT_DIR = "tomcat";
    public static final String ETC_DIR = "etc";
    public static final String DATA_SOURCE_DIRECTORY = "datasources";
    public static final String DEPLOYMENT_DIR = "deployment";
    public static final String SERVER_DIR = "server";
    public static final String USERSTORE_DIR = "userstores";

    public static final String CARBON_CONFIG_FILE = "carbon.xml";
    public static final String CIPHER_PROPERTY_FILE = "cipher-text.properties";
    public static final String CIPHER_TOOL_PROPERTY_FILE = "cipher-tool.properties";
    public static final String SECRET_PROPERTY_FILE = "secret-conf.properties";

    public static final class PrimaryKeyStore {
        public static final String PRIMARY_KEY_LOCATION_XPATH = "//Server/Security/KeyStore/Location";
        public static final String PRIMARY_KEY_TYPE_XPATH = "//Server/Security/KeyStore/Type";
        public static final String PRIMARY_KEY_ALIAS_XPATH = "//Server/Security/KeyStore/KeyAlias";
    }

    public static final class SecureVault {
        public static final String NS_PREFIX = "xmlns:svns";
        public static final String NS = "http://org.wso2.securevault/configuration";
        public static final String ATTRIBUTE = "provider";
        public static final String SECRET_PROVIDER_CLASS =
                "org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler";
        public static final String CARBON_DEFAULT_SECRET_PROVIDER =
                "org.wso2.carbon.securevault.DefaultSecretCallbackHandler";
        public static final String ALIAS = "svns:secretAlias";
        public static final String PASSWORD = "password";
        public static final String SECRET_REPOSITORIES = "secretRepositories";
        public static final String CARBON_SECRET_PROVIDER = "carbon.secretProvider";
        public static final String SECRET_FILE_PROVIDER = "secretRepositories.file.provider";
        public static final String SECRET_FILE_BASE_PROVIDER_CLASS =
                "org.wso2.securevault.secret.repository.FileBaseSecretRepositoryProvider";
        public static final String SECRET_FILE_LOCATION = "secretRepositories.file.location";
        public static final String KEYSTORE_LOCATION = "keystore.identity.location";
        public static final String KEYSTORE_TYPE = "keystore.identity.type";
        public static final String KEYSTORE_ALIAS = "keystore.identity.alias";
        public static final String KEYSTORE_STORE_PASSWORD = "keystore.identity.store.password";
        public static final String IDENTITY_STORE_PASSWORD = "identity.store.password";
        public static final String KEYSTORE_STORE_SECRET_PROVIDER = "keystore.identity.store.secretProvider";
        public static final String KEYSTORE_KEY_PASSWORD = "keystore.identity.key.password";
        public static final String IDENTITY_KEY_PASSWORD = "identity.key.password";
        public static final String KEYSTORE_KEY_SECRET_PROVIDER = "keystore.identity.key.secretProvider";
    }
}
