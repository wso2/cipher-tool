/**
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.ciphertool.utils;

public class Constants {
    public static final String CONSOLE_PASSWORD_PARAM = "password";
    public static final String KEYSTORE_PASSWORD = "keystore.password";
    public static final String CONFIGURE = "configure";
    public static final String CHANGE = "change";
    public static final String CARBON_HOME = "carbon.home";
    public static final String HOME_FOLDER = "home.folder";
    public static final String TRUE = "true";
    public static final String REPOSITORY_DIR = "repository";
    public static final String CONF_DIR = "conf";
    public static final String SECURITY_DIR = "security";
    public static final String RESOURCES_DIR = "resources";

    public static final String CARBON_CONFIG_FILE = "carbon.xml";
    public static final String CIPHER_TEXT_PROPERTY_FILE = "cipher-text.properties";
    public static final String CIPHER_TOOL_PROPERTY_FILE = "cipher-tool.properties";
    public static final String SECRET_PROPERTY_FILE = "secret-conf.properties";
    public static final String DEPLOYMENT_TOML_FILE = "deployment.toml";
    public static final String DEPLOYMENT_CONFIG_FILE_PATH = "deployment.config.file.path";
    public static final String CARBON_CONFIG_DIR_PATH = "carbon.config.dir.path";

    public static final String CIPHER_TEXT_PROPERTY_FILE_PROPERTY = "cipher.text.properties.file";
    public static final String CIPHER_TOOL_PROPERTY_FILE_PROPERTY = "cipher.tool.properties.file";
    public static final String CIPHER_STANDALONE_CONFIG_PROPERTY_FILE = "cipher-standalone-config.properties";
    public static final String SECRET_PROPERTY_FILE_PROPERTY = "secret.conf.properties.file";
    public static final String CIPHER_TRANSFORMATION_SYSTEM_PROPERTY = "org.wso2.CipherTransformation";

    public static final String KEY_LOCATION_PROPERTY = "primary.key.location";
    public static final String KEY_TYPE_PROPERTY = "primary.key.type";
    public static final String KEY_ALIAS_PROPERTY = "primary.key.alias";

    public static final String SECRET_PROPERTY_MAP_NAME = "secrets";
    public static final String SECRETS_SECTION = "[secrets]";
    public static final String SECTION_PREFIX = "[";
    public static final String SECTION_SUFFIX = "]";
    public static final String KEY_VALUE_SEPERATOR = "=";
    // This property will be set to true when external applications need to override the default values
    public static final String SET_EXTERNAL_SYSTEM_PROPERTY = "external.system.properties";

    public static final String SYS_PROPERTY_PLACEHOLDER_PREFIX = "$sys{"; 
    public static final String ENV_VAR_PLACEHOLDER_PREFIX = "$env{"; 
    public static final String PLACEHOLDER_SUFFIX = "}";

    public static final class PrimaryKeyStore {
        public static final String KEY_LOCATION_XPATH = "//Server/Security/KeyStore/Location";
        public static final String KEY_TYPE_XPATH = "//Server/Security/KeyStore/Type";
        public static final String KEY_ALIAS_XPATH = "//Server/Security/KeyStore/KeyAlias";
    }

    public static final class InternalKeyStore {
        public static final String KEY_LOCATION_XPATH = "//Server/Security/InternalKeyStore/Location";
        public static final String KEY_TYPE_XPATH = "//Server/Security/InternalKeyStore/Type";
        public static final String KEY_ALIAS_XPATH = "//Server/Security/InternalKeyStore/KeyAlias";
    }

    public static final class JCEProviders {
        public static final String SECURITY_JCE_PROVIDER = "security.jce.provider";
        public static final String JCE_PROVIDER = "jce.provider";
        public static final String KEYSTORE_KEY = "keystore.primary";
        public static final String BOUNCY_CASTLE_PROVIDER = "BC";
        public static final String BOUNCY_CASTLE_FIPS_PROVIDER = "BCFIPS";
        public static final String BC_FIPS_CLASS_NAME = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
        public static final String BC_CLASS_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";
        public static final String FIPS_APPROVED_ONLY = "org.bouncycastle.fips.approved_only";
    }

    public static final class SecureVault {
        public static final String ENABLE_SEC_VAULT = "secVault.enabled";
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
        public static final String SECRET_FILE_ALGORITHM= "secretRepositories.file.algorithm";
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
