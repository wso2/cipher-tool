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

    public static final String UTF8 = "UTF-8";
    public static final String OS_NAME = "os.name";
    public static final String CONSOLE_PASSWORD_PARAM = "password";
    public static final String KEYSTORE_PASSWORD = "keystore.password";
    public static final String CONFIGURE = "configure";
    public static final String CHANGE = "change";
    public static final String ROTATE = "rotate";
    public static final String CARBON_HOME = "carbon.home";
    public static final String HOME_FOLDER = "home.folder";
    public static final String TRUE = "true";
    public static final String SYMMETRIC = "symmetric";
    public static final String KEY_BASED_SYMMETRIC_ENCRYPTION_MODE = "key.based.encryption";
    public static final String OLD_KEY_ALIAS = "old.alias";
    public static final String REPOSITORY_DIR = "repository";
    public static final String CONF_DIR = "conf";
    public static final String SECURITY_DIR = "security";
    public static final String RESOURCES_DIR = "resources";

    public static final String CARBON_CONFIG_FILE = "carbon.xml";
    public static final String CIPHER_TEXT_PROPERTY_FILE = "cipher-text.properties";
    public static final String CIPHER_TOOL_PROPERTY_FILE = "cipher-tool.properties";
    public static final String SECRET_PROPERTY_FILE = "secret-conf.properties";
    public static final String DEFAULT_JSON_FILE = "default.json";
    public static final String DEFAULT_JSON_DIR_PATH = "default.json.dir.path";
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

    public static final String PRIMARY_KEYSTORE_PROPERTY_MAP_NAME = "keystore.primary";
    public static final String INTERNAL_KEYSTORE_PROPERTY_MAP_NAME = "keystore.internal";
    public static final String KEYSTORE_PRIMARY_FILE_NAME = "keystore.primary.file_name";
    public static final String KEYSTORE_PRIMARY_TYPE = "keystore.primary.type";
    public static final String KEYSTORE_PRIMARY_ALIAS = "keystore.primary.alias";
    public static final String KEYSTORE_INTERNAL_TYPE = "keystore.internal.type";
    public static final String KEYSTORE_INTERNAL_ALIAS = "keystore.internal.alias";

    public static final String KEY_FILE_NAME = "file_name";
    public static final String KEY_TYPE = "type";
    public static final String KEY_ALIAS = "alias";

    public static final String SECRET_PROPERTY_MAP_NAME = "secrets";
    public static final String SECRETS_SECTION = "[secrets]";
    public static final String SECTION_PREFIX = "[";
    public static final String SECTION_SUFFIX = "]";
    public static final String KEY_VALUE_SEPERATOR = "=";
    public static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    public static final String AES = "AES";
    public static final String RSA = "RSA";
    public static final String CIPHERTEXT = "cipherText";
    public static final String IV = "iv";
    public static final String INTERNAL = "Internal";
    public static final String PRIMARY = "Primary";

    public static final String HEX_PATTERN = "^[0-9a-fA-F]+$";

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

    public static final class SecureVault {
        public static final String ENABLE_SEC_VAULT = "secVault.enabled";
        public static final String NS_PREFIX = "xmlns:svns";
        public static final String NS = "http://org.wso2.securevault/configuration";
        public static final String ATTRIBUTE = "provider";
        public static final String SECRET_PROVIDER_CLASS =
                "org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler";
        public static final String CARBON_DEFAULT_SECRET_PROVIDER =
                "org.wso2.carbon.securevault.DefaultSecretCallbackHandler";
        public static final String ENCRYPTION_SECRET_PROVIDER =
                "org.wso2.carbon.securevault.EncryptionKeyCallbackHandler";
        public static final String ALIAS = "svns:secretAlias";
        public static final String PASSWORD = "password";
        public static final String SECRET_REPOSITORIES = "secretRepositories";
        public static final String CARBON_SECRET_PROVIDER = "carbon.secretProvider";
        public static final String SECRET_FILE_PROVIDER = "secretRepositories.file.provider";
        public static final String SECRET_FILE_ALGORITHM= "secretRepositories.file.algorithm";
        public static final String SECRET_FILE_ENCRYPTION_MODE=
                "secretRepositories.file.encryptionMode";
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
        public static final String KEY_BASED_SYMMETRIC_ENCRYPTION = "key.based.symmetric.encryption";
        public static final String KEY_BASED_SECRET_PROVIDER = "key.based.secretProvider";
        public static final String KEY_BASED_PASSWORD = "key.based.password";
        public static final String ENCRYPTION_KEY_PASSWORD = "encryption.key.password";
    }

    public enum Error {

        GET_KEY_ERROR_MESSAGE("Error retrieving key associated with alias : %s"),
        CIPHER_INIT_ERROR_MESSAGE("Error initializing Cipher."),
        INVALID_SECRET_ERROR_MESSAGE("The provided secret key is invalid."),
        JSON_VALUE_NOT_FOUND("Value \"%s\" not found in JSON"),
        TOML_NOT_FOUND("Deployment file %s not found"),
        PARAMETER_REQUIRED_FOR_ROTATE_MODE("%s parameter is required for key rotate mode mode."),
        INVALID_JSON("Invalid encrypted text: JSON parsing failed."),
        EMPTY_ENCRYPTION_KEY("Encryption key cannot be empty"),
        UNSUPPORTED_TRANSFORMATION_FOR_KEY_BASED_ENCRYPTION("Key-based encryption is only supported " +
                "for AES transformations. Configured transformation: %s"),
        INVALID_AES_KEY_LENGTH("Invalid AES key length: %d bytes. AES-256 requires a 32-byte " +
                "(256-bit) key."),
        INVALID_HEX_CHARACTER("Invalid hexadecimal character found in encryption key at position %d"),
        OLD_ENCRYPTION_KEY_REQUIRED("Old encryption key is required for key-based rotation mode"),
        NEW_ENCRYPTION_KEY_EMPTY("New encryption key cannot be empty");

        private final String messageTemplate;

        Error(String messageTemplate) {
            this.messageTemplate = messageTemplate;
        }

        public String getMessage(Object... args) {
            return String.format(this.messageTemplate, args);
        }
    }

    public static final class EncryptionKeyPrompts {
        public static final String OLD_KEY_PROMPT = "Please enter the old encryption key for rotation : ";
        public static final String ROTATION_NEW_KEY_PROMPT = "Please enter the new encryption key for rotation : ";
        public static final String DEFAULT_PROMPT = "Please enter the encryption key : ";
    }
}
