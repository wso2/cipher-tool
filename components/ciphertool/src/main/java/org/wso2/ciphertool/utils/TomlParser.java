/*
* Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.ciphertool.utils;

import net.consensys.cava.toml.Toml;
import net.consensys.cava.toml.TomlParseResult;
import net.consensys.cava.toml.TomlTable;
import org.apache.commons.lang.StringUtils;
import org.wso2.ciphertool.exception.CipherToolException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Parser class for reading and converting TOML configuration files into structured objects.
 */
public class TomlParser {
    private static final Logger log = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
    private TomlParseResult tomlContent;
    private TomlTable keystoreContent;
    private final boolean isExist;

    private String configFilePath;
    private final Map<String, String> secrets = new LinkedHashMap<>();

    public TomlParser() {
        configFilePath = System.getProperty(Constants.DEPLOYMENT_CONFIG_FILE_PATH);
        if (StringUtils.isEmpty(configFilePath)) {
            configFilePath = Paths.get(System.getProperty(Constants.CARBON_CONFIG_DIR_PATH),
                    Constants.DEPLOYMENT_TOML_FILE).toString();
        }
        isExist = new File(configFilePath).exists();
        loadTomlFile();
    }

    public boolean isFileExist() {
        return isExist;
    }

    public Map<String, String> getSecrets() {
        processSecrets();
        return secrets;
    }

    public String getKeyType() {
        if (keystoreContent == null) {
            getKeystoreContent();
        }
        if (keystoreContent != null && !keystoreContent.dottedKeySet().isEmpty()) {
            return keystoreContent.getString("type");
        }
        return null;
    }

    public String getKeyFile() {
        if (keystoreContent == null) {
            getKeystoreContent();
        }
        if (keystoreContent != null && !keystoreContent.dottedKeySet().isEmpty()) {
            return keystoreContent.getString("file_name");
        }
        return null;
    }

    public String getKeyAlias() {
        if (keystoreContent == null) {
            getKeystoreContent();
        }
        if (keystoreContent != null && !keystoreContent.dottedKeySet().isEmpty()) {
            return keystoreContent.getString("alias");
        }
        return null;
    }

    private void getKeystoreContent() {
       keystoreContent = tomlContent.getTable(Constants.JCEProviders.KEYSTORE_KEY);
    }

    private void loadTomlFile() {
        if (isExist) {
            try {
                tomlContent = Toml.parse(Paths.get(configFilePath));
                if (tomlContent.hasErrors()) {
                    StringBuilder errorMsg = new StringBuilder("Errors while parsing the toml file : ");
                    tomlContent.errors().forEach(err -> errorMsg.append(err.toString()).append(","));
                    throw new CipherToolException(errorMsg.toString());
                }
            } catch (IOException e) {
                throw new CipherToolException("Error while reading the toml file : " + configFilePath, e);
            }
        }
    }

    private void processSecrets() {
        TomlTable table = tomlContent.getTable(Constants.SECRET_PROPERTY_MAP_NAME);
        if (table != null) {
            table.dottedKeySet().forEach(key -> secrets.put(key, resolveVariable(table.getString(key))));
        }
    }

    private static String resolveVariable(String text) {
        String sysRefs = StringUtils.substringBetween(text, Constants.SYS_PROPERTY_PLACEHOLDER_PREFIX,
                Constants.PLACEHOLDER_SUFFIX);
        String envRefs = StringUtils.substringBetween(text, Constants.ENV_VAR_PLACEHOLDER_PREFIX,
                Constants.PLACEHOLDER_SUFFIX);

        // Resolves system property references ($sys{ref}) in an individual string.
        if (sysRefs != null) {
            String property = System.getProperty(sysRefs);
            if (StringUtils.isNotEmpty(property)) {
                text = text.replaceAll(Pattern.quote(Constants.SYS_PROPERTY_PLACEHOLDER_PREFIX + sysRefs +
                        Constants.PLACEHOLDER_SUFFIX), property);
            } else {
                log.warning("System property is not available for " + sysRefs);
            }
            return text;
        }

        if (envRefs != null) {
            String resolvedValue = System.getenv(envRefs);
            if (StringUtils.isNotEmpty(resolvedValue)) {
                text = text.replaceAll(Pattern.quote(Constants.ENV_VAR_PLACEHOLDER_PREFIX + envRefs +
                        Constants.PLACEHOLDER_SUFFIX), resolvedValue);
            } else {
                log.warning("Environment variable is not available for " + envRefs);
            }
            return text;
        }

        return text;
    }
}
