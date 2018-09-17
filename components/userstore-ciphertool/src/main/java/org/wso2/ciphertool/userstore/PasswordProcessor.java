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

import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The class which extracts and replaces passwords from files.
 */
public class PasswordProcessor {

    public String getPassword(String filePath, String passwordPattern, int regexGroup) throws Exception {

        try (InputStream fileInputStream = new FileInputStream(new File(filePath))) {

            String fileContent = IOUtils.toString(fileInputStream, "UTF-8");

            Pattern pattern = Pattern.compile(passwordPattern);
            Matcher matcher = pattern.matcher(fileContent);

            String password = null;
            while (matcher.find()) {
                password = matcher.group(regexGroup);
            }

            return password;
        }
    }

    public void replacePassword(String filePath, String passwordPattern, String newPassword) throws Exception {

        try (InputStream fileInputStream = new FileInputStream(new File(filePath))) {

            String fileContent = IOUtils.toString(fileInputStream, "UTF-8");
            Pattern pattern = Pattern.compile(passwordPattern);
            Matcher matcher = pattern.matcher(fileContent);

            while (matcher.find()) {
                fileContent = matcher.replaceFirst("$1" + newPassword + "$2");
            }

            IOUtils.write(fileContent, new FileOutputStream(new File(filePath)), "UTF-8");
        }
    }

}
