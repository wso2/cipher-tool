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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_CLEARTEXT;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_CRYPTO_ALGORITHM;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_FILE_PATH;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_KEYSTORE;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_KEYSTORE_PASSWORD;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_KEYSTORE_TYPE;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_KEY_ALIAS;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_NEW_PASSWORD;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_PASSWORD_PATTERN;
import static org.wso2.ciphertool.userstore.Constants.OPTION_NAME_REGEX_GROUP;

/**
 * The tool which extracts, encrypts and replaces user store passwords.
 */
public class CryptoTool {

    public static void main(String[] args) {

        Options options = buildOptions();

        if (args.length == 0) {
            printHelpMessageAndExit(options);
        } else {
            processInput(args, options);
        }
    }

    private static void processInput(String[] args, Options options) {

        CommandLineParser parser = new DefaultParser();
        try {
            // parse the command line arguments
            CommandLine line = parser.parse(options, args);

            String operation = line.getOptionValue(Constants.OPTION_NAME_OPERATION);

            if (Constants.OPERATION_TYPE_ENCRYPT.equals(operation)) {
                String cipherText = encrypt(line);
                outputText(cipherText);
            } else if (Constants.OPERATION_TYPE_EXTRACT_PASSWORD.equals(operation)) {
                String password = extractPassword(line);
                outputText(password);
            } else if (Constants.OPERATION_TYPE_REPLACE_PASSWORD.equals(operation)) {
                replacePassword(line);
            } else {
                printErrorAndExit(String.format("'%s' is not a valid operation type", operation));
            }
        } catch (Exception e) {
            printErrorAndExit("An error occurred.", e);
        }
    }

    private static void replacePassword(CommandLine line) throws Exception {

        String filePath = line.getOptionValue(OPTION_NAME_FILE_PATH);
        failIfArgumentIsEmpty(filePath, OPTION_NAME_FILE_PATH);

        String passwordPattern = line.getOptionValue(OPTION_NAME_PASSWORD_PATTERN);
        failIfArgumentIsEmpty(passwordPattern, OPTION_NAME_PASSWORD_PATTERN);

        String newPassword = line.getOptionValue(OPTION_NAME_NEW_PASSWORD);
        failIfArgumentIsEmpty(newPassword, OPTION_NAME_NEW_PASSWORD);

        new PasswordProcessor().replacePassword(filePath, passwordPattern, newPassword);
    }

    private static String extractPassword(CommandLine line) throws Exception {

        String filePath = line.getOptionValue(OPTION_NAME_FILE_PATH);
        failIfArgumentIsEmpty(filePath, OPTION_NAME_FILE_PATH);

        String passwordPattern = line.getOptionValue(OPTION_NAME_PASSWORD_PATTERN);
        failIfArgumentIsEmpty(passwordPattern, OPTION_NAME_PASSWORD_PATTERN);

        String regexGroup = line.getOptionValue(OPTION_NAME_REGEX_GROUP);
        failIfArgumentIsEmpty(regexGroup, OPTION_NAME_REGEX_GROUP);
        int regexGroupNumber = Integer.parseInt(regexGroup);

        return new PasswordProcessor().getPassword(filePath, passwordPattern, regexGroupNumber);
    }

    private static String encrypt(CommandLine line) throws Exception {

        String cleartext = line.getOptionValue(OPTION_NAME_CLEARTEXT);
        failIfArgumentIsEmpty(cleartext, OPTION_NAME_CLEARTEXT);

        CryptoContext cryptoContext = new CryptoContext();

        String keyStorePath = line.getOptionValue(OPTION_NAME_KEYSTORE);
        failIfArgumentIsEmpty(keyStorePath, OPTION_NAME_KEYSTORE);
        cryptoContext.setKeyStorePath(keyStorePath);

        String keyStoreType = line.getOptionValue(OPTION_NAME_KEYSTORE_TYPE);
        failIfArgumentIsEmpty(keyStoreType, OPTION_NAME_KEYSTORE_TYPE);
        cryptoContext.setKeyStoreType(keyStoreType);

        String keyAlias = line.getOptionValue(OPTION_NAME_KEY_ALIAS);
        failIfArgumentIsEmpty(keyAlias, OPTION_NAME_KEY_ALIAS);
        cryptoContext.setKeyAlias(keyAlias);

        String keyStorePassword = line.getOptionValue(OPTION_NAME_KEYSTORE_PASSWORD);
        failIfArgumentIsEmpty(keyStorePassword, OPTION_NAME_KEYSTORE_PASSWORD);
        cryptoContext.setKeyStorePassword(keyStorePassword);

        String algorithm = line.getOptionValue(OPTION_NAME_CRYPTO_ALGORITHM);
        failIfArgumentIsEmpty(algorithm, OPTION_NAME_CRYPTO_ALGORITHM);
        cryptoContext.setAlgorithm(algorithm);

        String cipherText = new Encryptor().encrypt(cleartext, cryptoContext);
        return cipherText;
    }

    private static void failIfArgumentIsEmpty(String argument, String argumentName) {

        if (argument == null || argument.length() == 0) {
            throw new IllegalArgumentException(String.format("The argument '%s' can't be empty", argumentName));
        }
    }

    private static void printErrorAndExit(String errorMessage) {

        printErrorAndExit(errorMessage, null);

    }

    private static void outputText(String text) {

        System.out.println(text);
    }

    private static void printErrorAndExit(String errorMessage, Exception e) {

        System.err.println(errorMessage);

        if (e != null) {
            e.printStackTrace(System.err);
        }

        System.exit(1);
    }

    private static Options buildOptions() {

        Options options = new Options();

        Option operation = Option.builder()
                .longOpt(Constants.OPTION_NAME_OPERATION)
                .desc("Name of the operation. (encrypt, get-password)")
                .hasArg()
                .argName(Constants.OPTION_NAME_OPERATION).build();
        options.addOption(operation);

        Option cleartextOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_CLEARTEXT)
                .desc("Cleartext to be encrypted")
                .hasArg()
                .argName(Constants.OPTION_NAME_CLEARTEXT).build();
        options.addOption(cleartextOption);

        Option keyStoreFileOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_KEYSTORE)
                .desc("Path of the keystore")
                .hasArg()
                .argName(Constants.OPTION_NAME_KEYSTORE).build();
        options.addOption(keyStoreFileOption);

        Option keyStoreTypeOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_KEYSTORE_TYPE)
                .desc("Path of the keystore")
                .hasArg()
                .argName(Constants.OPTION_NAME_KEYSTORE_TYPE).build();
        options.addOption(keyStoreTypeOption);

        Option keyAliasOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_KEY_ALIAS)
                .desc("Alias of the key")
                .hasArg()
                .argName(Constants.OPTION_NAME_KEY_ALIAS).build();
        options.addOption(keyAliasOption);

        Option keyStorePasswordOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_KEYSTORE_PASSWORD)
                .desc("Password of the keystore")
                .hasArg()
                .argName(Constants.OPTION_NAME_KEYSTORE_PASSWORD).build();
        options.addOption(keyStorePasswordOption);

        Option cryptoAlgorithmOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_CRYPTO_ALGORITHM)
                .desc("Crypto algorithm")
                .hasArg()
                .argName(Constants.OPTION_NAME_CRYPTO_ALGORITHM).build();
        options.addOption(cryptoAlgorithmOption);

        Option filePathOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_FILE_PATH)
                .desc("File path to be extracted the password from.")
                .hasArg()
                .argName(Constants.OPTION_NAME_FILE_PATH).build();
        options.addOption(filePathOption);

        Option passwordPatternOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_PASSWORD_PATTERN)
                .desc("Pattern of the password in the given file.")
                .hasArg()
                .argName(Constants.OPTION_NAME_PASSWORD_PATTERN).build();
        options.addOption(passwordPatternOption);

        Option regexGroupOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_REGEX_GROUP)
                .desc("Regex group of the password")
                .hasArg()
                .argName(Constants.OPTION_NAME_REGEX_GROUP).build();
        options.addOption(regexGroupOption);

        Option newPasswordOption = Option.builder()
                .longOpt(Constants.OPTION_NAME_NEW_PASSWORD)
                .desc("New password (encrypted) to be replaced with.")
                .hasArg()
                .argName(Constants.OPTION_NAME_NEW_PASSWORD).build();
        options.addOption(newPasswordOption);

        return options;
    }

    private static void printHelpMessageAndExit(Options options) {

        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("Usage", options);
        System.exit(0);
    }

}
