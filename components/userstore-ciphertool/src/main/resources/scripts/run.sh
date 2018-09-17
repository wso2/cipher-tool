# Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
#
# WSO2 Inc. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.


#NOTE : Set the following variables first.

#PRODUCT_HOME="<ABSOLUTE_PATH_OF_PRODUCT_HOME>"
#CRYPTO_TOOL_HOME="<ABSOLUTE_PATH_OF_CRYPTO_TOOL_HOME>"
#USERSTORE_FILE="$PRODUCT_HOME/<PATH_OF_SECONDARY_USER_STORE_FILE>"
#KEYSTORE_FILE="$PRODUCT_HOME/<PATH_OF_KEYSTORE_FILE>"
#KEY_ALIAS=<KEY_ALIAS>
#KEYSTORE_PASSWORD=<KEYSTORE_PASSWORD>

# Get the plain-text password from configuration file (user store conf) using the Java client

CLEARTEXT="$($CRYPTO_TOOL_HOME/bin/crypto-tool \
--operation extract-password \
--file $USERSTORE_FILE \
--password-pattern "<Property encrypted=\"true\" name=\"password\">(.*)</Property>" \
--regex-group 1)"

echo $CLEARTEXT

# Encrypt the password using the Java client

CIPHERTEXT="$($CRYPTO_TOOL_HOME/bin/crypto-tool \
--operation encrypt \
--keystore $KEYSTORE_FILE \
--keystore-type JKS \
--key-alias $KEY_ALIAS \
--keystore-password $KEYSTORE_PASSWORD \
--crypto-algorithm RSA/ECB/OAEPwithSHA1andMGF1Padding \
--cleartext $CLEARTEXT)"

echo $CIPHERTEXT

# Replace the password using the Java client

$CRYPTO_TOOL_HOME/bin/crypto-tool \
--operation replace-password \
--file $USERSTORE_FILE \
--password-pattern "(<Property encrypted=\"true\" name=\"password\">).*(</Property>)" \
--new-password $CIPHERTEXT

# (Optional) Replace the password using sed
# sed -i -e "s/$CLEARTEXT/$CIPHERTEXT/g" $USERSTORE_FILE
