/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.ciphertool;

/**
 * Keeps the constant values related to cipher tool
 */
public class CipherToolConstants {

    public static final String SECURE_VAULT_NS = "http://org.wso2.securevault/configuration";
    public static final String SECURE_VAULT_CAPITAL = "svns:SecureVault";
    public static final String SECURE_VAULT_SIMPLE = "svns:secureVault";
    public static final String SECURE_VAULT_NS_PREFIX = "xmlns:svns";
    public static final String SECURE_VAULT_ATTRIBUTE = "provider";
    public static final String SECURE_VAULT_ALIAS= "svns:secretAlias";    
    public static final String SECRET_PROVIDER = "org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler";
    public static final String CARBON_DEFAULT_SECRET_PROVIDER = "org.wso2.carbon.securevault.DefaultSecretCallbackHandler";
    public static final String CONF_DIR = "conf";
    public static final String SECURITY_DIR = "security";
    public static final String ETC_DIR = "etc";
    public static final String AXIS2_DIR = "axis2";
    public static final String TOMCAT_DIR = "tomcat";
    public static final String REPOSITORY_DIR = "repository";
    public static final String DATA_SOURCE_DIRECTORY = "datasources";
    public static final String DEPLOYMENT_DIR = "deployment";
    public static final String SERVER_DIR = "server";
    public static final String USERSTORE_DIR = "userstores";


    public static final String CARBON_CONFIG_FILE = "carbon.xml";
    public static final String CIPHER_PROPERTY_FILE = "cipher-text.properties";
    public static final String CIPHER_TOOL_PROPERTY_FILE = "cipher-tool.properties";
    public static final String SECRET_PROPERTY_FILE = "secret-conf.properties";

    public static final class PrimaryKeyStore {

        public static final String PRIMARY_KEY_LOCATION = "//Server/Security/RegistryKeyStore/" +
                "Location";
        public static final String PRIMARY_KEY_TYPE = "//Server/Security/RegistryKeyStore/Type";
        public static final String PRIMARY_KEY_ALIAS = "//Server/Security/RegistryKeyStore/" +
                "KeyAlias";
        
    }


    public static final class ProtectedPasswordXpath {
         // these xpaths are moved to cipher-tool.properties file.
        public static final String SSL_KEY_PASSWORD = "mgt-transports.xml//transports/transport[@name=" +
                                                      "'https']/parameter[@name='keystorePass'],false";
        public static final String ADMIN_PASSWORD = "user-mgt.xml//UserManager/Realm/Configuration/" +
                "AdminUser/Password,true";
        public static final String USER_DB_PASSWORD = "user-mgt.xml//UserManager/Realm/Configuration/" +
                "Property[@name='password'],true";
        public static final String LISTENER_TRUST_STORE_PASSWORD = "axis2.xml//axisconfig/transportReceiver" +
                "[@name='https']/parameter[@name='truststore']/TrustStore/Password,false";
        public static final String LISTENER_KEY_STORE_PASSWORD = "axis2.xml//axisconfig/transportReceiver" +
                "[@name='https']/parameter[@name='keystore']/KeyStore/Password,false";
        public static final String LISTENER_KEY_PASSWORD = "axis2.xml//axisconfig/transportReceiver" +
                "[@name='https']/parameter[@name='keystore']/KeyStore/KeyPassword,false";

        public static final String SENDER_TRUST_STORE_PASSWORD = "axis2.xml//axisconfig/transportSender" +
                "[@name='https']/parameter[@name='truststore']/TrustStore/Password,false";
        public static final String SENDER_KEY_STORE_PASSWORD = "axis2.xml//axisconfig/transportSender" +
                "[@name='https']/parameter[@name='keystore']/KeyStore/Password,false";
        public static final String SENDER_KEY_PASSWORD =  "axis2.xml//axisconfig/transportSender" +
                "[@name='https']/parameter[@name='keystore']/KeyStore/KeyPassword,false";
        public static final String REGISTRY_DB_PASSWORD = "";
        public static final String USER_STORE_CONNECTION_PASSWORD = "user-mgt.xml//UserManager/Realm/" +
                "UserStoreManager/Property[@name='ConnectionPassword'],true";
        public static final String SENDER_EMAIL_PASSWORD = "axis2.xml//axisconfig/transportSender" +
                "[@name='mailto']/parameter[@name='mail.smtp.password'],false";

        public static final String PRIMARY_KEY_STORE_PASSWORD = "carbon.xml//Server/Security/KeyStore" +
                "/Password,true";
        public static final String PRIMARY_PRIVATE_KEY_PASSWORD = "carbon.xml//Server/Security/KeyStore" +
                "/KeyPassword,true";
        public static final String PRIMARY_TRUST_STORE_PASSWORD = "carbon.xml//Server/Security/TrustStore" +
                "/Password,true";
        public static final String EVENT_BROKER_DELIVERY_MANAGER_PASSWORD = "event-broker.xml//eventBrokerConfig/eventBroker/deliveryManager/remoteMessageBroker" +
                "/Password,true";
    }

    public static final class PasswordAlias {
         // these aliases are moved to cipher-tool.properties file. The reason behind is that users should know aliases of these files to include in cipher-text.properties file.
        public static final String SSL_KEY = "transports.https.keystorePass";
        public static final String PRIMARY_KEY_STORE = "Carbon.Security.KeyStore.Password";
        public static final String PRIMARY_PRIVATE_KEY = "Carbon.Security.KeyStore.KeyPassword";
        public static final String PRIMARY_TRUST_STORE = "Carbon.Security.TrustStore.Password";
        public static final String ADMIN = "UserManager.AdminUser.Password";
        public static final String USER_DB = "UserManager.Configuration.Property.password";
        public static final String USER_STORE_CONNECTION = "UserStoreManager.Property" +
                ".ConnectionPassword";

        public static final String LISTENER_TRUST_STORE = "Axis2.Https.Listener.TrustStore.Password";
        public static final String LISTENER_KEY_STORE = "Axis2.Https.Listener.KeyStore.Password" ;
        public static final String LISTENER_KEY = "Axis2.Https.Listener.KeyStore.KeyPassword" ;

        public static final String SENDER_TRUST_STORE = "Axis2.Https.Sender.TrustStore.Password";
        public static final String SENDER_KEY_STORE = "Axis2.Https.Sender.KeyStore.Password" ;
        public static final String SENDER_KEY = "Axis2.Https.Sender.KeyStore.KeyPassword" ;

        public static final String SENDER_EMAIL = "Axis2.Mailto.Parameter.Password";

        public static final String REGISTRY_DB = "";

        public static final String EVENT_BROKER_CONFIG = "eventBrokerConfig.eventBroker." +
                "                                   deliveryManager.remoteMessageBroker.password";


    }
}
