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

package org.wso2.carbon.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class SSLContextUtils {
    private static final Logger LOG = LoggerFactory.getLogger(SSLContextUtils.class);

    public static final String SERVER_PRIMARY_KEYSTORE_FILE = "Security.KeyStore.Location";
    public static final String SERVER_PRIMARY_KEYSTORE_PASSWORD = "Security.KeyStore.Password";
    public static final String SERVER_PRIMARY_KEYSTORE_TYPE = "Security.KeyStore.Type";

    public static final String SECURITY_KEYSTORE_LOCATION = "Security.KeyStore.Location";
    public static final String KEY_PASSWORD = "Security.KeyStore.KeyPassword";

    /**
     * Create an SSLContext object by parsing the Keystore configured in carbon.xml file.
     *
     * @return SSLContext or null if creation failed.
     */
    public static SSLContext getSSLContext() {

        final ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();

        SSLContext sslContext = null;
        KeyManagerFactory keyManagerFactory;

        if (serverConfig != null) {
            String keyStorePath = serverConfig.getFirstProperty(SECURITY_KEYSTORE_LOCATION);
            String keyStorePassword = serverConfig.getFirstProperty(KEY_PASSWORD);

            char[] kspassphrase = keyStorePassword.toCharArray();

            try {
                // TODO - Replace with following when BouncyCastle is needed.
                //  Use addProvider instead of insertProviderAt.
//                sslContext = SSLContext.getInstance("TLS", "BCJSSE");
                sslContext = SSLContext.getDefault();

                keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                KeyStore keyStore = getPrimaryKeyStoreForSuperTenant();
                keyManagerFactory.init(keyStore, kspassphrase);
                sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            } catch (Exception e) {
                throw new RuntimeException("Error when try to load keystore" + keyStorePath, e);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Created SSL Context using keystore: {}", keyStorePath);
            }
        }
        return sslContext;
    }

    /**
     * Get the primary key store for the super tenant.
     *
     * @return primary key store object
     * @throws CarbonException Carbon Exception if any error occurs.
     */
    private static KeyStore getPrimaryKeyStoreForSuperTenant() throws CarbonException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Loading primary key store.");
        }

        try {
            ServerConfigurationService config = CarbonUtils.getServerConfiguration();
            String file = new File(config.getFirstProperty(SERVER_PRIMARY_KEYSTORE_FILE)).getAbsolutePath();
            KeyStore store = KeystoreUtils.getKeystoreInstance(config.getFirstProperty(SERVER_PRIMARY_KEYSTORE_TYPE));
            String password = config.getFirstProperty(SERVER_PRIMARY_KEYSTORE_PASSWORD);
            try (FileInputStream in = new FileInputStream(file)) {
                store.load(in, password.toCharArray());
            }
            return store;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException |
                 NoSuchProviderException e) {
            throw new CarbonException("Error while loading primary keystore", e);
        }
    }
}
