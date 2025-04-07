/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;

import static org.wso2.carbon.CarbonConstants.ALLOW_ALL;
import static org.wso2.carbon.CarbonConstants.DEFAULT_AND_LOCALHOST;
import static org.wso2.carbon.CarbonConstants.HOST_NAME_VERIFIER;

/**
 * Util methods for HTTP Client.
 */
public class HTTPClientUtils {

    private static final String BOUNCY_CASTLE_JSSE_PROVIDER = "BCJSSE";

    public static final String SECURITY_KEYSTORE_LOCATION = "Security.KeyStore.Location";
    public static final String KEY_PASSWORD = "Security.KeyStore.KeyPassword";

    private HTTPClientUtils() {
        //disable external instantiation
    }

    /**
     * Create SSLContext needed to HttpClientBuilder with BCJSSE provider.
     *
     * @return SSLContext.
     */
    private static javax.net.ssl.SSLContext getSSLContext() throws GeneralSecurityException {
        ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();

        String keyStorePath = serverConfig.getFirstProperty(SECURITY_KEYSTORE_LOCATION);
        String keyStorePassword = serverConfig.getFirstProperty(KEY_PASSWORD);
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);

        char[] kspassphrase = keyStorePassword.toCharArray();

        javax.net.ssl.SSLContext sslContext;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            KeyStore keyStore = keyStoreManager.getPrimaryKeyStore();
            keyManagerFactory.init(keyStore, kspassphrase);

            sslContext = javax.net.ssl.SSLContext.getInstance("TLS", BOUNCY_CASTLE_JSSE_PROVIDER);
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        } catch (Exception e) {
            throw new GeneralSecurityException("Error when try to load keystore" + keyStorePath, e);
        }

        return sslContext;
    }

    /**
     * Get the httpclient builder with custom hostname verifier.
     *
     * @return HttpClientBuilder.
     */
    public static HttpClientBuilder createClientWithCustomVerifier() {

        HttpClientBuilder httpClientBuilder;
        try {
            httpClientBuilder = HttpClientBuilder.create()
                    .setSSLContext(getSSLContext())
                    .useSystemProperties();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        if (DEFAULT_AND_LOCALHOST.equals(System.getProperty(HOST_NAME_VERIFIER))) {
            X509HostnameVerifier hostnameVerifier = new CustomHostNameVerifier();
            httpClientBuilder.setHostnameVerifier(hostnameVerifier);
        } else if (ALLOW_ALL.equals(System.getProperty(HOST_NAME_VERIFIER))) {
            httpClientBuilder.setHostnameVerifier(new AllowAllHostnameVerifier());
        }

        return httpClientBuilder;
    }
}
