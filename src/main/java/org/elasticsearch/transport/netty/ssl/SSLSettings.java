/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

package org.elasticsearch.transport.netty.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.elasticsearch.common.settings.Settings;

public class SSLSettings {
    final public boolean enabled;
    final public String keyStoreFile;
    final public String keyStorePassword;
    final public String keyStoreAlgorithm;
    final public String trustStoreFile;
    final public String trustStorePassword;
    final public String trustStoreAlgorithm;

    public SSLSettings(Settings settings) {
        enabled = settings.getAsBoolean("network.ssl.enabled", false);
        keyStoreFile = settings.get("network.ssl.keystore.file", System.getProperty("javax.net.ssl.keyStore"));
        keyStorePassword = settings.get("network.ssl.keystore.password", System.getProperty("javax.net.ssl.keyStorePassword"));
        keyStoreAlgorithm = settings.get("network.ssl.keystore.algorithm", System.getProperty("ssl.KeyManagerFactory.algorithm", KeyManagerFactory.getDefaultAlgorithm()));
        trustStoreFile = settings.get("network.ssl.truststore.file", System.getProperty("javax.net.ssl.trustStore"));
        trustStorePassword = settings.get("network.ssl.truststore.password", System.getProperty("javax.net.ssl.trustStorePassword"));
        trustStoreAlgorithm = settings.get("network.ssl.truststore.algorithm", System.getProperty("ssl.TrustManagerFactory.algorithm", TrustManagerFactory.getDefaultAlgorithm()));
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public String getKeyStoreAlgorithm() {
        return keyStoreAlgorithm;
    }

    public String getTrustStoreFile() {
        return trustStoreFile;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public String getTrustStoreAlgorithm() {
        return trustStoreAlgorithm;
    }

    private KeyStore getKeyStore(String file, String pass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("jks");
        FileInputStream in = new FileInputStream(file);
        try {
            ks.load(in, pass.toCharArray());
            return ks;
        } finally {
            in.close();
        }
    }

    public SSLContext createContext() {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(getKeyStoreAlgorithm());
            kmf.init(getKeyStore(getKeyStoreFile(), getKeyStorePassword()), getKeyStorePassword().toCharArray());

            TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(trustStoreAlgorithm);
            trustFactory.init(getKeyStore(getTrustStoreFile(), getTrustStorePassword()));

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), trustFactory.getTrustManagers(), null);

            return sslContext;
        } catch (Exception e) {
            throw new Error("Failed to initialize the SSLContext", e);
        }
    }
}
