package com.robobo.pki;

import java.io.InputStream;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * Factory utility for creating TLS SSLContext instances for Android applications
 * connecting to Robobo fleet robots using BKS keystores.
 */
public class SSLContextFactory {

    /**
     * Creates an SSLContext for Mutual TLS (mTLS) using a BKS keystore bundle, checking
     * manifest availability in advance for the targeted robot identity.
     *
     * @param bksInputStream InputStream for the generated robobo-identities.bks file
     * @param bksPassword    Password for the BKS keystore
     * @param targetRobotId  Target robot identity ID (e.g. "7VH" or "rob-7vh")
     * @param manifest       Parsed RoboboManifest instance
     * @return Initialized SSLContext ready for HTTPS/mTLS connections
     */
    public static SSLContext createSSLContextFromBks(
            InputStream bksInputStream,
            char[] bksPassword,
            String targetRobotId,
            RoboboManifest manifest
    ) throws Exception {
        // 1. Verify in advance if keys for the target robot are available in the manifest
        if (manifest != null && !manifest.isRobotAvailable(targetRobotId)) {
            throw new IllegalArgumentException(
                    "Robot identity '" + targetRobotId + "' is not available in the PKI manifest. Cannot proceed with TLS connection."
            );
        }

        String chosenAlias = manifest != null ? manifest.getRobotAlias(targetRobotId) : targetRobotId.toLowerCase();
        if (chosenAlias == null) {
            chosenAlias = targetRobotId.toLowerCase();
        }

        // 2. Load BKS KeyStore containing client certificates and Root CA
        KeyStore bksStore = KeyStore.getInstance("BKS");
        bksStore.load(bksInputStream, bksPassword);

        // 3. Initialize KeyManagerFactory for client certificate authentication
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(bksStore, bksPassword);

        KeyManager[] kmfManagers = kmf.getKeyManagers();
        KeyManager[] customManagers = new KeyManager[kmfManagers.length];
        for (int i = 0; i < kmfManagers.length; i++) {
            if (kmfManagers[i] instanceof X509KeyManager) {
                customManagers[i] = new RoboboKeyManager((X509KeyManager) kmfManagers[i], chosenAlias);
            } else {
                customManagers[i] = kmfManagers[i];
            }
        }

        // 4. Initialize TrustManagerFactory trusting the Root CA stored in the BKS keystore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(bksStore);

        // 5. Build TLS SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(customManagers, tmf.getTrustManagers(), null);

        return sslContext;
    }

    /**
     * Creates an SSLContext trusting the custom Robobo Root CA certificate from PEM input.
     */
    public static SSLContext createSSLContextFromCaCertificate(InputStream caCertInputStream) throws Exception {
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate ca = cf.generateCertificate(caCertInputStream);

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("robobo-root-ca", ca);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        return sslContext;
    }
}
