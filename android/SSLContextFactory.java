package com.robobo.pki;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * Factory utility for creating TLS SSLContext instances for Android applications
 * connecting to Robobo fleet robots.
 *
 * <p>Supports loading native PKCS#12 (.p12) identity files and X.509 Root CA certificates directly
 * from Android raw resources (res/raw/) or assets/ without requiring BKS keystores or BouncyCastle.</p>
 */
public class SSLContextFactory {

    /**
     * Creates an SSLContext for Mutual TLS (mTLS) directly from a PKCS#12 (.p12) identity stream
     * and a Root CA certificate stream.
     *
     * <p>This avoids the overhead and hanging issues associated with BKS keystores by using
     * Android's native PKCS#12 and X.509 providers.</p>
     *
     * @param p12InputStream    InputStream for the robot PKCS#12 identity file (.p12) from raw/assets
     * @param p12Password       Password for the PKCS#12 file
     * @param caCertInputStream InputStream for the Robobo Root CA certificate (ca.crt / PEM) from raw/assets
     * @return Initialized SSLContext ready for mTLS connections
     */
    public static SSLContext createSSLContextFromP12(
            InputStream p12InputStream,
            char[] p12Password,
            InputStream caCertInputStream
    ) throws Exception {
        return createSSLContextFromP12(p12InputStream, p12Password, caCertInputStream, null, null);
    }

    /**
     * Creates an SSLContext for Mutual TLS (mTLS) directly from a PKCS#12 (.p12) identity stream
     * and a Root CA certificate stream, checking manifest availability in advance for the target robot.
     *
     * @param p12InputStream    InputStream for the robot PKCS#12 identity file (.p12) from raw/assets
     * @param p12Password       Password for the PKCS#12 file
     * @param caCertInputStream InputStream for the Robobo Root CA certificate (ca.crt / PEM) from raw/assets
     * @param targetRobotId     Target robot identity ID (e.g. "7VH" or "rob-7vh"), optional
     * @param manifest          Parsed RoboboManifest instance, optional
     * @return Initialized SSLContext ready for mTLS connections
     */
    public static SSLContext createSSLContextFromP12(
            InputStream p12InputStream,
            char[] p12Password,
            InputStream caCertInputStream,
            String targetRobotId,
            RoboboManifest manifest
    ) throws Exception {
        // 1. Optional advance verification against the PKI manifest
        if (targetRobotId != null && manifest != null && !manifest.isRobotAvailable(targetRobotId)) {
            throw new IllegalArgumentException(
                    "Robot identity '" + targetRobotId + "' is not available in the PKI manifest. Cannot proceed with TLS connection."
            );
        }

        String chosenAlias = (targetRobotId != null && manifest != null) ? manifest.getRobotAlias(targetRobotId) : null;

        // 2. Load PKCS#12 KeyStore natively (supported out-of-the-box on Android)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(p12InputStream, p12Password);

        // 3. Initialize KeyManagerFactory for client certificate authentication
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, p12Password);

        KeyManager[] kmfManagers = kmf.getKeyManagers();
        KeyManager[] customManagers = kmfManagers;

        if (chosenAlias != null) {
            customManagers = new KeyManager[kmfManagers.length];
            for (int i = 0; i < kmfManagers.length; i++) {
                if (kmfManagers[i] instanceof X509KeyManager) {
                    customManagers[i] = new RoboboKeyManager((X509KeyManager) kmfManagers[i], chosenAlias);
                } else {
                    customManagers[i] = kmfManagers[i];
                }
            }
        }

        // 4. Initialize TrustManagerFactory using Root CA certificate
        TrustManagerFactory tmf;
        if (caCertInputStream != null) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate ca = cf.generateCertificate(caCertInputStream);

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("robobo-root-ca", ca);

            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
        } else {
            // Fall back to trusting certificates inside the PKCS12 store if CA stream is not provided
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
        }

        // 5. Build TLS SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(customManagers, tmf.getTrustManagers(), null);

        return sslContext;
    }


    /**
     * Creates an SSLContext trusting the custom Robobo Root CA certificate from PEM input.
     */
    public static SSLContext createSSLContextFromCaCertificate(InputStream caCertInputStream) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate ca = cf.generateCertificate(caCertInputStream);

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

