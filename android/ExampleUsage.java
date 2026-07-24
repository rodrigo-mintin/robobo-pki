package com.robobo.pki;

import java.io.InputStream;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

/**
 * Example demonstrating how to load a Robobo BKS keystore and manifest in Android
 * to dynamically select identity keys for specific fleet robots (e.g., "7VH" -> "rob-7vh").
 */
public class ExampleUsage {

    public void connectToRobot(
            InputStream manifestStream,
            InputStream bksStream,
            char[] keystorePassword,
            String robotId
    ) {
        try {
            // 1. Parse manifest.json to verify robot key availability in advance
            RoboboManifest manifest = RoboboManifest.fromInputStream(manifestStream);

            if (!manifest.isRobotAvailable(robotId)) {
                System.err.println("Robot " + robotId + " is NOT available in the generated PKI manifest!");
                return;
            }

            RoboboManifest.RobotInfo robotInfo = manifest.getRobotInfo(robotId);
            System.out.println("Connecting to robot " + robotInfo.id + " (" + robotInfo.hostname + ") at " + robotInfo.url);

            // 2. Initialize SSLContext using BKS keystore and target robot identity alias
            SSLContext sslContext = SSLContextFactory.createSSLContextFromBks(
                    bksStream,
                    keystorePassword,
                    robotId,
                    manifest
            );

            // 3. Configure HttpsURLConnection with custom SSLSocketFactory
            URL url = new URL(robotInfo.url);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());

            // 4. Connect to Robobo robot SSL/TLS endpoint
            conn.connect();
            int status = conn.getResponseCode();
            System.out.println("Connection status to " + robotInfo.url + ": " + status);

            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
