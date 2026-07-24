package com.robobo.pki;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility for parsing and querying the Robobo PKI manifest (manifest.json).
 * Used to verify identity availability in advance before establishing TLS connections.
 */
public class RoboboManifest {

    private final Map<String, RobotInfo> robots = new HashMap<>();

    public static class RobotInfo {
        public final String id;
        public final String alias;
        public final String hostname;
        public final String url;
        public final String certificateFile;
        public final String keyFile;
        public final String p12File;
        public final String fingerprint;

        public RobotInfo(String id, String alias, String hostname, String url,
                         String certificateFile, String keyFile, String p12File, String fingerprint) {
            this.id = id;
            this.alias = alias;
            this.hostname = hostname;
            this.url = url;
            this.certificateFile = certificateFile;
            this.keyFile = keyFile;
            this.p12File = p12File;
            this.fingerprint = fingerprint;
        }
    }

    public static RoboboManifest fromInputStream(InputStream inputStream) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            builder.append(line);
        }
        return fromJsonString(builder.toString());
    }

    public static RoboboManifest fromJsonString(String jsonString) throws Exception {
        JSONObject root = new JSONObject(jsonString);
        JSONArray robotsArray = root.getJSONArray("robots");

        RoboboManifest manifest = new RoboboManifest();
        for (int i = 0; i < robotsArray.length(); i++) {
            JSONObject obj = robotsArray.getJSONObject(i);
            String id = obj.getString("id");
            String alias = obj.getString("alias");
            String hostname = obj.getString("hostname");
            String url = obj.getString("url");
            String certFile = obj.optString("certificate_file", "");
            String keyFile = obj.optString("key_file", "");
            String p12File = obj.optString("p12_file", "");
            String fingerprint = obj.optString("fingerprint", "");

            RobotInfo info = new RobotInfo(id, alias, hostname, url, certFile, keyFile, p12File, fingerprint);
            manifest.robots.put(id.toUpperCase(), info);
            manifest.robots.put(alias.toLowerCase(), info);
        }
        return manifest;
    }

    /**
     * Checks if key and certificate materials for a specific robot ID or alias are available.
     *
     * @param robotIdOrAlias e.g. "7VH" or "rob-7vh"
     * @return true if keys exist in the manifest, false otherwise.
     */
    public boolean isRobotAvailable(String robotIdOrAlias) {
        if (robotIdOrAlias == null) return false;
        return robots.containsKey(robotIdOrAlias.toUpperCase()) ||
               robots.containsKey(robotIdOrAlias.toLowerCase());
    }

    /**
     * Retrieves the RobotInfo object for a given robot ID or alias.
     */
    public RobotInfo getRobotInfo(String robotIdOrAlias) {
        if (robotIdOrAlias == null) return null;
        RobotInfo info = robots.get(robotIdOrAlias.toUpperCase());
        if (info == null) {
            info = robots.get(robotIdOrAlias.toLowerCase());
        }
        return info;
    }

    /**
     * Resolves the keystore alias for a given robot ID (e.g. "7VH" -> "rob-7vh").
     */
    public String getRobotAlias(String robotIdOrAlias) {
        RobotInfo info = getRobotInfo(robotIdOrAlias);
        return info != null ? info.alias : null;
    }
}
