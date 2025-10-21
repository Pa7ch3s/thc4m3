package com.jb.thickclient;

import java.util.regex.Pattern;

/**
 * Tiny PAC string builder used by the THC4M3 PAC button.
 * Usage:
 *   String pac = PacBuilder.fromRegex(hostPattern)
 *                          .withProxy("127.0.0.1:8080")
 *                          .build();
 */
public final class PacBuilder {
    private Pattern hostPattern = Pattern.compile(".*");
    private String proxy = "DIRECT";

    private PacBuilder() { }

    /** Start from a Java Pattern to test the *host* in PAC. */
    public static PacBuilder fromRegex(Pattern p) {
        PacBuilder b = new PacBuilder();
        b.hostPattern = (p != null) ? p : Pattern.compile(".*");
        return b;
    }

    /** Proxy to return when the regex matches. e.g., "127.0.0.1:8080" */
    public PacBuilder withProxy(String hostPort) {
        if (hostPort == null || hostPort.trim().isEmpty()) {
            this.proxy = "DIRECT";
        } else {
            this.proxy = "PROXY " + hostPort.trim();
        }
        return this;
    }

    /** Build the PAC file as a String. */
    public String build() {
        // Escape for embedding in JS RegExp literal
        String js = hostPattern.pattern()
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");

        return "function FindProxyForURL(url, host) {\n"
             + "  var re = new RegExp(\"" + js + "\");\n"
             + "  if (re.test(host)) return \"" + proxy + "\";\n"
             + "  return \"DIRECT\";\n"
             + "}\n";
    }
}
