package org.cv.auth.server;

import org.cv.auth.LauncherAuthService;
import java.util.Locale;

public final class AuthServerMain {
    public static void main(String[] args) throws Exception {
        String host = resolve(args, "kol.auth.server.host", "KOL_AUTH_SERVER_HOST", "127.0.0.1");
        int port = resolvePort(args, "kol.auth.server.port", "KOL_AUTH_SERVER_PORT", 8085);
        System.out.println("Starting Kol auth validation server on " + host + ":" + port);
        AuthValidationServer.launch(new LauncherAuthService(), host, port);
    }

    private static String resolve(String[] args, String sysProp, String envVar, String def) {
        String fromArgs = parseOption(args, "--host");
        String fromProp = System.getProperty(sysProp);
        String fromEnv = System.getenv(envVar);
        String selected = firstNonBlank(fromArgs, fromProp, fromEnv);
        return selected == null ? def : selected.trim();
    }

    private static int resolvePort(String[] args, String sysProp, String envVar, int def) {
        String fromArgs = parseOption(args, "--port");
        String fromProp = System.getProperty(sysProp);
        String fromEnv = System.getenv(envVar);
        String selected = firstNonBlank(fromArgs, fromProp, fromEnv);
        if (selected != null) {
            try {
                int value = Integer.parseInt(selected.trim());
                if (value >= 1 && value <= 65535) {
                    return value;
                }
            } catch (NumberFormatException ignored) {}
        }
        return def;
    }

    private static String parseOption(String[] args, String option) {
        if (args == null || option == null) return null;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (option.equals(a)) {
                if (i + 1 < args.length) return args[i + 1];
            }
            if (a != null && a.toLowerCase(Locale.ROOT).startsWith(option + "=")) {
                return a.substring(option.length() + 1);
            }
        }
        return null;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String value : values) {
            if (value != null && !value.isBlank()) return value;
        }
        return null;
    }
}

