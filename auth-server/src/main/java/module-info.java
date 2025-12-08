module com.kol.auth.server {
    requires jdk.httpserver;
    requires com.fasterxml.jackson.databind;
    requires com.kol.auth.core;

    exports org.cv.auth.server;
}

