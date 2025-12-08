module com.kol.auth.core {
    requires java.sql;
    requires org.postgresql.jdbc;
    requires de.mkammerer.argon2.nolibs;
    requires com.sun.jna;

    exports org.cv.auth;
}
