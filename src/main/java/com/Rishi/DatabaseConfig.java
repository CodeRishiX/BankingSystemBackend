package com.Rishi;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConfig {
    public static Connection getConnection() throws SQLException {
        // Read database connection details from environment variables
        String url = System.getenv("DB_URL");
        String username = System.getenv("DB_USERNAME");
        String password = System.getenv("DB_PASSWORD");

        if (url == null || username == null || password == null) {
            throw new SQLException("Database environment variables (DB_URL, DB_USERNAME, DB_PASSWORD) are not set.");
        }

        return DriverManager.getConnection(url, username, password);
    }
}