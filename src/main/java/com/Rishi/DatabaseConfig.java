package com.Rishi;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConfig {
    public static Connection getConnection() throws SQLException {
        String url = System.getenv("DB_URL");
        String username = System.getenv("DB_USERNAME");
        String password = System.getenv("DB_PASSWORD");

        // Check if environment variables are set
        if (url == null || username == null || password == null) {
            throw new SQLException("Database credentials not found in environment variables. Set DB_URL, DB_USERNAME, and DB_PASSWORD.");
        }

        try {
            return DriverManager.getConnection(url, username, password);
        } catch (SQLException e) {
            throw new SQLException("Failed to connect to database: " + e.getMessage() +
                    "\nURL: " + url +
                    "\nUsername: " + username, e);
        }
    }
}