package com.Rishi;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mindrot.jbcrypt.BCrypt;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Login {
    private static final Logger logger = LogManager.getLogger(Login.class);

    public Map<String, Object> login(String account, String password, String userOtp, Connection con) throws SQLException {
        Map<String, Object> response = new HashMap<>();
        logger.info("Login attempt for account: {}", account);

        try {
            // Start a transaction
            con.setAutoCommit(false);

            // Fetch user details from the users table
            String userQuery = "SELECT email, password_hash, failed_attempts, lock_time FROM users WHERE account_number = ?";
            String email = null;
            String storedPassword = null;
            int failedAttempts = 0;
            Timestamp lockTime = null;

            try (PreparedStatement userPs = con.prepareStatement(userQuery)) {
                userPs.setString(1, account);
                try (ResultSet userRs = userPs.executeQuery()) {
                    if (userRs.next()) {
                        email = userRs.getString("email");
                        storedPassword = userRs.getString("password_hash");
                        failedAttempts = userRs.getInt("failed_attempts");
                        lockTime = userRs.getTimestamp("lock_time");
                    } else {
                        logger.warn("Account number not found in users table: {}", account);
                        throw new SQLException("Account number not found!");
                    }
                }
            }

            // Check if account is locked
            if (lockTime != null) {
                long currentTime = System.currentTimeMillis();
                long lockDuration = (currentTime - lockTime.getTime()) / 1000; // in seconds
                if (lockDuration < 300) { // 5 minutes lock
                    logger.warn("Account {} is locked. Time remaining: {} seconds", account, (300 - lockDuration));
                    throw new SQLException("Account is locked. Please try again after 5 minutes or reset your password.");
                } else {
                    // Unlock the account
                    String unlockQuery = "UPDATE users SET failed_attempts = 0, lock_time = NULL WHERE account_number = ?";
                    try (PreparedStatement unlockPs = con.prepareStatement(unlockQuery)) {
                        unlockPs.setString(1, account);
                        unlockPs.executeUpdate();
                        logger.info("Account {} unlocked after lock duration", account);
                    }
                    failedAttempts = 0;
                }
            }

            // Verify password
            if (!BCrypt.checkpw(password, storedPassword)) {
                failedAttempts++;
                if (failedAttempts >= 3) {
                    String lockQuery = "UPDATE users SET failed_attempts = ?, lock_time = ? WHERE account_number = ?";
                    try (PreparedStatement lockPs = con.prepareStatement(lockQuery)) {
                        lockPs.setInt(1, failedAttempts);
                        lockPs.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
                        lockPs.setString(3, account);
                        lockPs.executeUpdate();
                        logger.warn("Account {} locked after {} failed attempts", account, failedAttempts);
                        throw new SQLException("Account is locked. Please try again after 5 minutes or reset your password.");
                    }
                } else {
                    String updateAttemptsQuery = "UPDATE users SET failed_attempts = ? WHERE account_number = ?";
                    try (PreparedStatement updatePs = con.prepareStatement(updateAttemptsQuery)) {
                        updatePs.setInt(1, failedAttempts);
                        updatePs.setString(2, account);
                        updatePs.executeUpdate();
                        logger.warn("Incorrect password for account: {}. Attempt {} of 3", account, failedAttempts);
                        throw new SQLException("Incorrect password! Attempt " + failedAttempts + " of 3.");
                    }
                }
            }

            logger.info("Password verified successfully for account: {}", account);

            // Retrieve the stored OTP from the users table
            String otpQuery = "SELECT otp, otp_timestamp FROM users WHERE account_number = ?";
            String storedOtp = null;
            Timestamp otpTimestamp = null;
            try (PreparedStatement otpPs = con.prepareStatement(otpQuery)) {
                otpPs.setString(1, account);
                try (ResultSet otpRs = otpPs.executeQuery()) {
                    if (otpRs.next()) {
                        storedOtp = otpRs.getString("otp");
                        otpTimestamp = otpRs.getTimestamp("otp_timestamp");
                    }
                }
            }

            // If no OTP exists or it has expired, generate a new one
            if (storedOtp == null || otpTimestamp == null || isOtpExpired(otpTimestamp)) {
                String generatedOtp = OTPService.generateOTP(account);
                logger.info("Generated OTP for login for account {}: {}", account, generatedOtp);
                OTPService.sendOTP(account, con); // This will store the OTP in the users table
                storedOtp = generatedOtp;
                otpTimestamp = new Timestamp(System.currentTimeMillis());

                // Update the stored OTP and timestamp in the users table
                String updateOtpQuery = "UPDATE users SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
                try (PreparedStatement updateOtpPs = con.prepareStatement(updateOtpQuery)) {
                    updateOtpPs.setString(1, storedOtp);
                    updateOtpPs.setTimestamp(2, otpTimestamp);
                    updateOtpPs.setString(3, account);
                    updateOtpPs.executeUpdate();
                    logger.info("Stored new OTP for account: {}", account);
                }
            }

            // Verify OTP
            if (!userOtp.equals(storedOtp)) {
                logger.warn("Incorrect OTP entered for account: {} (entered: {}, stored: {})", account, userOtp, storedOtp);
                throw new IllegalArgumentException("Incorrect OTP! Please try again.");
            }

            logger.info("OTP verified successfully for account: {}", account);

            // Fetch balance from bank_accounts
            String balanceQuery = "SELECT balance FROM bank_accounts WHERE account_number = ?";
            double balance = 0.0;
            try (PreparedStatement balancePs = con.prepareStatement(balanceQuery)) {
                balancePs.setString(1, account);
                try (ResultSet balanceRs = balancePs.executeQuery()) {
                    if (balanceRs.next()) {
                        balance = balanceRs.getDouble("balance");
                    } else {
                        logger.warn("Account number not found in bank_accounts table: {}", account);
                        throw new SQLException("Account not found in bank_accounts table!");
                    }
                }
            }

            // Clear OTP and reset failed attempts after successful login
            String clearOtpQuery = "UPDATE users SET otp = NULL, otp_timestamp = NULL, failed_attempts = 0 WHERE account_number = ?";
            try (PreparedStatement clearOtpPs = con.prepareStatement(clearOtpQuery)) {
                clearOtpPs.setString(1, account);
                clearOtpPs.executeUpdate();
                logger.info("Cleared OTP and reset failed attempts for account: {}", account);
            }

            // Generate and store session token
            String token = UUID.randomUUID().toString();
            String updateTokenQuery = "UPDATE users SET session_token = ?, token_timestamp = ? WHERE account_number = ?";
            try (PreparedStatement tokenPs = con.prepareStatement(updateTokenQuery)) {
                tokenPs.setString(1, token);
                tokenPs.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
                tokenPs.setString(3, account);
                tokenPs.executeUpdate();
                logger.info("Generated and stored session token for account: {}", account);
            }

            // Commit the transaction
            con.commit();

            // Prepare success response with token
            response.put("status", "success");
            response.put("message", "Login successful");
            response.put("accnumber", account);
            response.put("email", email);
            response.put("balance", balance);
            response.put("token", token); // Add token to response
        } catch (SQLException e) {
            logger.error("SQLException during login for account {}: {}", account, e.getMessage(), e);
            con.rollback();
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during login for account {}: {}", account, e.getMessage(), e);
            con.rollback();
            throw new SQLException("Unexpected error during login: " + e.getMessage(), e);
        } finally {
            con.setAutoCommit(true);
        }

        return response;
    }

    private boolean isOtpExpired(Timestamp otpTimestamp) {
        long currentTime = System.currentTimeMillis();
        long otpTime = otpTimestamp.getTime();
        long elapsedTime = (currentTime - otpTime) / 1000; // Time in seconds
        if (elapsedTime > 300) { // 5 minutes = 300 seconds
            logger.warn("OTP expired (elapsed time: {}s)", elapsedTime);
            return true;
        }
        return false;
    }
}