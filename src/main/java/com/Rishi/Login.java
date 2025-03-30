package com.Rishi;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mindrot.jbcrypt.BCrypt;
import java.sql.*;
import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;

public class Login {
    private static final Logger logger = LogManager.getLogger(Login.class);

    public Map<String, Object> verifyLogin(String account, String password, String userOtp, Connection con) throws SQLException, MessagingException {
        Map<String, Object> response = new HashMap<>();
        logger.info("Login verification for account: {}", account);

        try {
            con.setAutoCommit(false);

            String userQuery = "SELECT email, password_hash, failed_attempts, lock_time, otp, otp_timestamp FROM users WHERE account_number = ?";
            String email = null;
            String storedPassword = null;
            int failedAttempts = 0;
            Timestamp lockTime = null;
            String storedOtp = null;
            Timestamp otpTimestamp = null;

            try (PreparedStatement userPs = con.prepareStatement(userQuery)) {
                userPs.setString(1, account);
                try (ResultSet userRs = userPs.executeQuery()) {
                    if (userRs.next()) {
                        email = userRs.getString("email");
                        storedPassword = userRs.getString("password_hash");
                        failedAttempts = userRs.getInt("failed_attempts");
                        lockTime = userRs.getTimestamp("lock_time");
                        storedOtp = userRs.getString("otp");
                        otpTimestamp = userRs.getTimestamp("otp_timestamp");
                    } else {
                        logger.warn("Account number not found in users table: {}", account);
                        throw new SQLException("Account number not found!");
                    }
                }
            }

            if (lockTime != null) {
                long currentTime = System.currentTimeMillis();
                long lockDuration = (currentTime - lockTime.getTime()) / 1000;
                if (lockDuration < 300) {
                    logger.warn("Account {} is locked. Time remaining: {} seconds", account, (300 - lockDuration));
                    throw new SQLException("Account is locked. Please try again after 5 minutes or reset your password.");
                } else {
                    String unlockQuery = "UPDATE users SET failed_attempts = 0, lock_time = NULL WHERE account_number = ?";
                    try (PreparedStatement unlockPs = con.prepareStatement(unlockQuery)) {
                        unlockPs.setString(1, account);
                        unlockPs.executeUpdate();
                        logger.info("Account {} unlocked after lock duration", account);
                    }
                    failedAttempts = 0;
                }
            }

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

            // Verify OTP (no generation here)
            if (storedOtp == null || otpTimestamp == null || isOtpExpired(otpTimestamp)) {
                logger.warn("No valid OTP found for account: {}", account);
                throw new SQLException("No valid OTP found. Please request a new OTP.");
            }
            if (!userOtp.equals(storedOtp)) {
                logger.warn("Incorrect OTP entered for account: {} (entered: {}, stored: {})", account, userOtp, storedOtp);
                throw new IllegalArgumentException("Incorrect OTP! Please try again.");
            }
            logger.info("OTP verified successfully for account: {}", account);

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
            // Add to user_sessions table
            String sessionQuery = "INSERT INTO user_sessions (account_number, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))";
            try (PreparedStatement sessionPs = con.prepareStatement(sessionQuery)) {
                sessionPs.setString(1, account);
                sessionPs.setString(2, token);
                sessionPs.executeUpdate();
            }

            con.commit();

            response.put("status", "success");
            response.put("message", "Login successful");
            response.put("accnumber", account);
            response.put("email", email);
            response.put("balance", balance);
            response.put("token", token);

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
        long elapsedTime = (currentTime - otpTime) / 1000;
        if (elapsedTime > 300) {
            logger.warn("OTP expired (elapsed time: {}s)", elapsedTime);
            return true;
        }
        return false;
    }

    // Added: Generate OTP method (made public for Banking_system.java)
    public String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        logger.info("Generated OTP: {}", otp);
        return String.valueOf(otp);
    }

    // Added: Send email method (made public for Banking_system.java)
    public void sendEmail(String to, String subject, String body) throws MessagingException {
        final String senderEmail = "saltlakesisco@gmail.com";
        final String senderPassword = "wgdl tlfz jmhf itrh";

        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(senderEmail, senderPassword);
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(senderEmail));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        message.setSubject(subject);
        message.setText(body);

        Transport.send(message);
        logger.info("Email sent successfully to: {}", to);
    }
}