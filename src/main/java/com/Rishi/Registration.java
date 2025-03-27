package com.Rishi;

import java.sql.*;
import javax.mail.MessagingException;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Registration {
    private static final Logger logger = LogManager.getLogger(Registration.class);

    public void reg(String accountNumber, String userOtp, int securityQuestionChoice,
                    String securityAnswer, String password1, String password2,
                    String email, Connection con) throws SQLException, MessagingException {
        logger.info("Starting registration for account: {}", accountNumber);

        // Input validation (unchanged)
        if (accountNumber == null || accountNumber.isEmpty()) {
            throw new IllegalArgumentException("Account number cannot be empty!");
        }
        if (securityQuestionChoice < 1 || securityQuestionChoice > 3) {
            throw new IllegalArgumentException("Invalid security question choice!");
        }
        if (securityAnswer == null || securityAnswer.isEmpty()) {
            throw new IllegalArgumentException("Security answer cannot be empty!");
        }
        if (!password1.equals(password2)) {
            throw new IllegalArgumentException("Passwords do not match!");
        }
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be empty!");
        }

        try {
            con.setAutoCommit(false);

            // Check if account exists in bank_accounts (unchanged)
            String checkBankQuery = "SELECT email, phone FROM bank_accounts WHERE account_number = ?";
            String storedEmail = null;
            String phone = null;
            try (PreparedStatement checkPs = con.prepareStatement(checkBankQuery)) {
                checkPs.setString(1, accountNumber);
                try (ResultSet rs = checkPs.executeQuery()) {
                    if (!rs.next()) {
                        throw new SQLException("Account not found in bank records.");
                    }
                    storedEmail = rs.getString("email");
                    phone = rs.getString("phone");
                }
            }

            // Fetch OTP from bank_accounts (FIXED: No redundant OTP generation)
            String otpQuery = "SELECT otp, otp_timestamp FROM bank_accounts WHERE account_number = ?";
            String storedOtp = null;
            Timestamp otpTimestamp = null;
            try (PreparedStatement otpPs = con.prepareStatement(otpQuery)) {
                otpPs.setString(1, accountNumber);
                try (ResultSet otpRs = otpPs.executeQuery()) {
                    if (otpRs.next()) {
                        storedOtp = otpRs.getString("otp");
                        otpTimestamp = otpRs.getTimestamp("otp_timestamp");
                    }
                }
            }

            // OTP verification (FIXED: Only generate new OTP if none exists or expired)
            if (storedOtp == null || otpTimestamp == null || isOtpExpired(otpTimestamp)) {
                storedOtp = OTPService.sendOTP(accountNumber, storedEmail != null ? storedEmail : email, con);
                throw new IllegalArgumentException("A new OTP has been sent. Use the latest OTP.");
            } else if (!userOtp.equals(storedOtp)) {
                throw new IllegalArgumentException("Incorrect OTP!");
            }

            // Proceed with registration (unchanged)
            String securityQuestion = getSecurityQuestion(securityQuestionChoice);
            String hashedAnswer = BCrypt.hashpw(securityAnswer, BCrypt.gensalt());
            String hashedPassword = BCrypt.hashpw(password1, BCrypt.gensalt(12));

            String insertUserQuery = "INSERT INTO users (account_number, email, phone, password_hash, " +
                    "security_question, security_answer_hash, otp_verified, registered_at) " +
                    "VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)";
            try (PreparedStatement insertUserPs = con.prepareStatement(insertUserQuery)) {
                insertUserPs.setString(1, accountNumber);
                insertUserPs.setString(2, storedEmail != null ? storedEmail : email);
                insertUserPs.setString(3, phone != null ? phone : "");
                insertUserPs.setString(4, hashedPassword);
                insertUserPs.setString(5, securityQuestion);
                insertUserPs.setString(6, hashedAnswer);
                insertUserPs.executeUpdate();
            }

            // Clear OTP after successful registration (unchanged)
            String clearOtpQuery = "UPDATE bank_accounts SET otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
            try (PreparedStatement clearOtpPs = con.prepareStatement(clearOtpQuery)) {
                clearOtpPs.setString(1, accountNumber);
                clearOtpPs.executeUpdate();
            }

            con.commit();
            logger.info("Registration successful for account: {}", accountNumber);

        } catch (SQLException | MessagingException e) {
            con.rollback();
            logger.error("Error during registration: {}", e.getMessage(), e);
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }

    // Helper method to get security question (unchanged)
    private String getSecurityQuestion(int choice) {
        switch (choice) {
            case 1: return "What is your pet's name?";
            case 2: return "What is your mother's maiden name?";
            case 3: return "What is the name of your first school?";
            default: throw new IllegalArgumentException("Invalid security question choice.");
        }
    }

    // Helper method to check OTP expiry (unchanged)
    private boolean isOtpExpired(Timestamp otpTimestamp) {
        long elapsedTime = (System.currentTimeMillis() - otpTimestamp.getTime()) / 1000;
        return elapsedTime > 300; // 5 minutes
    }

    // Other methods (forgotPassword, isPasswordStrong) remain unchanged.

    public static boolean isPasswordStrong(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
        boolean isStrong = password.matches(regex);
        logger.debug("Password strength check result: {}", isStrong);
        return isStrong;
    }
    public void forgotPassword(String accountNumber, String phoneNumber, String securityAnswer, String userOtp, String newPassword1, String newPassword2, Connection con) throws SQLException, MessagingException {
        logger.info("Forgot password attempt for account: {}", accountNumber);

        if (accountNumber == null || accountNumber.isEmpty()) {
            throw new IllegalArgumentException("Account number cannot be empty!");
        }
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            throw new IllegalArgumentException("Phone number cannot be empty!");
        }
        if (securityAnswer == null || securityAnswer.isEmpty()) {
            throw new IllegalArgumentException("Security answer cannot be empty!");
        }
        if (newPassword1 == null || newPassword2 == null || !newPassword1.equals(newPassword2)) {
            throw new IllegalArgumentException("New passwords do not match!");
        }

        try {
            con.setAutoCommit(false);

            String query = "SELECT * FROM users WHERE account_number = ?";
            String registeredPhone = null;
            String email = null;
            String securityQuestion = null;
            String hashedAnswer = null;
            try (PreparedStatement ps = con.prepareStatement(query)) {
                ps.setString(1, accountNumber);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        registeredPhone = rs.getString("phone");
                        email = rs.getString("email");
                        securityQuestion = rs.getString("security_question");
                        hashedAnswer = rs.getString("security_answer_hash");
                        logger.info("Fetched user data for account: {} - phone: {}, email: {}", accountNumber, registeredPhone, email);
                    } else {
                        logger.warn("Account number not found in users table: {}", accountNumber);
                        throw new SQLException("Account number not found!");
                    }
                }
            }

            if (!BCrypt.checkpw(securityAnswer, hashedAnswer)) {
                logger.warn("Incorrect security answer entered for account: {}", accountNumber);
                throw new IllegalArgumentException("Incorrect security answer!");
            }

            if (!registeredPhone.equals(phoneNumber)) {
                logger.warn("Incorrect phone number entered for account: {}", accountNumber);
                throw new IllegalArgumentException("Incorrect phone number!");
            }

            OTPService.sendOTP(accountNumber, con);
            logger.info("OTP sent for account: {}", accountNumber);

            if (!OTPService.verifyOTP(accountNumber, userOtp, con)) {
                logger.warn("OTP verification failed for account: {}", accountNumber);
                throw new IllegalArgumentException("Incorrect or expired OTP! Password reset failed.");
            }

            logger.info("OTP verified successfully for account: {}", accountNumber);

            if (!isPasswordStrong(newPassword1)) {
                logger.warn("Weak password entered for account: {}", accountNumber);
                throw new IllegalArgumentException("Password is weak. It must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters.");
            }

            String hashedPassword = BCrypt.hashpw(newPassword1, BCrypt.gensalt(12));
            String updateQuery = "UPDATE users SET password_hash = ? WHERE account_number = ?";
            try (PreparedStatement ps2 = con.prepareStatement(updateQuery)) {
                ps2.setString(1, hashedPassword);
                ps2.setString(2, accountNumber);
                int check = ps2.executeUpdate();

                if (check > 0) {
                    logger.info("Password updated successfully for account: {}", accountNumber);
                } else {
                    logger.error("Failed to update password for account: {}", accountNumber);
                    throw new SQLException("Failed to update password.");
                }
            }

            String clearOtpQuery = "UPDATE users SET otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
            try (PreparedStatement clearOtpPs = con.prepareStatement(clearOtpQuery)) {
                clearOtpPs.setString(1, accountNumber);
                clearOtpPs.executeUpdate();
                logger.info("Cleared OTP for account: {}", accountNumber);
            }

            con.commit();
            logger.info("Forgot password successful for account: {}", accountNumber);
        } catch (SQLException e) {
            logger.error("SQLException during forgot password for account {}: {}", accountNumber, e.getMessage(), e);
            con.rollback();
            throw e;
        } catch (MessagingException e) {
            logger.error("MessagingException during forgot password for account {}: {}", accountNumber, e.getMessage(), e);
            con.rollback();
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during forgot password for account {}: {}", accountNumber, e.getMessage(), e);
            con.rollback();
            throw new SQLException("Unexpected error during forgot password: " + e.getMessage(), e);
        } finally {
            con.setAutoCommit(true);
        }
    }
}