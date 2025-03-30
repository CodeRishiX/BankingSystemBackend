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

        // Input validation
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

            // 1. Check if account exists in bank_accounts
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

            // 2. Verify OTP against temporary pre-registration storage
            String verifyQuery = "SELECT otp, otp_timestamp FROM pre_registration WHERE account_number = ?";
            String storedOtp = null;
            Timestamp otpTimestamp = null;
            try (PreparedStatement verifyPs = con.prepareStatement(verifyQuery)) {
                verifyPs.setString(1, accountNumber);
                try (ResultSet rs = verifyPs.executeQuery()) {
                    if (rs.next()) {
                        storedOtp = rs.getString("otp");
                        otpTimestamp = rs.getTimestamp("otp_timestamp");
                    } else {
                        // Fallback to check users table if not found in pre_registration
                        String fallbackQuery = "SELECT otp, otp_timestamp FROM users WHERE account_number = ?";
                        try (PreparedStatement fallbackPs = con.prepareStatement(fallbackQuery)) {
                            fallbackPs.setString(1, accountNumber);
                            try (ResultSet fallbackRs = fallbackPs.executeQuery()) {
                                if (fallbackRs.next()) {
                                    storedOtp = fallbackRs.getString("otp");
                                    otpTimestamp = fallbackRs.getTimestamp("otp_timestamp");
                                }
                            }
                        }
                    }
                }
            }

            if (storedOtp == null || !userOtp.equals(storedOtp) || isOtpExpired(otpTimestamp)) {
                throw new IllegalArgumentException("Invalid or expired OTP!");
            }

            // 3. Proceed with registration
            String securityQuestion = getSecurityQuestion(securityQuestionChoice);
            String hashedAnswer = BCrypt.hashpw(securityAnswer, BCrypt.gensalt());
            String hashedPassword = BCrypt.hashpw(password1, BCrypt.gensalt(12));

            // Insert into users table
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

            // Clean up pre-registration data if it exists
            String clearPreRegQuery = "DELETE FROM pre_registration WHERE account_number = ?";
            try (PreparedStatement clearPs = con.prepareStatement(clearPreRegQuery)) {
                clearPs.setString(1, accountNumber);
                clearPs.executeUpdate();
            }

            // Clear OTP from users table if it exists there
            String clearUserOtpQuery = "UPDATE users SET otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
            try (PreparedStatement clearUserOtpPs = con.prepareStatement(clearUserOtpQuery)) {
                clearUserOtpPs.setString(1, accountNumber);
                clearUserOtpPs.executeUpdate();
            }

            con.commit();
            logger.info("Registration successful for account: {}", accountNumber);

        } catch (SQLException | IllegalArgumentException e) {
            con.rollback();
            logger.error("Error during registration: {}", e.getMessage(), e);
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }

    // Helper method to check if OTP is expired
    private boolean isOtpExpired(Timestamp otpTimestamp) {
        if (otpTimestamp == null) return true;
        long currentTime = System.currentTimeMillis();
        long otpTime = otpTimestamp.getTime();
        return (currentTime - otpTime) > (5 * 60 * 1000); // 5 minutes expiration
    }

    // Helper method to get security question
    private String getSecurityQuestion(int choice) {
        switch (choice) {
            case 1: return "What is your pet's name?";
            case 2: return "What is your mother's maiden name?";
            case 3: return "What is the name of your first school?";
            default: throw new IllegalArgumentException("Invalid security question choice.");
        }
    }

    // Password strength checker
    public static boolean isPasswordStrong(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
        boolean isStrong = password.matches(regex);
        logger.debug("Password strength check result: {}", isStrong);
        return isStrong;
    }

    // Forgot password method (updated to use new OTP verification)
    public void forgotPassword(String accountNumber, String phoneNumber, String securityAnswer,
                               String userOtp, String newPassword1, String newPassword2,
                               Connection con) throws SQLException, MessagingException {
        logger.info("Forgot password attempt for account: {}", accountNumber);

        // Input validation
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

            // Get user details
            String query = "SELECT * FROM users WHERE account_number = ?";
            String registeredPhone = null;
            String email = null;
            String hashedAnswer = null;
            try (PreparedStatement ps = con.prepareStatement(query)) {
                ps.setString(1, accountNumber);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        registeredPhone = rs.getString("phone");
                        email = rs.getString("email");
                        hashedAnswer = rs.getString("security_answer_hash");
                    } else {
                        throw new SQLException("Account number not found!");
                    }
                }
            }

            // Verify security answer
            if (!BCrypt.checkpw(securityAnswer, hashedAnswer)) {
                throw new IllegalArgumentException("Incorrect security answer!");
            }

            // Verify phone number
            if (!registeredPhone.equals(phoneNumber)) {
                throw new IllegalArgumentException("Incorrect phone number!");
            }

            // Verify OTP (using the new verification logic)
            String verifyQuery = "SELECT otp, otp_timestamp FROM users WHERE account_number = ?";
            String storedOtp = null;
            Timestamp otpTimestamp = null;
            try (PreparedStatement verifyPs = con.prepareStatement(verifyQuery)) {
                verifyPs.setString(1, accountNumber);
                try (ResultSet rs = verifyPs.executeQuery()) {
                    if (rs.next()) {
                        storedOtp = rs.getString("otp");
                        otpTimestamp = rs.getTimestamp("otp_timestamp");
                    }
                }
            }

            if (storedOtp == null || !userOtp.equals(storedOtp) || isOtpExpired(otpTimestamp)) {
                throw new IllegalArgumentException("Invalid or expired OTP!");
            }

            // Check password strength
            if (!isPasswordStrong(newPassword1)) {
                throw new IllegalArgumentException("Password is weak. It must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters.");
            }

            // Update password
            String hashedPassword = BCrypt.hashpw(newPassword1, BCrypt.gensalt(12));
            String updateQuery = "UPDATE users SET password_hash = ? WHERE account_number = ?";
            try (PreparedStatement ps = con.prepareStatement(updateQuery)) {
                ps.setString(1, hashedPassword);
                ps.setString(2, accountNumber);
                if (ps.executeUpdate() == 0) {
                    throw new SQLException("Failed to update password.");
                }
            }

            // Clear OTP
            String clearOtpQuery = "UPDATE users SET otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
            try (PreparedStatement clearOtpPs = con.prepareStatement(clearOtpQuery)) {
                clearOtpPs.setString(1, accountNumber);
                clearOtpPs.executeUpdate();
            }

            con.commit();
            logger.info("Password reset successful for account: {}", accountNumber);

        } catch (SQLException e) {
            con.rollback();
            logger.error("Error during password reset: {}", e.getMessage(), e);
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }
}