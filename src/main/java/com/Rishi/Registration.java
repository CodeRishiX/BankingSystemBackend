package com.Rishi;

import java.sql.*;
import javax.mail.MessagingException;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

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

            // Clean up pre-registration data
            String clearPreRegQuery = "DELETE FROM pre_registration WHERE account_number = ?";
            try (PreparedStatement clearPs = con.prepareStatement(clearPreRegQuery)) {
                clearPs.setString(1, accountNumber);
                clearPs.executeUpdate();
            }

            // Clear OTP from users table
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

    // Updated method for /get-security-question with phone number verification (unchanged)
    public Map<String, String> getSecurityQuestionAndHash(String accountNumber, String phoneNumber, Connection con) throws SQLException {
        Map<String, String> result = new HashMap<>();
        String query = "SELECT security_question, security_answer_hash, phone FROM users WHERE account_number = ?";

        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedPhone = rs.getString("phone");
                    if (!storedPhone.equals(phoneNumber)) {
                        throw new SQLException("Phone number mismatch");
                    }
                    result.put("question", rs.getString("security_question"));
                    result.put("answerHash", rs.getString("security_answer_hash"));
                    return result;
                }
            }
        }
        throw new SQLException("Account not found");
    }

    // Updated method for /verify-security-answer with OTP sent to email instead of SMS
    public String verifySecurityAnswerAndGenerateOtp(String accountNumber, String providedAnswer, Connection con) throws SQLException, MessagingException {
        logger.info("Verifying security answer for account: {}", accountNumber);

        String query = "SELECT security_answer_hash, email FROM users WHERE account_number = ?";
        String storedHash = null;
        String email = null;
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    storedHash = rs.getString("security_answer_hash");
                    email = rs.getString("email");
                } else {
                    throw new SQLException("Account not found");
                }
            }
        }

        if (!BCrypt.checkpw(providedAnswer, storedHash)) {
            throw new IllegalArgumentException("Incorrect security answer");
        }

        // Generate and store OTP
        String otp = String.format("%06d", new Random().nextInt(999999));
        String updateQuery = "UPDATE users SET otp = ?, otp_timestamp = CURRENT_TIMESTAMP WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(updateQuery)) {
            ps.setString(1, otp);
            ps.setString(2, accountNumber);
            int rowsUpdated = ps.executeUpdate();
            if (rowsUpdated == 0) {
                throw new SQLException("Failed to store OTP");
            }
        }

        // Send OTP via email instead of SMS
        sendEmail(email, "Your OTP for Password Reset", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");

        logger.info("OTP generated and sent to email {} for account: {}", email, accountNumber);
        return otp;
    }

    // Updated method for /reset-password (unchanged)
    public void resetPassword(String accountNumber, String userOtp, String newPassword, Connection con) throws SQLException {
        logger.info("Resetting password for account: {}", accountNumber);

        try {
            con.setAutoCommit(false);

            // Verify OTP
            String verifyQuery = "SELECT otp, otp_timestamp FROM users WHERE account_number = ?";
            String storedOtp = null;
            Timestamp otpTimestamp = null;
            try (PreparedStatement verifyPs = con.prepareStatement(verifyQuery)) {
                verifyPs.setString(1, accountNumber);
                try (ResultSet rs = verifyPs.executeQuery()) {
                    if (rs.next()) {
                        storedOtp = rs.getString("otp");
                        otpTimestamp = rs.getTimestamp("otp_timestamp");
                    } else {
                        throw new SQLException("Account not found");
                    }
                }
            }

            if (storedOtp == null || !userOtp.equals(storedOtp) || isOtpExpired(otpTimestamp)) {
                throw new IllegalArgumentException("Invalid or expired OTP");
            }

            // Check password strength
            if (!isPasswordStrong(newPassword)) {
                throw new IllegalArgumentException("Password is weak. It must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters.");
            }

            // Update password
            String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
            String updateQuery = "UPDATE users SET password_hash = ?, otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
            try (PreparedStatement ps = con.prepareStatement(updateQuery)) {
                ps.setString(1, hashedPassword);
                ps.setString(2, accountNumber);
                int rowsUpdated = ps.executeUpdate();
                if (rowsUpdated == 0) {
                    throw new SQLException("Failed to update password");
                }
            }

            con.commit();
            logger.info("Password reset successful for account: {}", accountNumber);

        } catch (SQLException | IllegalArgumentException e) {
            con.rollback();
            logger.error("Error during password reset: {}", e.getMessage(), e);
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }

    // Helper method to get phone number (unchanged)
    private String getPhoneNumber(String accountNumber, Connection con) throws SQLException {
        String query = "SELECT phone FROM users WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("phone");
                }
            }
        }
        throw new SQLException("Phone number not found");
    }

    // New method to send email (aligned with registration flow)
    private void sendEmail(String email, String subject, String message) throws MessagingException {
        logger.info("Sending email to {}: {}", email, message);
        // Assuming Login class has a sendEmail method similar to what’s used elsewhere
        new Login().sendEmail(email, subject, message); // Reuse existing email logic
    }

    // Removed sendSms since it’s no longer needed
    // Helper method to check if OTP is expired (unchanged)
    boolean isOtpExpired(Timestamp otpTimestamp) {
        if (otpTimestamp == null) return true;
        long currentTime = System.currentTimeMillis();
        long otpTime = otpTimestamp.getTime();
        return (currentTime - otpTime) > (5 * 60 * 1000); // 5 minutes expiration
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

    // Password strength checker (unchanged)
    public static boolean isPasswordStrong(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
        boolean isStrong = password.matches(regex);
        logger.debug("Password strength check result: {}", isStrong);
        return isStrong;
    }

    // Deprecated methods (updated to reflect email change)
    @Deprecated
    public Map<String, String> getSecurityQuestionAndHash(String accountNumber, Connection con) throws SQLException {
        return getSecurityQuestionAndHash(accountNumber, getPhoneNumber(accountNumber, con), con);
    }

    @Deprecated
    public boolean verifySecurityAnswer(String providedAnswer, String storedHash) {
        return BCrypt.checkpw(providedAnswer, storedHash);
    }

    @Deprecated
    public String generatePasswordResetOtp(String accountNumber, Connection con) throws SQLException, MessagingException {
        return verifySecurityAnswerAndGenerateOtp(accountNumber, "", con); // Dummy answer for compatibility
    }

    @Deprecated
    public void forgotPassword(String accountNumber, String phoneNumber, String securityAnswer,
                               String userOtp, String newPassword1, String newPassword2,
                               Connection con) throws SQLException, MessagingException {
        if (!newPassword1.equals(newPassword2)) {
            throw new IllegalArgumentException("Passwords do not match!");
        }
        resetPassword(accountNumber, userOtp, newPassword1, con);
    }
}