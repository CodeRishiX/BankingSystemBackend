package com.Rishi;

import java.util.*;
import java.sql.*;
import org.mindrot.jbcrypt.BCrypt;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Login {
    private static final Logger logger = LogManager.getLogger(Login.class);

    public boolean log(String account, Connection con, Scanner sc) {
        try {
            logger.info("Enter your password: ");
            String enteredPassword = sc.nextLine();

            String query = "SELECT email, phone, password_hash, failed_attempts, lock_time FROM users WHERE account_number=?";
            try (PreparedStatement ps = con.prepareStatement(query)) {
                ps.setString(1, account);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String email = rs.getString("email");
                        String phone = rs.getString("phone");
                        String storedHashedPassword = rs.getString("password_hash");
                        int failedAttempts = rs.getInt("failed_attempts");
                        Timestamp lockTime = rs.getTimestamp("lock_time");

                        if (lockTime != null) {
                            long lockDuration = System.currentTimeMillis() - lockTime.getTime();
                            if (lockDuration < 24 * 60 * 60 * 1000) {
                                logger.error("Your account is locked. Try again after 24 hours.");
                                return false;
                            } else {
                                String unlockQuery = "UPDATE users SET failed_attempts=0, lock_time=NULL WHERE account_number=?";
                                try (PreparedStatement unlockStmt = con.prepareStatement(unlockQuery)) {
                                    unlockStmt.setString(1, account);
                                    unlockStmt.executeUpdate();
                                    logger.info("Your account is unlocked. You can try logging in.");
                                }
                            }
                        }

                        if (BCrypt.checkpw(enteredPassword, storedHashedPassword)) {
                            OTPService.sendOTP(account, con);
                            logger.info("Enter the OTP received on your email: ");
                            String userOtp = sc.nextLine();

                            if (!OTPService.verifyOTP(account, userOtp, con)) {
                                logger.error("Incorrect or expired OTP! Login failed.");
                                return false;
                            }

                            logger.info("OTP Verified Successfully!");
                            logger.info("Login Successful!");

                            String resetAttemptsQuery = "UPDATE users SET failed_attempts=0, lock_time=NULL WHERE account_number=?";
                            try (PreparedStatement resetStmt = con.prepareStatement(resetAttemptsQuery)) {
                                resetStmt.setString(1, account);
                                resetStmt.executeUpdate();
                            }

                            String query1 = "SELECT name, balance, account_number FROM bank_accounts WHERE account_number=?";
                            try (PreparedStatement ps1 = con.prepareStatement(query1)) {
                                ps1.setString(1, account);
                                try (ResultSet rs1 = ps1.executeQuery()) {
                                    if (rs1.next()) {
                                        String name = rs1.getString("name");
                                        double balance = rs1.getDouble("balance");
                                        String accnumber = rs1.getString("account_number");

                                        logger.info("=== Account Details ===");
                                        logger.info("Name: {}", name);
                                        logger.info("Account Number: {}", accnumber);
                                        logger.info("Email: {}", email);
                                        logger.info("Phone: {}", phone);
                                        logger.info("Balance: {}", balance);
                                    }
                                }
                            }
                            return true;
                        } else {
                            failedAttempts++;
                            if (failedAttempts >= 3) {
                                String lockQuery = "UPDATE users SET lock_time=NOW() WHERE account_number=?";
                                try (PreparedStatement lockStmt = con.prepareStatement(lockQuery)) {
                                    lockStmt.setString(1, account);
                                    lockStmt.executeUpdate();
                                    logger.error("Too many failed attempts! Your account is locked for 24 hours.");
                                }
                            } else {
                                String updateAttemptsQuery = "UPDATE users SET failed_attempts=? WHERE account_number=?";
                                try (PreparedStatement updateStmt = con.prepareStatement(updateAttemptsQuery)) {
                                    updateStmt.setInt(1, failedAttempts);
                                    updateStmt.setString(2, account);
                                    updateStmt.executeUpdate();
                                    logger.warn("Incorrect password! Attempt {} of 3.", failedAttempts);
                                }
                            }
                            return false;
                        }
                    } else {
                        logger.error("Account number not found!");
                        return false;
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Database error during login: {}", e.getMessage(), e);
            return false;
        }
    }

    // Custom exception for user data retrieval issues
    public static class UserDataRetrievalException extends Exception {
        public UserDataRetrievalException(String message) {
            super(message);
        }
    }

    public String getUserEmail(String accountNumber, Connection con) throws UserDataRetrievalException {
        String query = "SELECT email FROM users WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String email = rs.getString("email");
                    if (email == null || email.trim().isEmpty()) {
                        logger.warn("No valid email found for account: {}", accountNumber);
                        throw new UserDataRetrievalException("No valid email found for account: " + accountNumber);
                    }
                    logger.debug("Retrieved email: {} for account: {}", email, accountNumber);
                    return email;
                } else {
                    logger.error("Account not found for email retrieval: {}", accountNumber);
                    throw new UserDataRetrievalException("Account not found: " + accountNumber);
                }
            }
        } catch (SQLException e) {
            logger.error("Error retrieving user email for account {}: {}", accountNumber, e.getMessage(), e);
            throw new UserDataRetrievalException("Database error retrieving email for account " + accountNumber + ": " + e.getMessage());
        }
    }

    public double getUserBalance(String accountNumber, Connection con) throws UserDataRetrievalException {
        String query = "SELECT balance FROM bank_accounts WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    double balance = rs.getDouble("balance");
                    logger.debug("Retrieved balance: {} for account: {}", balance, accountNumber);
                    return balance;
                } else {
                    logger.error("Account not found for balance retrieval: {}", accountNumber);
                    throw new UserDataRetrievalException("Account not found: " + accountNumber);
                }
            }
        } catch (SQLException e) {
            logger.error("Error retrieving user balance for account {}: {}", accountNumber, e.getMessage(), e);
            throw new UserDataRetrievalException("Database error retrieving balance for account " + accountNumber + ": " + e.getMessage());
        }
    }

    public static String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    public static void sendEmail(String recipientEmail, String otp) {
        final String senderEmail = "saltlakesisco@gmail.com";
        final String senderPassword = "wgdl tlfz jmhf itrh";

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(senderEmail, senderPassword);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail));
            message.setSubject("Your OTP Code");
            message.setText("Your OTP is: " + otp + "\n\nThis OTP is valid for 5 minutes.");

            Transport.send(message);
            logger.info("OTP sent successfully to {}", recipientEmail);
        } catch (MessagingException e) {
            logger.error("Failed to send OTP: {}", e.getMessage(), e);
        }
    }

    public static boolean isPasswordStrong(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
        return password.matches(regex);
    }
}