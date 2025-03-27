package com.Rishi;

import org.mindrot.jbcrypt.BCrypt;
import spark.Spark;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import java.io.IOException;
import java.sql.*;
import java.util.Map;
import org.json.JSONObject;

import javax.mail.MessagingException;

public class Banking_system {
    private static final Logger logger = LogManager.getLogger(Banking_system.class);

    public static void main(String[] args) {
        Spark.port(8080);
        logger.info("Database connected successfully!");
        logger.info("Banking System server started on port 8080");

        Spark.get("/", (req, res) -> "Banking System is running on port 8080!");

        // Registration endpoint (unchanged)
        Spark.post("/register", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String userOtp = req.queryParams("otp");
            int securityQuestionChoice = Integer.parseInt(req.queryParams("securityQuestionChoice"));
            String securityAnswer = req.queryParams("securityAnswer");
            String password1 = req.queryParams("password1");
            String password2 = req.queryParams("password2");
            String email = req.queryParams("email");

            Registration registration = new Registration();
            try (Connection conn = DatabaseConfig.getConnection()) {
                registration.reg(accountNumber, userOtp, securityQuestionChoice, securityAnswer, password1, password2, email, conn);
                return "{\"status\": \"success\", \"message\": \"Registration successful\"}";
            } catch (SQLException | MessagingException e) {
                logger.error("Registration failed: {}", e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Registration failed: " + e.getMessage() + "\"}";
            } catch (IllegalArgumentException e) {
                return "{\"status\": \"error\", \"message\": \"" + e.getMessage() + "\"}";
            }
        });

        // Login: Request OTP (unchanged)
        Spark.post("/login/request-otp", (req, res) -> {
            res.type("application/json");
            String accNumber = req.queryParams("accnumber");
            String password = req.queryParams("password");
            logger.info("Login OTP request for account: {}", accNumber);

            try (Connection conn = DatabaseConfig.getConnection()) {
                Login loginService = new Login();
                String userQuery = "SELECT password_hash, email FROM users WHERE account_number = ?";
                String email;
                try (PreparedStatement ps = conn.prepareStatement(userQuery)) {
                    ps.setString(1, accNumber);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            logger.warn("Account {} does not exist", accNumber);
                            return "{\"status\": \"error\", \"message\": \"Account does not exist!\"}";
                        }
                        String storedHash = rs.getString("password_hash");
                        email = rs.getString("email");
                        if (!BCrypt.checkpw(password, storedHash)) {
                            String updateAttemptsQuery = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE account_number = ?";
                            try (PreparedStatement updatePs = conn.prepareStatement(updateAttemptsQuery)) {
                                updatePs.setString(1, accNumber);
                                updatePs.executeUpdate();
                            }
                            String checkAttemptsQuery = "SELECT failed_attempts FROM users WHERE account_number = ?";
                            try (PreparedStatement checkPs = conn.prepareStatement(checkAttemptsQuery)) {
                                checkPs.setString(1, accNumber);
                                try (ResultSet rs2 = checkPs.executeQuery()) {
                                    if (rs2.next() && rs2.getInt("failed_attempts") >= 3) {
                                        String lockQuery = "UPDATE users SET lock_time = ? WHERE account_number = ?";
                                        try (PreparedStatement lockPs = conn.prepareStatement(lockQuery)) {
                                            lockPs.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
                                            lockPs.setString(2, accNumber);
                                            lockPs.executeUpdate();
                                        }
                                        logger.warn("Account {} locked due to too many failed attempts", accNumber);
                                        return "{\"status\": \"error\", \"message\": \"Account locked due to too many failed attempts!\"}";
                                    }
                                }
                            }
                            logger.warn("Incorrect password for account: {}", accNumber);
                            return "{\"status\": \"error\", \"message\": \"Incorrect password!\"}";
                        }
                    }
                }
                String otp = loginService.generateOTP();
                String updateOtpQuery = "UPDATE users SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
                try (PreparedStatement updateOtpPs = conn.prepareStatement(updateOtpQuery)) {
                    updateOtpPs.setString(1, otp);
                    updateOtpPs.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
                    updateOtpPs.setString(3, accNumber);
                    updateOtpPs.executeUpdate();
                    logger.info("Stored new OTP for account: {}", accNumber);
                }
                loginService.sendEmail(email, "Your OTP for login", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");
                logger.info("OTP sent to email: {} for account: {}", email, accNumber);
                return "{\"status\": \"success\", \"message\": \"OTP sent to your email. Please verify.\"}";
            } catch (SQLException | MessagingException e) {
                logger.error("OTP request failed for account {}: {}", accNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"OTP request failed: " + e.getMessage() + "\"}";
            }
        });

        // Login: Verify OTP (unchanged)
        Spark.post("/login/verify", (req, res) -> {
            res.type("application/json");
            String accNumber = req.queryParams("accnumber");
            String password = req.queryParams("password");
            String otp = req.queryParams("otp");
            logger.info("Login verification for account: {}", accNumber);

            try (Connection conn = DatabaseConfig.getConnection()) {
                Login loginService = new Login();
                Map<String, Object> result = loginService.verifyLogin(accNumber, password, otp, conn);
                return new JSONObject(result).toString();
            } catch (SQLException e) {
                logger.error("Login failed for account {}: {}", accNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Login failed: " + e.getMessage() + "\"}";
            } catch (MessagingException e) {
                logger.error("MessagingException during login for account {}: {}", accNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Login failed: " + e.getMessage() + "\"}";
            }
        });

        // Transfer: Request OTP (unchanged)
        Spark.post("/transfer/request-otp", (req, res) -> {
            res.type("application/json");
            String fromAccount = req.queryParams("fromAccount");
            String toAccount = req.queryParams("toAccount");
            double amount = Double.parseDouble(req.queryParams("amount"));
            logger.info("Transfer OTP request from {} to {} for amount {}", fromAccount, toAccount, amount);

            try (Connection conn = DatabaseConfig.getConnection()) {
                String balanceQuery = "SELECT balance, email FROM bank_accounts WHERE account_number = ?";
                double balance;
                String email;
                try (PreparedStatement ps = conn.prepareStatement(balanceQuery)) {
                    ps.setString(1, fromAccount);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            return "{\"status\": \"error\", \"message\": \"Sender account does not exist!\"}";
                        }
                        balance = rs.getDouble("balance");
                        email = rs.getString("email");
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement(balanceQuery)) {
                    ps.setString(1, toAccount);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            return "{\"status\": \"error\", \"message\": \"Recipient account does not exist!\"}";
                        }
                    }
                }
                if (balance < amount) {
                    return "{\"status\": \"error\", \"message\": \"Insufficient balance!\"}";
                }
                if (fromAccount.equals(toAccount)) {
                    return "{\"status\": \"error\", \"message\": \"Cannot transfer to same account!\"}";
                }
                Online_Transaction ot = new Online_Transaction(conn, fromAccount, balance, email);
                OTPService.sendOTP(fromAccount, conn);
                return "{\"status\": \"success\", \"message\": \"OTP sent to your email. Please verify.\"}";
            } catch (SQLException | MessagingException e) {
                logger.error("Transfer OTP request failed: {}", e.getMessage());
                return "{\"status\": \"error\", \"message\": \"OTP request failed: " + e.getMessage() + "\"}";
            }
        });

        // Transfer: Verify and Execute (unchanged)
        Spark.post("/transfer", (req, res) -> {
            res.type("application/json");
            String fromAccount = req.queryParams("fromAccount");
            String toAccount = req.queryParams("toAccount");
            double amount = Double.parseDouble(req.queryParams("amount"));
            String otp = req.queryParams("otp");
            logger.info("Transfer attempt from {} to {} for amount {}", fromAccount, toAccount, amount);

            try (Connection conn = DatabaseConfig.getConnection()) {
                String balanceQuery = "SELECT balance, email FROM bank_accounts WHERE account_number = ?";
                double balance;
                String email;
                try (PreparedStatement ps = conn.prepareStatement(balanceQuery)) {
                    ps.setString(1, fromAccount);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            return "{\"status\": \"error\", \"message\": \"Sender account does not exist!\"}";
                        }
                        balance = rs.getDouble("balance");
                        email = rs.getString("email");
                    }
                }
                Online_Transaction ot = new Online_Transaction(conn, fromAccount, balance, email);
                ot.fundTransfer(toAccount, amount, otp, conn);
                return "{\"status\": \"success\", \"message\": \"Transfer successful\"}";
            } catch (SQLException | MessagingException e) {
                logger.error("Transfer failed: {}", e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Transfer failed: " + e.getMessage() + "\"}";
            }
        });

        // Send Statement via Email (unchanged)
        Spark.post("/send-statement", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            int month = Integer.parseInt(req.queryParams("month"));
            int year = Integer.parseInt(req.queryParams("year"));
            logger.info("Request to send statement for account: {}, month: {}, year: {}", accountNumber, month, year);

            try (Connection conn = DatabaseConfig.getConnection()) {
                String balanceQuery = "SELECT balance, email FROM bank_accounts WHERE account_number = ?";
                double balance;
                String email;
                try (PreparedStatement ps = conn.prepareStatement(balanceQuery)) {
                    ps.setString(1, accountNumber);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            return "{\"status\": \"error\", \"message\": \"Account does not exist!\"}";
                        }
                        balance = rs.getDouble("balance");
                        email = rs.getString("email");
                    }
                }
                String pdfFilePath = PDFStatementGenerator.generatePDFStatement(accountNumber, month, year, conn);
                PDFStatementGenerator.sendEmailWithPDF(email, pdfFilePath);
                return "{\"status\": \"success\", \"message\": \"Statement sent to your email.\"}";
            } catch (SQLException e) {
                logger.error("Failed to generate statement for account {}: {}", accountNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Failed to generate statement: " + e.getMessage() + "\"}";
            } catch (IOException | MessagingException e) {
                logger.error("Failed to send statement for account {}: {}", accountNumber, e.getClass());
                return "{\"status\": \"error\", \"message\": \"Failed to send statement: " + e.getClass() + "\"}";
            }
        });

        // Forgot Password: Request OTP (new)
        Spark.post("/forgot-password/request-otp", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String phoneNumber = req.queryParams("phoneNumber");
            String securityAnswer = req.queryParams("securityAnswer");
            logger.info("Forgot password OTP request for account: {}", accountNumber);

            try (Connection conn = DatabaseConfig.getConnection()) {
                Registration registration = new Registration();
                // Trigger OTP generation without resetting password yet
                String query = "SELECT phone, security_answer_hash FROM users WHERE account_number = ?";
                String registeredPhone;
                String hashedAnswer;

                try (PreparedStatement ps = conn.prepareStatement(query)) {
                    ps.setString(1, accountNumber);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            logger.warn("Account number not found: {}", accountNumber);
                            return "{\"status\": \"error\", \"message\": \"Account number not found!\"}";
                        }
                        registeredPhone = rs.getString("phone");
                        hashedAnswer = rs.getString("security_answer_hash");
                        if (!BCrypt.checkpw(securityAnswer, hashedAnswer)) {
                            logger.warn("Incorrect security answer for account: {}", accountNumber);
                            return "{\"status\": \"error\", \"message\": \"Incorrect security answer!\"}";
                        }
                        if (!registeredPhone.equals(phoneNumber)) {
                            logger.warn("Incorrect phone number for account: {}", accountNumber);
                            return "{\"status\": \"error\", \"message\": \"Incorrect phone number!\"}";
                        }
                    }
                }
                OTPService.sendOTP(accountNumber, conn);
                logger.info("OTP sent for forgot password to account: {}", accountNumber);
                return "{\"status\": \"success\", \"message\": \"OTP sent to your email. Please verify.\"}";
            } catch (SQLException | MessagingException e) {
                logger.error("Forgot password OTP request failed for account {}: {}", accountNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"OTP request failed: " + e.getMessage() + "\"}";
            }
        });

        // Forgot Password: Reset Password (new)
        Spark.post("/forgot-password/reset", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String phoneNumber = req.queryParams("phoneNumber");
            String securityAnswer = req.queryParams("securityAnswer");
            String userOtp = req.queryParams("otp");
            String newPassword1 = req.queryParams("newPassword1");
            String newPassword2 = req.queryParams("newPassword2");
            logger.info("Forgot password reset attempt for account: {}", accountNumber);

            try (Connection conn = DatabaseConfig.getConnection()) {
                Registration registration = new Registration();
                registration.forgotPassword(accountNumber, phoneNumber, securityAnswer, userOtp, newPassword1, newPassword2, conn);
                return "{\"status\": \"success\", \"message\": \"Password reset successful\"}";
            } catch (SQLException e) {
                logger.error("Forgot password reset failed for account {}: {}", accountNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Reset failed: " + e.getMessage() + "\"}";
            } catch (MessagingException e) {
                logger.error("MessagingException during forgot password reset for account {}: {}", accountNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"Reset failed: " + e.getMessage() + "\"}";
            } catch (IllegalArgumentException e) {
                logger.error("Invalid input during forgot password reset for account {}: {}", accountNumber, e.getMessage());
                return "{\"status\": \"error\", \"message\": \"" + e.getMessage() + "\"}";
            }
        });
    }
}