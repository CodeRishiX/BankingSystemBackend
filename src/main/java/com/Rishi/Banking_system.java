package com.Rishi;

import org.mindrot.jbcrypt.BCrypt;
import spark.Spark;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import java.io.IOException;
import java.sql.*;
import java.util.Calendar;
import java.util.Map;
import java.util.HashMap;
import org.json.JSONObject;
import org.json.JSONException;
import com.google.gson.Gson;

import javax.mail.MessagingException;

public class Banking_system {
    private static final Logger logger = LogManager.getLogger(Banking_system.class);

    private static String successResponse(String message) {
        return new JSONObject()
                .put("status", "success")
                .put("message", message)
                .toString();
    }

    private static String errorResponse(String message) {
        return new JSONObject()
                .put("status", "error")
                .put("message", message)
                .toString();
    }

    private static String getAccountEmail(Connection conn, String accountNumber) throws SQLException {
        String query = "SELECT email FROM bank_accounts WHERE account_number = ?";
        try (PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("email") : null;
            }
        }
    }

    public static void main(String[] args) {
        Spark.port(8080);
        logger.info("Database connected successfully!");
        logger.info("Banking System server started on port 8080");

        Spark.get("/", (req, res) -> "Banking System is running on port 8080!");

        // Registration Initiation (Request OTP)
        Spark.post("/register/init", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String email = req.queryParams("email");

            try (Connection conn = DatabaseConfig.getConnection()) {
                String checkQuery = "SELECT email FROM bank_accounts WHERE account_number = ?";
                String storedEmail = null;
                try (PreparedStatement ps = conn.prepareStatement(checkQuery)) {
                    ps.setString(1, accountNumber);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            return errorResponse("Account not found in our records");
                        }
                        storedEmail = rs.getString("email");
                    }
                }
                if (!email.equals(storedEmail)) {
                    return errorResponse("Email does not match the registered email for this account");
                }
                OTPService.sendOTP(accountNumber, email, conn);
                return successResponse("OTP sent to your email");
            } catch (SQLException | MessagingException e) {
                logger.error("Registration initiation failed: {}", e.getMessage());
                return errorResponse("Failed to send OTP: " + e.getMessage());
            }
        });

        // Registration Completion (Verify OTP and Create Account)
        Spark.post("/register/complete", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String otp = req.queryParams("otp");
            int securityQuestionChoice = Integer.parseInt(req.queryParams("securityQuestionChoice"));
            String securityAnswer = req.queryParams("securityAnswer");
            String password1 = req.queryParams("password1");
            String password2 = req.queryParams("password2");
            String email = req.queryParams("email");

            Registration registration = new Registration();
            try (Connection conn = DatabaseConfig.getConnection()) {
                registration.reg(accountNumber, otp, securityQuestionChoice, securityAnswer,
                        password1, password2, email, conn);
                return successResponse("Registration successful");
            } catch (SQLException | MessagingException e) {
                logger.error("Registration failed: {}", e.getMessage());
                return errorResponse("Registration failed: " + e.getMessage());
            } catch (IllegalArgumentException e) {
                return errorResponse(e.getMessage());
            }
        });

        // Login: Request OTP
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
                            return errorResponse("Account does not exist!");
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
                                        return errorResponse("Account locked due to too many failed attempts!");
                                    }
                                }
                            }
                            logger.warn("Incorrect password for account: {}", accNumber);
                            return errorResponse("Incorrect password!");
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
                return successResponse("OTP sent to your email. Please verify.");
            } catch (SQLException | MessagingException e) {
                logger.error("OTP request failed for account {}: {}", accNumber, e.getMessage());
                return errorResponse("OTP request failed: " + e.getMessage());
            }
        });

        // Login: Verify OTP
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
                return errorResponse("Login failed: " + e.getMessage());
            } catch (MessagingException e) {
                logger.error("MessagingException during login for account {}: {}", accNumber, e.getMessage());
                return errorResponse("Login failed: " + e.getMessage());
            }
        });

        // Transfer: Request OTP
        Spark.post("/transfer/request-otp", (req, res) -> {
            res.type("application/json");
            String fromAccount = req.queryParams("fromAccount");
            String toAccount = req.queryParams("toAccount");
            double amount;
            try {
                amount = Double.parseDouble(req.queryParams("amount"));
            } catch (NumberFormatException e) {
                return errorResponse("Invalid amount format");
            }

            logger.info("Requesting OTP for transfer: {} -> {}, Amount: {}", fromAccount, toAccount, amount);

            try (Connection conn = DatabaseConfig.getConnection()) {
                TransferService transferService = new TransferService();

                // Validate sender account
                if (!transferService.accountExists(fromAccount, conn)) {
                    logger.error("Sender account not found: {}", fromAccount);
                    return errorResponse("Sender account not found");
                }

                // Validate recipient account
                if (!transferService.accountExists(toAccount, conn)) {
                    logger.error("Recipient account not found: {}", toAccount);
                    return errorResponse("Recipient account not found");
                }

                // Additional validation (same account check)
                if (fromAccount.equals(toAccount)) {
                    logger.error("Cannot transfer to the same account: {}", fromAccount);
                    return errorResponse("Cannot transfer to the same account");
                }

                // Validate amount
                if (amount <= 0) {
                    logger.error("Invalid amount: {}", amount);
                    return errorResponse("Amount must be positive");
                }
                double senderBalance = transferService.getAccountBalance(fromAccount, conn);
                if (senderBalance < amount) {
                    logger.error("Insufficient funds in sender account {}: Balance {}, Requested {}", fromAccount, senderBalance, amount);
                    return errorResponse("Insufficient funds");
                }

                // Generate and store OTP
                String otp = new Login().generateOTP(); // Using Login's OTP generation
                String updateOtpQuery = "UPDATE users SET otp = ?, otp_timestamp = CURRENT_TIMESTAMP WHERE account_number = ?";
                try (PreparedStatement ps = conn.prepareStatement(updateOtpQuery)) {
                    ps.setString(1, otp);
                    ps.setString(2, fromAccount);
                    int rowsUpdated = ps.executeUpdate();
                    if (rowsUpdated == 0) {
                        logger.error("Failed to store OTP for account: {}", fromAccount);
                        return errorResponse("Failed to generate OTP");
                    }
                }

                // Send OTP
                String senderEmail = transferService.getAccountEmail(fromAccount, conn);
                new Login().sendEmail(senderEmail, "Transfer OTP", "Your OTP for transferring ₹" + amount + " to account " + toAccount + " is: " + otp);

                logger.info("OTP sent successfully to {} for transfer from {} to {}", senderEmail, fromAccount, toAccount);
                return successResponse("OTP sent to registered email");
            } catch (SQLException e) {
                logger.error("Database error in transfer/request-otp: {}", e.getMessage());
                return errorResponse("Database error: " + e.getMessage());
            } catch (MessagingException e) {
                logger.error("Failed to send OTP email: {}", e.getMessage());
                return errorResponse("Failed to send OTP: " + e.getMessage());
            }
        });

        // Transfer: Verify and Execute
        Spark.post("/transfer", (req, res) -> {
            res.type("application/json");

            try {
                JSONObject json = new JSONObject(req.body());

                String fromAccount = json.getString("fromAccount");
                String toAccount = json.getString("toAccount");
                double amount = json.getDouble("amount");
                String otp = json.getString("otp");
                String token = req.headers("Authorization");

                if (token == null || !token.startsWith("Bearer ")) {
                    res.status(401);
                    return errorResponse("Authorization token required");
                }
                token = token.substring(7);

                logger.info("Transfer attempt from {} to {} for amount {}", fromAccount, toAccount, amount);

                try (Connection conn = DatabaseConfig.getConnection()) {
                    TransferService transferService = new TransferService();
                    transferService.transferFunds(fromAccount, toAccount, amount, otp, token, conn);
                    return successResponse("Transfer successful");
                } catch (SQLException | MessagingException e) {
                    res.status(500);
                    logger.error("Transfer failed: {}", e.getMessage());
                    return errorResponse(e.getMessage().replace("\"", "'"));
                } catch (IllegalArgumentException e) {
                    res.status(400);
                    return errorResponse(e.getMessage().replace("\"", "'"));
                }
            } catch (JSONException e) {
                res.status(400);
                return errorResponse("Invalid request format");
            } catch (Exception e) {
                res.status(500);
                logger.error("Unexpected error in transfer: {}", e.getMessage());
                return errorResponse("Internal server error");
            }
        });

        // Send Statement via Email
        Spark.post("/send-statement", (req, res) -> {
            res.type("application/json");
            try {
                String authHeader = req.headers("Authorization");
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    res.status(401);
                    return errorResponse("Authorization token required");
                }
                String token = authHeader.substring(7);

                String accountNumber = req.queryParams("accountNumber");
                int month = Integer.parseInt(req.queryParams("month"));
                int year = Integer.parseInt(req.queryParams("year"));

                logger.info("Generating statement for account: {}, month: {}, year: {}",
                        accountNumber, month, year);

                if (month < 1 || month > 12) {
                    return errorResponse("Invalid month (1-12)");
                }
                if (year < 2000 || year > Calendar.getInstance().get(Calendar.YEAR) + 1) {
                    return errorResponse("Invalid year");
                }

                try (Connection conn = DatabaseConfig.getConnection()) {
                    String tokenCheckQuery = "SELECT account_number FROM user_sessions WHERE token = ? AND expires_at > NOW()";
                    try (PreparedStatement ps = conn.prepareStatement(tokenCheckQuery)) {
                        ps.setString(1, token);
                        ResultSet rs = ps.executeQuery();
                        if (!rs.next() || !rs.getString("account_number").equals(accountNumber)) {
                            res.status(403);
                            return errorResponse("Unauthorized access");
                        }
                    }

                    conn.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);

                    String email = getAccountEmail(conn, accountNumber);
                    if (email == null) {
                        return errorResponse("Account not found");
                    }

                    String pdfFilePath = PDFStatementGenerator.generatePDFStatement(
                            accountNumber,
                            month,
                            year,
                            conn
                    );

                    PDFStatementGenerator.sendEmailWithPDF(email, pdfFilePath);

                    return successResponse("Statement sent to " + email);

                } catch (SQLException e) {
                    logger.error("Database error generating statement for {}: {}", accountNumber, e.getMessage());
                    return errorResponse("Database error generating statement");
                } catch (IOException e) {
                    logger.error("File error generating statement for {}: {}", accountNumber, e.getMessage());
                    return errorResponse("Error creating PDF file");
                } catch (MessagingException e) {
                    logger.error("Email error for {}: {}", accountNumber, e.getMessage());
                    return errorResponse("Error sending email");
                }
            } catch (NumberFormatException e) {
                return errorResponse("Invalid month/year format");
            } catch (Exception e) {
                logger.error("Unexpected error in send-statement: {}", e.getMessage());
                return errorResponse("Internal server error");
            }
        });

        // ===== FORGOT PASSWORD ENDPOINTS ===== //

        // Step 1: Get Security Question (Updated with phone number verification)
        Spark.get("/get-security-question", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String phoneNumber = req.queryParams("phoneNumber");
            try (Connection conn = DatabaseConfig.getConnection()) {
                Registration registration = new Registration();
                Map<String, String> result = registration.getSecurityQuestionAndHash(accountNumber, phoneNumber, conn);
                return new Gson().toJson(result);
            } catch (SQLException e) {
                logger.error("Error getting security question: {}", e.getMessage());
                res.status(404);
                return errorResponse("Account not found or phone number mismatch");
            }
        });

        // Step 2: Verify Security Answer and Request OTP (Updated with new method)
        Spark.post("/verify-security-answer", (req, res) -> {
            res.type("application/json");
            try {
                JSONObject json = new JSONObject(req.body());
                String accountNumber = json.getString("accountNumber");
                String answer = json.getString("answer");

                try (Connection conn = DatabaseConfig.getConnection()) {
                    Registration registration = new Registration();
                    registration.verifySecurityAnswerAndGenerateOtp(accountNumber, answer, conn);
                    return successResponse("OTP sent to registered email"); // Updated message
                }
            } catch (SQLException e) {
                logger.error("Database error during verification: {}", e.getMessage());
                res.status(404);
                return errorResponse("Account not found");
            } catch (MessagingException e) {
                logger.error("Error sending OTP: {}", e.getMessage());
                res.status(500);
                return errorResponse("OTP sending failed");
            } catch (IllegalArgumentException e) {
                logger.error("Invalid security answer for account: {}", e.getMessage());
                res.status(400);
                return errorResponse(e.getMessage());
            } catch (JSONException e) {
                logger.error("Invalid request format: {}", e.getMessage());
                res.status(400);
                return errorResponse("Invalid request format");
            }
        });

        // Step 3: Reset Password (Updated with new method)
        Spark.post("/reset-password", (req, res) -> {
            res.type("application/json");
            try {
                JSONObject json;
                try {
                    json = new JSONObject(req.body());
                } catch (JSONException e) {
                    logger.error("Invalid JSON format: {}", req.body());
                    res.status(400);
                    return errorResponse("Invalid request format");
                }

                String accountNumber = json.getString("accountNumber");
                String otp = json.getString("otp");
                String newPassword = json.getString("newPassword");

                try (Connection conn = DatabaseConfig.getConnection()) {
                    Registration registration = new Registration();
                    registration.resetPassword(accountNumber, otp, newPassword, conn);
                    // Invalidate existing sessions
                    String invalidateSessionQuery = "DELETE FROM user_sessions WHERE account_number = ?";
                    try (PreparedStatement ps = conn.prepareStatement(invalidateSessionQuery)) {
                        ps.setString(1, accountNumber);
                        ps.executeUpdate();
                    }
                    logger.info("Password reset completed for account: {}", accountNumber);
                    return successResponse("Password updated successfully");
                }
            } catch (SQLException e) {
                logger.error("Database error during password reset: {}", e.getMessage());
                res.status(500);
                return errorResponse("Reset failed: " + e.getMessage());
            } catch (IllegalArgumentException e) {
                logger.error("Invalid input during password reset: {}", e.getMessage());
                res.status(400);
                return errorResponse(e.getMessage());
            } catch (JSONException e) {
                logger.error("JSON parsing error: {}", e.getMessage());
                res.status(400);
                return errorResponse("Invalid request format");
            }
        });

        // Original Forgot Password Endpoints (maintained for backward compatibility)
        Spark.post("/forgot-password/request-otp", (req, res) -> {
            res.type("application/json");
            String accountNumber = req.queryParams("accountNumber");
            String phoneNumber = req.queryParams("phoneNumber");
            String securityAnswer = req.queryParams("securityAnswer");
            logger.info("Forgot password OTP request for account: {}", accountNumber);

            try (Connection conn = DatabaseConfig.getConnection()) {
                Registration registration = new Registration();
                String query = "SELECT phone, security_answer_hash FROM users WHERE account_number = ?";
                String registeredPhone;
                String hashedAnswer;

                try (PreparedStatement ps = conn.prepareStatement(query)) {
                    ps.setString(1, accountNumber);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            logger.warn("Account number not found: {}", accountNumber);
                            return errorResponse("Account number not found!");
                        }
                        registeredPhone = rs.getString("phone");
                        hashedAnswer = rs.getString("security_answer_hash");
                        if (!BCrypt.checkpw(securityAnswer, hashedAnswer)) {
                            logger.warn("Incorrect security answer for account: {}", accountNumber);
                            return errorResponse("Incorrect security answer!");
                        }
                        if (!registeredPhone.equals(phoneNumber)) {
                            logger.warn("Incorrect phone number for account: {}", accountNumber);
                            return errorResponse("Incorrect phone number!");
                        }
                    }
                }
                OTPService.sendOTP(accountNumber, conn);
                logger.info("OTP sent for forgot password to account: {}", accountNumber);
                return successResponse("OTP sent to your email. Please verify.");
            } catch (SQLException | MessagingException e) {
                logger.error("Forgot password OTP request failed for account {}: {}", accountNumber, e.getMessage());
                return errorResponse("OTP request failed: " + e.getMessage());
            }
        });

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
                return successResponse("Password reset successful");
            } catch (SQLException e) {
                logger.error("Forgot password reset failed for account {}: {}", accountNumber, e.getMessage());
                return errorResponse("Reset failed: " + e.getMessage());
            } catch (MessagingException e) {
                logger.error("MessagingException during forgot password reset for account {}: {}", accountNumber, e.getMessage());
                return errorResponse("Reset failed: " + e.getMessage());
            } catch (IllegalArgumentException e) {
                logger.error("Invalid input during forgot password reset for account {}: {}", accountNumber, e.getMessage());
                return errorResponse(e.getMessage());
            }
        });
        // Get Transaction History (Live Display)
        Spark.get("/get-transaction-history", (req, res) -> {
            res.type("application/json");
            try {
                String authHeader = req.headers("Authorization");
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    res.status(401);
                    return errorResponse("Authorization token required");
                }
                String token = authHeader.substring(7);

                String accountNumber = req.queryParams("accountNumber");

                logger.info("Fetching transaction history for account: {}", accountNumber);

                try (Connection conn = DatabaseConfig.getConnection()) {
                    String tokenCheckQuery = "SELECT account_number FROM user_sessions WHERE token = ? AND expires_at > NOW()";
                    try (PreparedStatement ps = conn.prepareStatement(tokenCheckQuery)) {
                        ps.setString(1, token);
                        ResultSet rs = ps.executeQuery();
                        if (!rs.next() || !rs.getString("account_number").equals(accountNumber)) {
                            res.status(403);
                            return errorResponse("Unauthorized access");
                        }
                    }

                    Registration registration = new Registration(); // Assuming displayTransactionHistory is moved here
                    String history = registration.displayTransactionHistory(accountNumber, conn);
                    Map<String, String> responseMap = new HashMap<>();
                    responseMap.put("history", history);
                    return new Gson().toJson(responseMap);
                } catch (SQLException e) {
                    logger.error("Database error fetching transaction history for {}: {}", accountNumber, e.getMessage());
                    res.status(500);
                    return errorResponse("Database error fetching transaction history");
                }
            } catch (Exception e) {
                logger.error("Unexpected error in get-transaction-history: {}", e.getMessage());
                res.status(500);
                return errorResponse("Internal server error");
            }
        });
    }
}