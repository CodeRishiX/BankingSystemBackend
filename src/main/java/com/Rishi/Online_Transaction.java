package com.Rishi;

import java.util.*;
import java.sql.*;
import java.util.Properties;
import java.util.Random;
import javax.mail.*;
import javax.mail.internet.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Online_Transaction extends Login {
    private static final Logger logger = LogManager.getLogger(Online_Transaction.class);

    private Connection connection;
    private Scanner scanner;
    private String accnumber;
    private double balance;
    private String email;

    public Online_Transaction(Connection connection, Scanner scanner, String accnumber, double balance, String email) {
        this.connection = connection;
        this.scanner = scanner;
        this.accnumber = accnumber;
        this.balance = balance;
        this.email = email;
    }

    public void fundTransfer(String receiverAccount, double amount, Connection con, Scanner sc) {
        try {
            con.setAutoCommit(false); // Start transaction

            // Step 1: Check if Receiver Exists Before Proceeding
            String checkReceiverQuery = "SELECT balance, email FROM bank_accounts WHERE account_number = ?";
            try (PreparedStatement checkReceiverPs = con.prepareStatement(checkReceiverQuery)) {
                checkReceiverPs.setString(1, receiverAccount);
                try (ResultSet receiverRs = checkReceiverPs.executeQuery()) {
                    if (!receiverRs.next()) {  // If receiver doesn't exist, stop transaction
                        logger.error("Recipient account not found! Transaction cancelled.");
                        return;
                    }
                    if (accnumber.equals(receiverAccount)) {
                        logger.error(accnumber + " Transaction cancelled! --> Trying to transfer in own account (( SELF TRANSFER))");
                        System.out.println("Cannot transfer to same account --😬😬😬");
                        return;
                    }

                    // Receiver exists, fetch their email and current balance
                    String recipientEmail = receiverRs.getString("email");
                    double receiverOldBalance = receiverRs.getDouble("balance");

                    // Step 2: Fetch sender's balance
                    String query = "SELECT balance FROM bank_accounts WHERE account_number = ?";
                    try (PreparedStatement ps = con.prepareStatement(query)) {
                        ps.setString(1, accnumber);
                        try (ResultSet rs = ps.executeQuery()) {
                            if (rs.next()) {
                                double senderOldBalance = rs.getDouble("balance");
                                logger.info("💰 Your current balance: {}", senderOldBalance);

                                // Step 3: Ask for amount AFTER showing balance
                                logger.info("Enter the amount you want to transfer: ");
                                amount = sc.nextDouble();
                                sc.nextLine(); // Consume newline

                                // Added Validation for Negative or Zero Amount
                                if (amount <= 0) {
                                    logger.error("Invalid transfer amount: {}. Amount must be greater than 0.", amount);
                                    System.out.println("❌ Invalid amount! Please enter a positive value.");
                                    return;
                                }

                                // CALL FRAUD DETECTION API
                                boolean isFraud = FraudDetectionService.isTransactionFraudulent(
                                        amount, senderOldBalance, senderOldBalance - amount,
                                        receiverOldBalance, receiverOldBalance + amount, "Fund Transfer"
                                );

                                if (isFraud) {
                                    logger.error("🚨 Transaction Blocked: Fraud Detected!");
                                    String insertFraudQuery = "INSERT INTO transactions(sender_account, receiver_account, amount, transaction_type, status, oldbalanceOrg, oldbalanceDest, is_fraud) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                                    try (PreparedStatement psFraud = con.prepareStatement(insertFraudQuery, Statement.RETURN_GENERATED_KEYS)) {
                                        psFraud.setString(1, accnumber);
                                        psFraud.setString(2, receiverAccount);
                                        psFraud.setDouble(3, amount);
                                        psFraud.setString(4, "Fund Transfer");
                                        psFraud.setString(5, "Failed"); // Changed to "Failed"
                                        psFraud.setDouble(6, senderOldBalance);
                                        psFraud.setDouble(7, receiverOldBalance);
                                        psFraud.setInt(8, 1); // is_fraud = 1 for fraudulent
                                        int rowsAffected = psFraud.executeUpdate();

                                        if (rowsAffected > 0) {
                                            try (ResultSet generatedKeys = psFraud.getGeneratedKeys()) {
                                                if (generatedKeys.next()) {
                                                    int transactionId = generatedKeys.getInt(1);
                                                    logger.info("📌 Fraudulent Transaction ID: {}", transactionId);
                                                    con.commit(); // Commit the fraud record
                                                }
                                            }
                                        } else {
                                            logger.error("Failed to insert fraudulent transaction record.");
                                        }
                                    }
                                    return; // Exit after logging fraud
                                }

                                if (senderOldBalance < amount) {
                                    logger.error("Not sufficient funds available to transfer money.");
                                    return;
                                }

                                // Step 4: OTP Verification
                                OTPService.sendOTP(accnumber, con);
                                logger.info("Enter the OTP received on your email: ");
                                String userOtp = sc.nextLine();
                                if (!OTPService.verifyOTP(accnumber, userOtp, con)) {
                                    logger.error("Incorrect or expired OTP! Transaction cancelled.");
                                    return;
                                }
                                logger.info("OTP Verified Successfully!");
                                logger.info("Login Successful!");

                                // Calculate new balances
                                double senderNewBalance = senderOldBalance - amount;
                                double receiverNewBalance = receiverOldBalance + amount;

                                // Step 5: Update sender's account balance
                                String deductQuery = "UPDATE bank_accounts SET balance = ? WHERE account_number = ?";
                                try (PreparedStatement psDeduct = con.prepareStatement(deductQuery)) {
                                    psDeduct.setDouble(1, senderNewBalance);
                                    psDeduct.setString(2, accnumber);
                                    psDeduct.executeUpdate();
                                }

                                // Step 6: Update receiver's account balance
                                String addQuery = "UPDATE bank_accounts SET balance = ? WHERE account_number = ?";
                                try (PreparedStatement psAdd = con.prepareStatement(addQuery)) {
                                    psAdd.setDouble(1, receiverNewBalance);
                                    psAdd.setString(2, receiverAccount);
                                    psAdd.executeUpdate();
                                }

                                // Commit the balance updates
                                con.commit();

                                // Step 7: Insert successful transaction record
                                String insertQuery = "INSERT INTO transactions(sender_account, receiver_account, amount, transaction_type, status, oldbalanceOrg, newbalanceOrig, oldbalanceDest, newbalanceDest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                                try (PreparedStatement psSuccess = con.prepareStatement(insertQuery, Statement.RETURN_GENERATED_KEYS)) {
                                    psSuccess.setString(1, accnumber);
                                    psSuccess.setString(2, receiverAccount);
                                    psSuccess.setDouble(3, amount);
                                    psSuccess.setString(4, "Fund Transfer");
                                    psSuccess.setString(5, "Completed");
                                    psSuccess.setDouble(6, senderOldBalance);
                                    psSuccess.setDouble(7, senderNewBalance);
                                    psSuccess.setDouble(8, receiverOldBalance);
                                    psSuccess.setDouble(9, receiverNewBalance);
                                    int rowsAffected = psSuccess.executeUpdate();

                                    if (rowsAffected > 0) {
                                        try (ResultSet generatedKeys = psSuccess.getGeneratedKeys()) {
                                            if (generatedKeys.next()) {
                                                int transactionId = generatedKeys.getInt(1);
                                                logger.info("📌 Transaction ID: {}", transactionId);
                                                String updateOtpQuery = "UPDATE transactions SET otp_verified = 1 WHERE id = ?";
                                                try (PreparedStatement psOtp = con.prepareStatement(updateOtpQuery)) {
                                                    psOtp.setInt(1, transactionId);
                                                    psOtp.executeUpdate();
                                                    con.commit(); // Commit OTP verification
                                                    logger.info("OTP verification updated in transaction.");
                                                }
                                            }
                                        }
                                    } else {
                                        logger.error("Failed to insert successful transaction record.");
                                    }
                                }

                                // Final: Notify user and send email alerts
                                logger.info("Money Transferred Successfully!");
                                logger.info("Your current balance is {}", senderNewBalance);

                                // Send alert to sender
                                sendalert(this.email, amount, receiverAccount, "Fund Transfer", senderNewBalance, "sender");
                                // Send alert to receiver
                                sendalert(recipientEmail, amount, accnumber, "Fund Transfer", receiverNewBalance, "receiver");
                            } else {
                                logger.error("Your account number does not exist, please try again.");
                            }
                        }
                    }
                }
            }
        } catch (SQLException e) {
            try {
                con.rollback(); // Rollback if any error occurs
                logger.error("Transaction failed. Rolled back changes.");
            } catch (SQLException rollbackEx) {
                logger.error("Rollback failed: {}", rollbackEx.getMessage(), rollbackEx);
            }
            logger.error("SQLException in fundTransfer: {}", e.getMessage(), e);
        } finally {
            try {
                con.setAutoCommit(true); // Restore default behavior
            } catch (SQLException ex) {
                logger.error("Failed to restore auto-commit: {}", ex.getMessage(), ex);
                System.out.println("❌ Failed to reset auto-commit.");
            }
        }
    }

    public void displayTransactionHistory(String accnumber, Connection con) {
        String query = "SELECT id, sender_account, receiver_account, transaction_type, amount, timestamp, status, is_fraud " +
                "FROM transactions " +
                "WHERE sender_account = ? OR receiver_account = ? " +
                "ORDER BY timestamp DESC";

        try (PreparedStatement pstmt = con.prepareStatement(query)) {
            pstmt.setString(1, accnumber);
            pstmt.setString(2, accnumber);
            try (ResultSet rs = pstmt.executeQuery()) {
                logger.info("Transaction History:");
                logger.info(String.format("%-15s %-19s %-19s %-20s %-10s %-15s %-20s %-12s",
                        "Transaction ID", "Sender", "Receiver", "Transaction Type", "Type", "Amount", "Date", "Status"));
                logger.info("-----------------------------------------------------------------------------------------------------");

                while (rs.next()) {
                    int transactionID = rs.getInt("id");
                    String sender = rs.getString("sender_account");
                    String receiver = rs.getString("receiver_account");
                    String transactionType = rs.getString("transaction_type");
                    double amount = rs.getDouble("amount");
                    String timestamp = rs.getString("timestamp");
                    String status = rs.getString("status");
                    int isFraud = rs.getInt("is_fraud");

                    // Determine if it's a Debit or Credit
                    String type = sender.equals(accnumber) ? "Debit" : "Credit";

                    logger.info(String.format("%-15d %-19s %-19s %-20s %-10s %-15.2f %-20s %-12s",
                            transactionID, sender, receiver, transactionType, type, amount, timestamp, status + (isFraud == 1 ? " (Fraud)" : "")));
                }
            }
        } catch (SQLException e) {
            logger.error("Error displaying transaction history: {}", e.getMessage(), e);
        }
    }

    public static String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    public static void sendEmail(String recipientEmail, String subject, String messageBody) {
        final String senderEmail = "saltlakesisco@gmail.com";
        final String senderPassword = "wgdl tlfz jmhf itrh";

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(senderEmail, senderPassword);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail));
            message.setSubject(subject);
            message.setText(messageBody);

            Transport.send(message);
            logger.info("Email sent successfully to {}", recipientEmail);
        } catch (MessagingException e) {
            logger.error("Failed to send email: {}", e.getMessage(), e);
        }
    }

    public static void sendalert(String recipientEmail, double amount, String otherParty, String type, double newBalance, String role) {
        final String senderEmail = "saltlakesisco@gmail.com";
        final String senderPassword = "wgdl tlfz jmhf itrh";

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(senderEmail, senderPassword);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail));

            String subject, emailBody;
            if (role.equals("sender")) {
                subject = "🚨 Transaction Alert - You Sent Money";
                emailBody = "Dear Customer,\n\n"
                        + "You have successfully transferred ₹" + amount + " to account " + otherParty + ".\n"
                        + "Transaction Type: " + type + "\n"
                        + "Date: " + new java.util.Date() + "\n"
                        + "New Balance: ₹" + newBalance + "\n\n"
                        + "If this transaction was not authorized by you, please contact customer support immediately.\n\n"
                        + "Best Regards,\n Jay Shree Ram";
            } else {
                subject = " Transaction Alert - You Received Money";
                emailBody = "Dear Customer,\n\n"
                        + "You have received ₹" + amount + " from account " + otherParty + ".\n"
                        + "Transaction Type: " + type + "\n"
                        + "Date: " + new java.util.Date() + "\n"
                        + "New Balance: ₹" + newBalance + "\n\n"
                        + "If this transaction was not expected, please contact customer support immediately.\n\n"
                        + "Best Regards,\n Jay shree Ram";
            }

            message.setSubject(subject);
            message.setText(emailBody);
            Transport.send(message);

            logger.info("Transaction alert sent to {}", recipientEmail);
        } catch (MessagingException e) {
            logger.error("Failed to send transaction alert: {}", e.getMessage(), e);
        }
    }
}