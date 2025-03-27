package com.Rishi;

import java.sql.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.mail.MessagingException;

public class Online_Transaction extends Login {
    private static final Logger logger = LogManager.getLogger(Online_Transaction.class);

    private Connection connection;
    private String accnumber;
    private double balance;
    private String email;

    public Online_Transaction(Connection connection, String accnumber, double balance, String email) {
        this.connection = connection;
        this.accnumber = accnumber;
        this.balance = balance;
        this.email = email;
    }

    public void fundTransfer(String receiverAccount, double amount, String userOtp, Connection con) throws SQLException, MessagingException {
        try {
            con.setAutoCommit(false);

            String checkReceiverQuery = "SELECT balance, email FROM bank_accounts WHERE account_number = ?";
            try (PreparedStatement checkReceiverPs = con.prepareStatement(checkReceiverQuery)) {
                checkReceiverPs.setString(1, receiverAccount);
                try (ResultSet receiverRs = checkReceiverPs.executeQuery()) {
                    if (!receiverRs.next()) {
                        logger.error("Recipient account not found! Transaction cancelled for account: {}", accnumber);
                        throw new SQLException("Recipient account not found! Transaction cancelled.");
                    }
                    if (accnumber.equals(receiverAccount)) {
                        logger.error("{} Transaction cancelled! --> Trying to transfer in own account", accnumber);
                        throw new SQLException("Cannot transfer to same account.");
                    }

                    String recipientEmail = receiverRs.getString("email");
                    double receiverOldBalance = receiverRs.getDouble("balance");

                    String query = "SELECT balance FROM bank_accounts WHERE account_number = ?";
                    double senderOldBalance;
                    try (PreparedStatement ps = con.prepareStatement(query)) {
                        ps.setString(1, accnumber);
                        try (ResultSet rs = ps.executeQuery()) {
                            if (rs.next()) {
                                senderOldBalance = rs.getDouble("balance");
                                logger.info("💰 Sender's current balance: {} for account: {}", senderOldBalance, accnumber);
                            } else {
                                logger.error("Your account number does not exist, please try again for account: {}", accnumber);
                                throw new SQLException("Your account number does not exist, please try again.");
                            }
                        }
                    }

                    if (amount <= 0) {
                        logger.error("Invalid transfer amount: {}. Amount must be greater than 0 for account: {}", amount, accnumber);
                        throw new SQLException("Invalid amount! Please enter a positive value.");
                    }

                    boolean isFraud;
                    try {
                        isFraud = FraudDetectionService.isTransactionFraudulent(
                                amount, senderOldBalance, senderOldBalance - amount,
                                receiverOldBalance, receiverOldBalance + amount, "Fund Transfer"
                        );
                    } catch (FraudDetectionService.FraudDetectionException e) {
                        logger.error("Fraud detection failed for account {}: {}", accnumber, e.getMessage(), e);
                        throw new SQLException("Fraud detection failed: " + e.getMessage(), e);
                    }

                    if (isFraud) {
                        logger.error("🚨 Transaction Blocked: Fraud Detected for account: {}", accnumber);
                        String insertFraudQuery = "INSERT INTO transactions(sender_account, receiver_account, amount, transaction_type, status, oldbalanceOrg, oldbalanceDest, is_fraud) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
                        try (PreparedStatement psFraud = con.prepareStatement(insertFraudQuery, Statement.RETURN_GENERATED_KEYS)) {
                            psFraud.setString(1, accnumber);
                            psFraud.setString(2, receiverAccount);
                            psFraud.setDouble(3, amount);
                            psFraud.setString(4, "Fund Transfer");
                            psFraud.setString(5, "Failed");
                            psFraud.setDouble(6, senderOldBalance);
                            psFraud.setDouble(7, receiverOldBalance);
                            psFraud.setInt(8, 1);
                            int rowsAffected = psFraud.executeUpdate();

                            if (rowsAffected > 0) {
                                try (ResultSet generatedKeys = psFraud.getGeneratedKeys()) {
                                    if (generatedKeys.next()) {
                                        int transactionId = generatedKeys.getInt(1);
                                        logger.info("📌 Fraudulent Transaction ID: {} for account: {}", transactionId, accnumber);
                                    }
                                }
                            } else {
                                throw new SQLException("Failed to insert fraudulent transaction record.");
                            }
                        }
                        con.commit();
                        return;
                    }

                    if (senderOldBalance < amount) {
                        logger.error("Not sufficient funds available to transfer money for account: {}", accnumber);
                        throw new SQLException("Not sufficient funds available to transfer money.");
                    }

                    // OTP Verification (moved to endpoint level, just verify here)
                    if (!OTPService.verifyOTP(accnumber, userOtp, con)) {
                        logger.error("Incorrect or expired OTP! Transaction cancelled for account: {}", accnumber);
                        throw new SQLException("Incorrect or expired OTP! Transaction cancelled.");
                    }
                    logger.info("OTP Verified Successfully for account: {}", accnumber);

                    double senderNewBalance = senderOldBalance - amount;
                    double receiverNewBalance = receiverOldBalance + amount;

                    String deductQuery = "UPDATE bank_accounts SET balance = ? WHERE account_number = ?";
                    try (PreparedStatement psDeduct = con.prepareStatement(deductQuery)) {
                        psDeduct.setDouble(1, senderNewBalance);
                        psDeduct.setString(2, accnumber);
                        psDeduct.executeUpdate();
                    }

                    String addQuery = "UPDATE bank_accounts SET balance = ? WHERE account_number = ?";
                    try (PreparedStatement psAdd = con.prepareStatement(addQuery)) {
                        psAdd.setDouble(1, receiverNewBalance);
                        psAdd.setString(2, receiverAccount);
                        psAdd.executeUpdate();
                    }

                    String insertQuery = "INSERT INTO transactions(sender_account, receiver_account, amount, transaction_type, status, oldbalanceOrg, newbalanceOrig, oldbalanceDest, newbalanceDest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                    int transactionId;
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
                                    transactionId = generatedKeys.getInt(1);
                                    logger.info("📌 Transaction ID: {} for account: {}", transactionId, accnumber);
                                } else {
                                    throw new SQLException("Failed to retrieve transaction ID.");
                                }
                            }
                        } else {
                            throw new SQLException("Failed to insert successful transaction record.");
                        }
                    }

                    String updateOtpQuery = "UPDATE transactions SET otp_verified = 1 WHERE id = ?";
                    try (PreparedStatement psOtp = con.prepareStatement(updateOtpQuery)) {
                        psOtp.setInt(1, transactionId);
                        psOtp.executeUpdate();
                    }

                    con.commit();

                    logger.info("Money Transferred Successfully for account: {}", accnumber);
                    logger.info("Your current balance is {} for account: {}", senderNewBalance, accnumber);

                    this.balance = senderNewBalance;

                    sendalert(this.email, amount, receiverAccount, "Fund Transfer", senderNewBalance, "sender");
                    sendalert(recipientEmail, amount, accnumber, "Fund Transfer", receiverNewBalance, "receiver");
                }
            }
        } catch (SQLException e) {
            con.rollback();
            logger.error("SQLException in fundTransfer for account {}: {}", accnumber, e.getMessage(), e);
            throw e;
        } catch (MessagingException e) {
            con.rollback();
            logger.error("MessagingException in fundTransfer for account {}: {}", accnumber, e.getMessage(), e);
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }

    public String displayTransactionHistory(String accnumber, Connection con) throws SQLException {
        StringBuilder history = new StringBuilder();
        history.append(String.format("%-15s %-19s %-19s %-20s %-10s %-15s %-20s %-12s\n",
                "Transaction ID", "Sender", "Receiver", "Transaction Type", "Type", "Amount", "Date", "Status"));
        history.append("-----------------------------------------------------------------------------------------------------\n");

        String query = "SELECT id, sender_account, receiver_account, transaction_type, amount, timestamp, status, is_fraud " +
                "FROM transactions " +
                "WHERE sender_account = ? OR receiver_account = ? " +
                "ORDER BY timestamp DESC";

        try (PreparedStatement pstmt = con.prepareStatement(query)) {
            pstmt.setString(1, accnumber);
            pstmt.setString(2, accnumber);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    int transactionID = rs.getInt("id");
                    String sender = rs.getString("sender_account");
                    String receiver = rs.getString("receiver_account");
                    String transactionType = rs.getString("transaction_type");
                    double amount = rs.getDouble("amount");
                    String timestamp = rs.getString("timestamp");
                    String status = rs.getString("status");
                    int isFraud = rs.getInt("is_fraud");

                    String type = sender.equals(accnumber) ? "Debit" : "Credit";

                    history.append(String.format("%-15d %-19s %-19s %-20s %-10s %-15.2f %-20s %-12s\n",
                            transactionID, sender, receiver, transactionType, type, amount, timestamp, status + (isFraud == 1 ? " (Fraud)" : "")));
                }
            }
        } catch (SQLException e) {
            logger.error("Error displaying transaction history for account {}: {}", accnumber, e.getMessage(), e);
            throw e;
        }

        logger.info("Retrieved transaction history for account: {}", accnumber);
        return history.toString();
    }

    public void sendalert(String recipientEmail, double amount, String otherParty, String type, double newBalance, String role) throws MessagingException {
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
            subject = "Transaction Alert - You Received Money";
            emailBody = "Dear Customer,\n\n"
                    + "You have received ₹" + amount + " from account " + otherParty + ".\n"
                    + "Transaction Type: " + type + "\n"
                    + "Date: " + new java.util.Date() + "\n"
                    + "New Balance: ₹" + newBalance + "\n\n"
                    + "If this transaction was not expected, please contact customer support immediately.\n\n"
                    + "Best Regards,\n Jay Shree Ram";
        }

        OTPService.sendEmail(recipientEmail, subject, emailBody);
        logger.info("Transaction alert sent to {}", recipientEmail);
    }
}