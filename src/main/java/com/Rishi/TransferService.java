package com.Rishi;

import java.sql.*;
import java.util.UUID;
import javax.mail.MessagingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TransferService {
    private static final Logger logger = LogManager.getLogger(TransferService.class);

    public void transferFunds(String fromAccount, String toAccount, double amount,
                              String otp, String token, Connection con)
            throws SQLException, MessagingException {

        if (con == null) {
            throw new SQLException("Database connection cannot be null");
        }

        boolean originalAutoCommit = con.getAutoCommit();
        try {
            // 1. Start transaction
            con.setAutoCommit(false);
            logger.debug("Transaction started for transfer from {} to {}", fromAccount, toAccount);

            // 2. Verify token
            if (!verifyToken(fromAccount, token, con)) {
                throw new IllegalArgumentException("Invalid or expired token");
            }

            // 3. Verify OTP
            verifyOTP(fromAccount, otp, con);

            // 4. Validate accounts
            validateAccounts(fromAccount, toAccount, con);

            // 5. Get balances before transfer
            double[] balances = getBalances(fromAccount, toAccount, con);
            double senderOldBalance = balances[0];
            double receiverOldBalance = balances[1];

            // 6. Validate transfer amount
            validateTransferAmount(amount, senderOldBalance);

            // 7. Check for fraud
            if (isFraudulentTransaction(fromAccount, toAccount, amount, senderOldBalance, receiverOldBalance, con)) {
                handleFraudulentTransaction(fromAccount, toAccount, amount, senderOldBalance, receiverOldBalance, con);
                con.commit();
                throw new IllegalArgumentException("Transaction flagged as potentially fraudulent");
            }

            // 8. Execute transfer
            executeTransfer(fromAccount, toAccount, amount, senderOldBalance, receiverOldBalance, con);

            // 9. Get emails for alerts
            String senderEmail = getAccountEmail(fromAccount, con);
            String recipientEmail = getAccountEmail(toAccount, con);

            // 10. Commit transaction
            con.commit();
            logger.info("Transfer completed successfully: {} to {}, Amount: {}",
                    fromAccount, toAccount, amount);

            // 11. Send alerts (outside transaction)
            sendAlerts(fromAccount, toAccount, amount, senderEmail, recipientEmail,
                    senderOldBalance - amount, receiverOldBalance + amount);

        } catch (SQLException | IllegalArgumentException e) {
            handleTransferFailure(con, e);
            throw e;
        } finally {
            resetAutoCommit(con, originalAutoCommit);
        }
    }

    // ========== NEW ALERT-RELATED METHODS ========== //

    private String getAccountEmail(String accountNumber, Connection con) throws SQLException {
        String query = "SELECT email FROM bank_accounts WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("email");
                }
                throw new SQLException("Email not found for account: " + accountNumber);
            }
        }
    }

    private void sendAlerts(String fromAccount, String toAccount, double amount,
                            String senderEmail, String recipientEmail,
                            double senderNewBalance, double receiverNewBalance) {
        try {
            // Send sender alert
            if (senderEmail != null && !senderEmail.trim().isEmpty()) {
                String senderSubject = "🚨 Transaction Alert - You Sent Money";
                String senderBody = String.format(
                        "Dear Customer,\n\nYou have transferred ₹%.2f to account %s.\n" +
                                "New Balance: ₹%.2f\n\nBest Regards,\nYour Bank",
                        amount, toAccount, senderNewBalance
                );
                OTPService.sendEmail(senderEmail, senderSubject, senderBody);
                logger.info("Sent alert to sender: {}", senderEmail);
            }

            // Send recipient alert
            if (recipientEmail != null && !recipientEmail.trim().isEmpty()) {
                String recipientSubject = "💰 Transaction Alert - You Received Money";
                String recipientBody = String.format(
                        "Dear Customer,\n\nYou received ₹%.2f from account %s.\n" +
                                "New Balance: ₹%.2f\n\nBest Regards,\nYour Bank",
                        amount, fromAccount, receiverNewBalance
                );
                OTPService.sendEmail(recipientEmail, recipientSubject, recipientBody);
                logger.info("Sent alert to recipient: {}", recipientEmail);
            }
        } catch (MessagingException e) {
            logger.error("Failed to send alerts (transaction still succeeded): {}", e.getMessage());
        }
    }

    // ========== EXISTING HELPER METHODS (UNCHANGED) ========== //

    private void verifyOTP(String accountNumber, String otp, Connection con) throws SQLException {
        if (!OTPService.verifyOTP(accountNumber, otp, con)) {
            throw new IllegalArgumentException("Invalid OTP");
        }
    }

    private double[] getBalances(String fromAccount, String toAccount, Connection con) throws SQLException {
        double senderBalance = getAccountBalance(fromAccount, con);
        double receiverBalance = getAccountBalance(toAccount, con);
        return new double[]{senderBalance, receiverBalance};
    }

    private void validateTransferAmount(double amount, double senderBalance) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Transfer amount must be positive");
        }
        if (senderBalance < amount) {
            throw new IllegalArgumentException("Insufficient funds");
        }
    }

    private boolean isFraudulentTransaction(String fromAccount, String toAccount, double amount,
                                            double senderOldBalance, double receiverOldBalance,
                                            Connection con) throws SQLException {
        try {
            return FraudDetectionService.isTransactionFraudulent(
                    amount, senderOldBalance, senderOldBalance - amount,
                    receiverOldBalance, receiverOldBalance + amount, "TRANSFER"
            );
        } catch (FraudDetectionService.FraudDetectionException e) {
            logger.error("Fraud detection service error: {}", e.getMessage());
            throw new SQLException("Fraud detection service unavailable", e);
        }
    }

    private void handleFraudulentTransaction(String fromAccount, String toAccount, double amount,
                                             double senderOldBalance, double receiverOldBalance,
                                             Connection con) throws SQLException {
        logger.warn("Fraud detected in transaction: {} -> {} (Amount: {})",
                fromAccount, toAccount, amount);
        recordTransaction(fromAccount, toAccount, amount, senderOldBalance, senderOldBalance,
                receiverOldBalance, receiverOldBalance, "Failed", 1, con);
    }

    private void executeTransfer(String fromAccount, String toAccount, double amount,
                                 double senderOldBalance, double receiverOldBalance,
                                 Connection con) throws SQLException {
        updateAccountBalance(fromAccount, -amount, con);
        updateAccountBalance(toAccount, amount, con);
        recordTransaction(fromAccount, toAccount, amount, senderOldBalance, senderOldBalance - amount,
                receiverOldBalance, receiverOldBalance + amount, "Completed", 0, con);
    }

    private void handleTransferFailure(Connection con, Exception e) throws SQLException {
        logger.error("Transfer failed: {}", e.getMessage());
        try {
            if (con != null && !con.getAutoCommit()) {
                con.rollback();
                logger.debug("Transaction rolled back successfully");
            }
        } catch (SQLException ex) {
            logger.error("Rollback failed: {}", ex.getMessage());
            throw ex;
        }
    }

    private void resetAutoCommit(Connection con, boolean originalAutoCommit) {
        try {
            if (con != null) {
                con.setAutoCommit(originalAutoCommit);
                logger.debug("Auto-commit reset to {}", originalAutoCommit);
            }
        } catch (SQLException e) {
            logger.error("Failed to reset auto-commit: {}", e.getMessage());
        }
    }

    // ========== EXISTING DATABASE OPERATIONS (UNCHANGED) ========== //

    private boolean verifyToken(String accountNumber, String token, Connection con) throws SQLException {
        String query = "SELECT 1 FROM user_sessions WHERE account_number = ? AND token = ? AND expires_at > NOW()";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            ps.setString(2, token);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private void validateAccounts(String fromAccount, String toAccount, Connection con) throws SQLException {
        if (fromAccount.equals(toAccount)) {
            throw new IllegalArgumentException("Cannot transfer to same account");
        }
        if (!accountExists(fromAccount, con)) {
            throw new IllegalArgumentException("Sender account not found");
        }
        if (!accountExists(toAccount, con)) {
            throw new IllegalArgumentException("Recipient account not found");
        }
    }

    private boolean accountExists(String accountNumber, Connection con) throws SQLException {
        String query = "SELECT 1 FROM bank_accounts WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private double getAccountBalance(String accountNumber, Connection con) throws SQLException {
        String query = "SELECT balance FROM bank_accounts WHERE account_number = ? FOR UPDATE";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getDouble("balance");
                }
                throw new SQLException("Account not found: " + accountNumber);
            }
        }
    }

    private void updateAccountBalance(String accountNumber, double amount, Connection con) throws SQLException {
        String query = "UPDATE bank_accounts SET balance = balance + ? WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setDouble(1, amount);
            ps.setString(2, accountNumber);
            if (ps.executeUpdate() != 1) {
                throw new SQLException("Failed to update account balance");
            }
        }
    }

    private void recordTransaction(String fromAccount, String toAccount, double amount,
                                   double senderOldBalance, double senderNewBalance,
                                   double receiverOldBalance, double receiverNewBalance,
                                   String status, int isFraud, Connection con) throws SQLException {
        String query = "INSERT INTO transactions (" +
                "sender_account, receiver_account, transaction_type, amount, " +
                "status, oldbalanceOrg, newbalanceOrig, oldbalanceDest, newbalanceDest, is_fraud) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, fromAccount);
            ps.setString(2, toAccount);
            ps.setString(3, "Fund Transfer");
            ps.setDouble(4, amount);
            ps.setString(5, status);
            ps.setDouble(6, senderOldBalance);
            ps.setDouble(7, senderNewBalance);
            ps.setDouble(8, receiverOldBalance);
            ps.setDouble(9, receiverNewBalance);
            ps.setInt(10, isFraud);
            ps.executeUpdate();
        }
    }
}