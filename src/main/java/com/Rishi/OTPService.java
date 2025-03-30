package com.Rishi;

import java.sql.*;
import java.util.Properties;
import java.util.Random;
import javax.mail.*;
import javax.mail.internet.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OTPService {
    private static final Logger logger = LogManager.getLogger(OTPService.class);
    private static final int OTP_EXPIRATION_MINUTES = 5;

    // Generate a 6-digit OTP
    public static String generateOTP(String accountNumber) {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        logger.info("Generated OTP for account {}: {}", accountNumber, otp);
        return String.valueOf(otp);
    }

    // Send OTP and store it in the appropriate table
    public static String sendOTP(String accnumber, String email, Connection con) throws SQLException, MessagingException {
        String otp = generateOTP(accnumber);
        Timestamp otpTimestamp = new Timestamp(System.currentTimeMillis());

        try {
            con.setAutoCommit(false);

            // Check if user exists in users table
            boolean userExists = checkUserExists(accnumber, con);

            if (userExists) {
                // Existing user - store in users table
                String updateQuery = "UPDATE users SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
                try (PreparedStatement ps = con.prepareStatement(updateQuery)) {
                    ps.setString(1, otp);
                    ps.setTimestamp(2, otpTimestamp);
                    ps.setString(3, accnumber);
                    ps.executeUpdate();
                }
                logger.info("Stored OTP in users table for account: {}", accnumber);
            } else {
                // Pre-registration - store in pre_registration table
                String insertQuery = "INSERT INTO pre_registration (account_number, otp, otp_timestamp) " +
                        "VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE " +
                        "otp = VALUES(otp), otp_timestamp = VALUES(otp_timestamp)";
                try (PreparedStatement ps = con.prepareStatement(insertQuery)) {
                    ps.setString(1, accnumber);
                    ps.setString(2, otp);
                    ps.setTimestamp(3, otpTimestamp);
                    ps.executeUpdate();
                }
                logger.info("Stored OTP in pre_registration table for account: {}", accnumber);
            }

            // Send OTP via email if email is provided
            if (email != null && !email.trim().isEmpty()) {
                sendEmail(email, "🔐 Your OTP Code", "Your OTP is: " + otp +
                        "\nThis OTP will expire in " + OTP_EXPIRATION_MINUTES + " minutes.");
                logger.info("OTP sent to email: {} for account: {}", email, accnumber);
            } else {
                logger.warn("No email provided for account {}. OTP generated but not sent: {}", accnumber, otp);
            }

            con.commit();
            return otp;
        } catch (SQLException | MessagingException e) {
            con.rollback();
            logger.error("Error in sendOTP for account {}: {}", accnumber, e.getMessage());
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }

    // Overloaded method to fetch email and send OTP
    public static void sendOTP(String accnumber, Connection con) throws SQLException, MessagingException {
        String emailQuery = "SELECT email FROM users WHERE account_number = ? UNION ALL " +
                "SELECT email FROM bank_accounts WHERE account_number = ? LIMIT 1";
        String email = null;
        try (PreparedStatement emailPs = con.prepareStatement(emailQuery)) {
            emailPs.setString(1, accnumber);
            emailPs.setString(2, accnumber);
            try (ResultSet rs = emailPs.executeQuery()) {
                if (rs.next()) {
                    email = rs.getString("email");
                }
            }
        }

        if (email == null) {
            throw new IllegalArgumentException("No email found for account: " + accnumber);
        }

        sendOTP(accnumber, email, con);
    }

    // Verify OTP from either users or pre_registration table
    public static boolean verifyOTP(String accnumber, String userOtp, Connection con) throws SQLException {
        // First check pre_registration table
        String preRegQuery = "SELECT otp, otp_timestamp FROM pre_registration WHERE account_number = ?";
        String storedOtp = null;
        Timestamp otpTimestamp = null;

        try (PreparedStatement ps = con.prepareStatement(preRegQuery)) {
            ps.setString(1, accnumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    storedOtp = rs.getString("otp");
                    otpTimestamp = rs.getTimestamp("otp_timestamp");
                    logger.debug("Found OTP in pre_registration for account: {}", accnumber);
                }
            }
        }

        // If not found in pre_registration, check users table
        if (storedOtp == null) {
            String userQuery = "SELECT otp, otp_timestamp FROM users WHERE account_number = ?";
            try (PreparedStatement ps = con.prepareStatement(userQuery)) {
                ps.setString(1, accnumber);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        storedOtp = rs.getString("otp");
                        otpTimestamp = rs.getTimestamp("otp_timestamp");
                        logger.debug("Found OTP in users table for account: {}", accnumber);
                    }
                }
            }
        }

        if (storedOtp == null || otpTimestamp == null) {
            throw new IllegalStateException("No OTP found for this account. Please request a new OTP.");
        }

        // Check OTP expiration
        long elapsedTimeMillis = System.currentTimeMillis() - otpTimestamp.getTime();
        if (elapsedTimeMillis > (OTP_EXPIRATION_MINUTES * 60 * 1000)) {
            throw new IllegalStateException("OTP expired! Please request a new one.");
        }

        if (!userOtp.equals(storedOtp)) {
            throw new IllegalArgumentException("Incorrect OTP! Please try again.");
        }

        // Clear OTP after successful verification
        clearOTP(accnumber, con);

        return true;  // No need to commit, let caller handle transactions
    }


    // Clears OTP from both tables after successful verification
    private static void clearOTP(String accnumber, Connection con) throws SQLException {
        // Clear from pre_registration table
        String clearPreRegQuery = "DELETE FROM pre_registration WHERE account_number = ?";
        try (PreparedStatement clearPreRegPs = con.prepareStatement(clearPreRegQuery)) {
            clearPreRegPs.setString(1, accnumber);
            clearPreRegPs.executeUpdate();
        }

        // Clear from users table
        String clearUserQuery = "UPDATE users SET otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
        try (PreparedStatement clearUserPs = con.prepareStatement(clearUserQuery)) {
            clearUserPs.setString(1, accnumber);
            clearUserPs.executeUpdate();
        }

        logger.info("Cleared OTP for account: {}", accnumber);
    }

    // Helper method to check if user exists
    private static boolean checkUserExists(String accnumber, Connection con) throws SQLException {
        String query = "SELECT 1 FROM users WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accnumber);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Send Email Function (unchanged)
    public static void sendEmail(String to, String subject, String body) throws MessagingException {
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

        logger.info("Email sent to: {}", to);
    }
}