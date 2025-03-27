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

    // Generate a 6-digit OTP (unchanged)
    public static String generateOTP(String accountNumber) {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        logger.info("Generated OTP for account {}: {}", accountNumber, otp);
        return String.valueOf(otp);
    }

    // Unified sendOTP method (FIXED: Ensure OTP is committed immediately)
    public static String sendOTP(String accnumber, String email, Connection con) throws SQLException, MessagingException {
        String otp = generateOTP(accnumber);
        Timestamp otpTimestamp = new Timestamp(System.currentTimeMillis());

        // Store OTP in bank_accounts table (use a new connection to avoid transaction rollback)
        try (Connection localCon = DatabaseConfig.getConnection()) {
            String updateQuery = "UPDATE bank_accounts SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
            try (PreparedStatement ps = localCon.prepareStatement(updateQuery)) {
                ps.setString(1, otp);
                ps.setTimestamp(2, otpTimestamp);
                ps.setString(3, accnumber);
                ps.executeUpdate();
                logger.info("Stored OTP in bank_accounts for account: {}", accnumber);
            }
        }

        // Send email (unchanged)
        if (email != null && !email.trim().isEmpty()) {
            sendEmail(email, "🔐 Your OTP Code", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");
            logger.info("OTP sent to email: {} for account: {}", email, accnumber);
        } else {
            logger.warn("No email found for account {}. OTP: {}", accnumber, otp);
            throw new IllegalArgumentException("No valid email provided for account: " + accnumber);
        }

        return otp;
    }

    // Overloaded sendOTP (unchanged)
    public static void sendOTP(String accnumber, Connection con) throws SQLException, MessagingException {
        String emailQuery = "SELECT email FROM bank_accounts WHERE account_number = ?";
        String email = null;
        try (PreparedStatement emailPs = con.prepareStatement(emailQuery)) {
            emailPs.setString(1, accnumber);
            try (ResultSet rs = emailPs.executeQuery()) {
                if (rs.next()) {
                    email = rs.getString("email");
                }
            }
        }
        sendOTP(accnumber, email, con);
    }

    // verifyOTP methods (unchanged)
    public static boolean verifyOTP(String accnumber, String userOtp, Connection con) throws SQLException {
        String query = "SELECT otp, otp_timestamp FROM bank_accounts WHERE account_number = ?";
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, accnumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedOtp = rs.getString("otp");
                    Timestamp otpTimestamp = rs.getTimestamp("otp_timestamp");
                    if (storedOtp == null || otpTimestamp == null) {
                        throw new IllegalStateException("No OTP found! Request a new OTP.");
                    }
                    long elapsedTime = (System.currentTimeMillis() - otpTimestamp.getTime()) / 1000;
                    if (elapsedTime > 300) {
                        throw new IllegalStateException("OTP expired! Request a new one.");
                    }
                    if (!userOtp.equals(storedOtp)) {
                        throw new IllegalArgumentException("Incorrect OTP! Try again.");
                    }
                    return true;
                }
                throw new SQLException("Account not found: " + accnumber);
            }
        }
    }

    // sendEmail (unchanged)
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