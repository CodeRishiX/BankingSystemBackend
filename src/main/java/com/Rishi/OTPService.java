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

    // Generate a 6-digit OTP
    public static String generateOTP(String accountNumber) {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        logger.info("Generated OTP for account {}: {}", accountNumber, otp);
        return String.valueOf(otp);
    }

    // Send OTP and store it in the database
    public static String sendOTP(String accnumber, String email, Connection con) throws SQLException, MessagingException {
        String otp = generateOTP(accnumber);
        Timestamp otpTimestamp = new Timestamp(System.currentTimeMillis());

        // Store OTP in database with explicit transaction handling
        try (Connection localCon = DatabaseConfig.getConnection()) {
            localCon.setAutoCommit(false);  // Disable auto-commit

            String updateQuery = "UPDATE users  SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
            try (PreparedStatement ps = localCon.prepareStatement(updateQuery)) {
                ps.setString(1, otp);
                ps.setTimestamp(2, otpTimestamp);
                ps.setString(3, accnumber);
                ps.executeUpdate();
                localCon.commit();  // Commit changes
                logger.info("Stored OTP in bank_accounts for account: {}", accnumber);
            } catch (SQLException e) {
                localCon.rollback();  // Rollback in case of error
                throw e;
            }
        }

        // Send OTP via email
        if (email != null && !email.trim().isEmpty()) {
            sendEmail(email, "🔐 Your OTP Code", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");
            logger.info("OTP sent to email: {} for account: {}", email, accnumber);
        } else {
            logger.warn("No email found for account {}. OTP: {}", accnumber, otp);
            throw new IllegalArgumentException("No valid email provided for account: " + accnumber);
        }

        return otp;
    }

    // Overloaded method to fetch email and send OTP
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

    // Verify OTP with additional debugging
    public static boolean verifyOTP(String accnumber, String userOtp, Connection con) throws SQLException {
        String query = "SELECT otp, otp_timestamp FROM users  WHERE account_number = ?";
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

                    // Debugging timestamps
                    System.out.println("OTP Timestamp from DB: " + otpTimestamp);
                    System.out.println("Current Time: " + new java.util.Date());
                    System.out.println("Elapsed Time: " + elapsedTime + " seconds");

                    if (elapsedTime > 300) {  // OTP expires in 5 minutes
                        throw new IllegalStateException("OTP expired! Request a new one.");
                    }
                    if (!userOtp.equals(storedOtp)) {
                        throw new IllegalArgumentException("Incorrect OTP! Try again.");
                    }

                    // Clear OTP after successful verification
                    clearOTP(accnumber, con);

                    return true;
                }
                throw new SQLException("Account not found: " + accnumber);
            }
        }
    }

    // Clears OTP after successful verification
    private static void clearOTP(String accnumber, Connection con) throws SQLException {
        String clearOTPQuery = "UPDATE users  SET otp = NULL, otp_timestamp = NULL WHERE account_number = ?";
        try (PreparedStatement clearPs = con.prepareStatement(clearOTPQuery)) {
            clearPs.setString(1, accnumber);
            clearPs.executeUpdate();
            logger.info("Cleared OTP for account: {}", accnumber);
        }
    }

    // Send Email Function
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
