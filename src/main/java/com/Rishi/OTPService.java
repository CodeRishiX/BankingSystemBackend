package com.Rishi;

import java.sql.*;
import java.util.Properties;
import java.util.Random;
import javax.mail.*;
import javax.mail.internet.*;
import org.apache.logging.log4j.LogManager; // Added Log4j import
import org.apache.logging.log4j.Logger;    // Added Logger import

public class OTPService {
    private static final Logger logger = LogManager.getLogger(OTPService.class); // Added Logger instance

    public static String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        logger.debug("Generated OTP: {}", otp); // Log OTP generation
        return String.valueOf(otp);
    }

    // For registration: takes email directly
    public static String sendOTP(String email) {
        String otp = generateOTP();
        if (email != null && !email.trim().isEmpty()) {
            sendEmail(email, "🔐 Your OTP Code", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");
            logger.info("OTP sent to email: {}", email); // Log successful OTP send
            return otp;
        } else {
            System.out.println("❌ No valid email provided.");
            logger.warn("No valid email provided for OTP send"); // Log invalid email
            return null;
        }
    }

    // For registration with database storage
    public static String sendOTP(String accnumber, String email, Connection con) {
        try {
            String otp = generateOTP();
            Timestamp otpTimestamp = new Timestamp(System.currentTimeMillis());
            logger.debug("Preparing to store OTP for account: {}", accnumber); // Log OTP prep

            String query = "UPDATE bank_accounts SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
            try (PreparedStatement ps = con.prepareStatement(query)) {
                ps.setString(1, otp);
                ps.setTimestamp(2, otpTimestamp);
                ps.setString(3, accnumber);
                ps.executeUpdate();
                logger.info("OTP stored in bank_accounts for account: {}", accnumber); // Log OTP storage
            }

            if (email != null && !email.trim().isEmpty()) {
                sendEmail(email, "🔐 Your OTP Code", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");
                logger.info("OTP sent to email: {} for account: {}", email, accnumber); // Log email send
            } else {
                System.out.println("❌ No valid email provided for account: " + accnumber);
                logger.warn("No valid email provided for account: {}", accnumber); // Log invalid email
            }

            return otp;
        } catch (SQLException e) {
            System.out.println("❌ Database error in sendOTP: " + e.getMessage());
            logger.error("Database error in sendOTP for account {}: {}", accnumber, e.getMessage(), e); // Log SQL error
            e.printStackTrace();
            return null;
        }
    }

    // For forgotPassword
    public static void sendOTP(String accnumber, Connection con) {
        try {
            String otp = generateOTP();
            Timestamp otpTimestamp = new Timestamp(System.currentTimeMillis());
            logger.debug("Generating OTP for forgotPassword, account: {}", accnumber); // Log OTP generation

            // Store OTP in users table
            String query = "UPDATE users SET otp = ?, otp_timestamp = ? WHERE account_number = ?";
            try (PreparedStatement ps = con.prepareStatement(query)) {
                ps.setString(1, otp);
                ps.setTimestamp(2, otpTimestamp);
                ps.setString(3, accnumber);
                int rowsUpdated = ps.executeUpdate();
                if (rowsUpdated == 0) {
                    System.out.println("❌ Failed to store OTP: Account not found in users table.");
                    logger.warn("Failed to store OTP: Account {} not found in users table", accnumber); // Log account not found
                    return;
                }
                logger.info("OTP stored in users table for account: {}", accnumber); // Log successful storage
            }

            // Fetch email (no decryption needed since it’s plaintext)
            String emailQuery = "SELECT email FROM users WHERE account_number = ?";
            try (PreparedStatement emailPs = con.prepareStatement(emailQuery)) {
                emailPs.setString(1, accnumber);
                ResultSet rs = emailPs.executeQuery();
                if (rs.next()) {
                    String email = rs.getString("email"); // Use directly, no decryption
                    if (email != null && !email.trim().isEmpty()) {
                        sendEmail(email, "🔐 Your OTP Code", "Your OTP is: " + otp + "\nThis OTP will expire in 5 minutes.");
                        logger.info("OTP sent to email: {} for account: {}", email, accnumber); // Log email send
                    } else {
                        System.out.println("❌ Email is invalid for account: " + accnumber);
                        logger.warn("Invalid email for account: {}", accnumber); // Log invalid email
                    }
                } else {
                    System.out.println("❌ No email found for account: " + accnumber);
                    logger.warn("No email found for account: {}", accnumber); // Log no email found
                }
            }
        } catch (SQLException e) {
            System.out.println("❌ Database error in sendOTP: " + e.getMessage());
            logger.error("Database error in sendOTP for account {}: {}", accnumber, e.getMessage(), e); // Log SQL error
            e.printStackTrace();
        }
    }

    public static boolean verifyOTP(String accnumber, String userOtp, Connection con) {
        try {
            String query = "SELECT otp, otp_timestamp FROM users WHERE account_number = ?";
            try (PreparedStatement ps = con.prepareStatement(query)) {
                ps.setString(1, accnumber);
                ResultSet rs = ps.executeQuery();

                if (rs.next()) {
                    String storedOtp = rs.getString("otp");
                    Timestamp otpTimestamp = rs.getTimestamp("otp_timestamp");
                    logger.debug("Fetched OTP: {} and timestamp: {} for account: {}", storedOtp, otpTimestamp, accnumber); // Log fetched data

                    if (storedOtp == null || otpTimestamp == null) {
                        System.out.println("❌ No OTP found! Request a new OTP.");
                        logger.warn("No OTP found for account: {}", accnumber); // Log no OTP
                        return false;
                    }

                    long currentTime = System.currentTimeMillis();
                    long otpTime = otpTimestamp.getTime();
                    long elapsedTime = (currentTime - otpTime) / 1000; // Time in seconds

                    if (elapsedTime > 300) { // 5 minutes = 300 seconds
                        System.out.println("❌ OTP has expired! Please request a new one.");
                        logger.warn("OTP expired for account: {} (elapsed time: {}s)", accnumber, elapsedTime); // Log expiration
                        return false;
                    }

                    if (!userOtp.equals(storedOtp)) {
                        System.out.println("❌ Incorrect OTP! Please try again.");
                        logger.warn("Incorrect OTP entered for account: {} (entered: {}, stored: {})", accnumber, userOtp, storedOtp); // Log incorrect OTP
                        return false;
                    }

                    System.out.println("✅ OTP verified successfully.");
                    logger.info("OTP verified successfully for account: {}", accnumber); // Log success
                    return true;
                } else {
                    System.out.println("❌ Account not found!");
                    logger.warn("Account not found for OTP verification: {}", accnumber); // Log account not found
                    return false;
                }
            }
        } catch (SQLException e) {
            System.out.println("❌ Database error in verifyOTP: " + e.getMessage());
            logger.error("Database error in verifyOTP for account {}: {}", accnumber, e.getMessage(), e); // Log SQL error
            e.printStackTrace();
            return false;
        }
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
            System.out.println("✅ Email sent successfully to " + recipientEmail);
            logger.info("Email sent successfully to: {}", recipientEmail); // Log success
        } catch (MessagingException e) {
            System.out.println("❌ Failed to send email: " + e.getMessage());
            logger.error("Failed to send email to {}: {}", recipientEmail, e.getMessage(), e); // Log failure
            e.printStackTrace();
        }
    }
}