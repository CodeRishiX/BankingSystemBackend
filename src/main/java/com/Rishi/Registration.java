package com.Rishi;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.sql.*;
import java.util.Random;
import java.util.Scanner;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.logging.log4j.LogManager; // Added Log4j import
import org.apache.logging.log4j.Logger;    // Added Logger import

public class Registration {

    private final static String url = "jdbc:mysql://localhost:3306/bank";
    private final static String username = "root";
    private final static String password = "Rishi54307e";
    private static final Logger logger = LogManager.getLogger(Registration.class); // Added Logger instance

    public static void reg() {
        Scanner sc = new Scanner(System.in);

//        try (Connection con = DriverManager.getConnection(url, username, password)) {
//            con.setAutoCommit(false);

        try(Connection con = DatabaseConfig.getConnection()) { // Use DatabaseConfig
            con.setAutoCommit(false);
            logger.info("Starting registration process"); // Log start of registration

            System.out.print("Welcome, Enter your Account number: ");
            String accountNumber = sc.nextLine();
            logger.debug("User entered account number: {}", accountNumber); // Log account number input
            String alreadyregistered="select * from users where account_number=? ";
            try(PreparedStatement ps = con.prepareStatement(alreadyregistered)) {
                ps.setString(1, accountNumber);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    String present=rs.getString("account_number");
                    if(accountNumber.equals(present)) {
                        logger.info("Account number already registered, --> present in user table ");
                        System.out.println("Your account number is already in use & registered");
                        return;
                    }
                }
            }

            String checkQuery = "SELECT email, phone FROM bank_accounts WHERE account_number = ?";
            try (PreparedStatement checkPs = con.prepareStatement(checkQuery)) {
                checkPs.setString(1, accountNumber);
                try (ResultSet rs = checkPs.executeQuery()) {
                    if (rs.next()) {
                        String email = rs.getString("email");
                        String phone = rs.getString("phone");
                        logger.info("Fetched email: {} and phone: {} for account: {}", email, phone, accountNumber); // Log fetched data


                        String otp = OTPService.sendOTP(email);
                        if (otp == null) {
                            System.out.println("❌ Failed to send OTP.");
                            logger.error("Failed to send OTP for account: {}", accountNumber); // Log OTP failure
                            con.rollback();
                            return;
                        }

                        System.out.print("Enter the OTP received: ");
                        String enteredOtp = sc.nextLine();
                        logger.debug("User entered OTP: {}", enteredOtp); // Log OTP input

                        if (!enteredOtp.equals(otp)) {
                            System.out.println("❌ Incorrect OTP! Please try again.");
                            logger.warn("Incorrect OTP entered for account: {}", accountNumber); // Log incorrect OTP
                            con.rollback();
                            return;
                        }

                        System.out.println("✅ OTP Verified Successfully!");
                        logger.info("OTP verified successfully for account: {}", accountNumber); // Log OTP success

                        // Add security question logic
                        System.out.println("\nChoose a security question:");
                        System.out.println("1. What is your pet's name?");
                        System.out.println("2. What is your mother's maiden name?");
                        System.out.println("3. What is the name of your first school?");
                        System.out.print("Enter your choice (1-3): ");
                        int choice = sc.nextInt();
                        sc.nextLine(); // Consume newline
                        logger.debug("User selected security question choice: {}", choice); // Log choice

                        String securityQuestion = "";
                        switch (choice) {
                            case 1: securityQuestion = "What is your pet's name?"; break;
                            case 2: securityQuestion = "What is your mother's maiden name?"; break;
                            case 3: securityQuestion = "What is the name of your first school?"; break;
                            default:
                                System.out.println("❌ Invalid choice! Registration failed.");
                                logger.warn("Invalid security question choice: {} for account: {}", choice, accountNumber); // Log invalid choice
                                con.rollback();
                                return;
                        }
                        System.out.print("Enter your answer: ");
                        String securityAnswer = sc.nextLine();
                        String hashedAnswer = BCrypt.hashpw(securityAnswer, BCrypt.gensalt());
                        logger.debug("User entered security answer for account: {}", accountNumber); // Log answer (not logging actual answer for security)

                        // Password logic
                        String pass1, pass2;
                        do {
                            System.out.print("Create a new password: ");
                            pass1 = sc.nextLine();
                            System.out.print("Re-enter password: ");
                            pass2 = sc.nextLine();

                            if (!pass1.equals(pass2)) {
                                System.out.println("❌ Passwords do not match. Try again.");
                                logger.warn("Passwords do not match for account: {}", accountNumber); // Log mismatch
                            } else if (!isPasswordStrong(pass1)) {
                                System.out.println("❌ Weak password! Use at least 8 characters, upper/lower case, numbers, and symbols.");
                                logger.warn("Weak password entered for account: {}", accountNumber); // Log weak password
                            }
                        } while (!pass1.equals(pass2) || !isPasswordStrong(pass1));
                        logger.debug("User entered passwords for account: {}", accountNumber); // Log password entry (not logging actual passwords)

                        String hashedPassword = BCrypt.hashpw(pass2, BCrypt.gensalt(12));

                        // Insert with security question
                        String insertUserQuery = "INSERT INTO users (account_number, email, phone, password_hash, security_question, security_answer_hash, otp_verified) VALUES (?, ?, ?, ?, ?, ?, ?)";
                        try (PreparedStatement insertUserPs = con.prepareStatement(insertUserQuery)) {
                            insertUserPs.setString(1, accountNumber);
                            insertUserPs.setString(2, email);
                            insertUserPs.setString(3, phone);
                            insertUserPs.setString(4, hashedPassword);
                            insertUserPs.setString(5, securityQuestion);
                            insertUserPs.setString(6, hashedAnswer);
                            insertUserPs.setInt(7, 1);
                            insertUserPs.executeUpdate();
                            logger.info("User data inserted into database for account: {}", accountNumber); // Log DB insert
                        }

                        String clearOtpQuery = "UPDATE bank_accounts SET otp_verified = 1 WHERE account_number = ?";
                        try (PreparedStatement clearOtpPs = con.prepareStatement(clearOtpQuery)) {
                            clearOtpPs.setString(1, accountNumber);
                            clearOtpPs.executeUpdate();
                            logger.info("OTP verification updated in bank_accounts for account: {}", accountNumber); // Log OTP update
                        }

                        con.commit();
                        System.out.println("✅ Registration successful!");
                        logger.info("Registration completed successfully for account: {}", accountNumber); // Log success
                    } else {
                        System.out.println("❌ Account number not found.");
                        logger.warn("Account number not found in bank_accounts: {}", accountNumber); // Log account not found
                    }
                }
            }
        } catch (SQLException e) {
            System.out.println("❌ Database error: " + e.getMessage());
            logger.error("SQLException during registration: {}", e.getMessage(), e); // Log SQL error
            e.printStackTrace();
        }
    }

    // ✅ Function to generate a 6-digit OTP
    private static String generateOTP() {
        Random rand = new Random();
        int otp = 100000 + rand.nextInt(900000);
        logger.debug("Generated OTP: {}", otp); // Log OTP generation
        return String.valueOf(otp);
    }

    public static boolean isPasswordStrong(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
        boolean isStrong = password.matches(regex);
        logger.debug("Password strength check result: {}", isStrong); // Log password strength check
        return isStrong;
    }

    public void forgotPassword(Connection con, Scanner sc) {
        System.out.println("Enter your account number:");
        String account = sc.nextLine();
        logger.info("User entered account number for forgot password: {}", account); // Log account input

        System.out.println("Enter your linked phone number:");
        String phone = sc.nextLine();
        logger.debug("User entered phone number: {}", phone); // Log phone input

        String query = "SELECT * FROM users WHERE account_number = ?";

        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setString(1, account);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) { // ✅ Check if the account exists
                String registeredPhone = rs.getString("phone");
                String email = rs.getString("email");
                String securityQuestion = rs.getString("security_question");
                String hashedAnswer = rs.getString("security_answer_hash");
                logger.info("Fetched user data for account: {} - phone: {}, email: {}", account, registeredPhone, email); // Log fetched data

                System.out.println("Security question:-->" + securityQuestion);
                String enteredanswer = sc.nextLine();
                logger.debug("User entered security answer for account: {}", account); // Log security answer input (not logging actual answer)

                if (BCrypt.checkpw(enteredanswer, hashedAnswer)) {
                    logger.info("Security answer verified successfully for account: {}", account); // Log security answer success

                    if (registeredPhone.equals(phone)) {
                        logger.info("Phone number matched for account: {}", account); // Log phone match

                        // ✅ Step 1: Generate OTP and store it in the database
                        OTPService.sendOTP(account, con);
                        logger.info("OTP sent for account: {}", account); // Log OTP send

                        // ✅ Step 2: Ask the user to enter the OTP
                        System.out.print("Enter the OTP received on your email: ");
                        String userOtp = sc.nextLine();
                        logger.debug("User entered OTP: {}", userOtp); // Log OTP input

                        // ✅ Step 3: Verify OTP (including expiry check)
                        if (!OTPService.verifyOTP(account, userOtp, con)) {
                            System.out.println("❌ Incorrect or expired OTP! Password reset failed.");
                            logger.warn("OTP verification failed for account: {}", account); // Log OTP failure
                            return;
                        }

                        System.out.println("✅ OTP verified! Proceeding to reset password.");
                        logger.info("OTP verified successfully for account: {}", account); // Log OTP success

                        // ✅ Step 4: Ask for a new password
                        String pass1, pass2;
                        do {
                            System.out.print("Create a new password (must be strong): ");
                            pass1 = sc.nextLine();
                            System.out.print("Re-enter password: ");
                            pass2 = sc.nextLine();

                            if (!pass1.equals(pass2)) {
                                System.out.println("❌ Passwords do not match. Try again.");
                                logger.warn("Passwords do not match for account: {}", account); // Log mismatch
                            } else if (!isPasswordStrong(pass1)) {
                                System.out.println("❌ Password is weak. It must contain at least 8 characters, including uppercase, lowercase, numbers, and special characters.");
                                logger.warn("Weak password entered for account: {}", account); // Log weak password
                            }
                        } while (!pass1.equals(pass2) || !isPasswordStrong(pass1));
                        logger.debug("User entered new passwords for account: {}", account); // Log password entry

                        // ✅ Step 5: Hash the new password and update it in the database
                        String hashedPassword = BCrypt.hashpw(pass2, BCrypt.gensalt(12));
                        String updateQuery = "UPDATE users SET password_hash = ? WHERE account_number = ?";

                        try (PreparedStatement ps2 = con.prepareStatement(updateQuery)) {
                            ps2.setString(1, hashedPassword);
                            ps2.setString(2, account);
                            int check = ps2.executeUpdate();

                            if (check > 0) {
                                System.out.println("✅ Password updated successfully!");
                                logger.info("Password updated successfully for account: {}", account); // Log success
                            } else {
                                System.out.println("❌ Failed to update password.");
                                logger.error("Failed to update password for account: {}", account); // Log failure
                            }
                        }
                    } else {
                        System.out.println("❌ Incorrect phone number! Please try again.");
                        logger.warn("Incorrect phone number entered for account: {}", account); // Log phone mismatch
                    }
                }
                else
                {
                    System.out.println("Hey incorrect !! security answer. Please try again.");
                    logger.warn("Incorrect security answer entered for account: {}", account); // Log incorrect security answer
                }
            } else {
                System.out.println("❌ Account number not found! Please try again.");
                logger.warn("Account number not found in users table: {}", account); // Log account not found
            }
        } catch (SQLException e) {
            System.out.println("❌ Database error: " + e.getMessage());
            logger.error("SQLException in forgotPassword for account {}: {}", account, e.getMessage(), e); // Log SQL error
            e.printStackTrace();
        }
    }
}