package com.Rishi;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Scanner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Banking_system {
    private static final Logger logger = LogManager.getLogger(Banking_system.class);

    public static void main(String[] args) {
        // Test Log4j with different log levels
        logger.info("Application started - Testing Log4j");
        logger.debug("This is a debug message to test Log4j");
        logger.error("This is an error message to test Log4j");

        // Establish database connection using DatabaseConfig
        Connection connection = null;
        try {
            connection = DatabaseConfig.getConnection();
            logger.info("Database connected successfully!");
            System.out.println("✅ Database Connected Successfully!");
        } catch (SQLException e) {
            logger.error("Database connection failed: {}", e.getMessage(), e);
            System.out.println("❌ Database Connection Failed: " + e.getMessage());
            return; // Exit if database connection fails
        }

        // Use try-with-resources for Scanner (auto-closes scanner)
        try (Scanner sc = new Scanner(System.in)) {
            boolean exit = false;

            while (!exit) {
                System.out.println("\n=== Banking System ===");
                System.out.println("1. Register");
                System.out.println("2. Login");
                System.out.println("3. Forgot Password");
                System.out.println("4. Exit");
                System.out.print("Enter your choice: ");

                int choice = sc.nextInt();
                sc.nextLine(); // Consume newline left by nextInt()
                logger.debug("User selected main menu option: {}", choice);

                switch (choice) {
                    case 1:
                        Registration regi = new Registration();
                        regi.reg();
                        break;

                    case 2:
                        Login login = new Login();
                        System.out.print("Enter your Account Number: ");
                        String accnumber = sc.nextLine();
                        logger.info("Login attempt for account: {}", accnumber);

                        boolean loginSuccess = login.log(accnumber, connection, sc);

                        if (loginSuccess) {
                            logger.info("Login successful for account: {}. Proceeding to transactions...", accnumber);
                            System.out.println("\n✅ Login Successful. Proceeding to transactions...");

                            try {
                                // Fetch email and balance with exception handling
                                String email = login.getUserEmail(accnumber, connection);
                                double balance = login.getUserBalance(accnumber, connection);

                                // Create Online Transaction object
                                Online_Transaction transaction = new Online_Transaction(connection, sc, accnumber, balance, email);

                                String pdfFilePath = null;
                                int month = 0, year = 0;

                                // Transaction menu
                                boolean transactionExit = false;
                                while (!transactionExit) {
                                    System.out.println("\n=== Transaction Menu ===");
                                    System.out.println("1. Fund Transfer");
                                    System.out.println("2. View Transaction History");
                                    System.out.println("3. Download Transaction History (PDF)");
                                    System.out.println("4. Send Transaction History via Email");
                                    System.out.println("5. Exit Transactions");
                                    System.out.print("Enter your choice: ");

                                    int transactionChoice = sc.nextInt();
                                    sc.nextLine(); // Consume newline left by nextInt()
                                    logger.debug("User selected transaction menu option: {}", transactionChoice);

                                    switch (transactionChoice) {
                                        case 1:
                                            System.out.print("Enter recipient account number: ");
                                            String receiverAccount = sc.nextLine();
                                            System.out.print("Enter amount to transfer: ");
                                            double amount = sc.nextDouble();
                                            sc.nextLine(); // Consume newline left by nextDouble()
                                            logger.info("Initiating fund transfer from {} to {} for amount: {}", accnumber, receiverAccount, amount);
                                            transaction.fundTransfer(receiverAccount, amount, connection, sc);
                                            break;

                                        case 2:
                                            logger.info("Viewing transaction history for account: {}", accnumber);
                                            transaction.displayTransactionHistory(accnumber, connection);
                                            break;

                                        case 3:
                                            System.out.print("Enter month (1-12): ");
                                            month = sc.nextInt();
                                            System.out.print("Enter year (e.g., 2025): ");
                                            year = sc.nextInt();
                                            sc.nextLine(); // Consume newline left by nextInt()
                                            logger.info("Generating PDF statement for account: {} for month: {}, year: {}", accnumber, month, year);

                                            pdfFilePath = PDFStatementGenerator.generatePDFStatement(accnumber, month, year, connection);
                                            if (pdfFilePath != null) {
                                                logger.info("PDF statement generated successfully for account: {}. Path: {}", accnumber, pdfFilePath);
                                                System.out.println("✅ PDF statement downloaded successfully: " + pdfFilePath);
                                            } else {
                                                logger.error("Failed to generate PDF statement for account: {}", accnumber);
                                                System.out.println("❌ Failed to generate PDF statement.");
                                            }
                                            break;

                                        case 4:
                                            System.out.print("Enter month (1-12): ");
                                            month = sc.nextInt();
                                            System.out.print("Enter year (e.g., 2025): ");
                                            year = sc.nextInt();
                                            sc.nextLine(); // Consume newline left by nextInt()
                                            logger.info("Sending transaction history via email for account: {} for month: {}, year: {}", accnumber, month, year);

                                            pdfFilePath = PDFStatementGenerator.generatePDFStatement(accnumber, month, year, connection);
                                            if (pdfFilePath != null) {
                                                PDFStatementGenerator.sendEmailWithPDF(email, pdfFilePath);
                                                logger.info("PDF statement sent to email: {} for account: {}", email, accnumber);
                                                System.out.println("✅ PDF statement sent to " + email);
                                            } else {
                                                logger.error("Failed to generate PDF statement for email sending for account: {}", accnumber);
                                                System.out.println("❌ Failed to generate PDF statement.");
                                            }
                                            break;

                                        case 5:
                                            transactionExit = true;
                                            logger.info("User exited transaction menu for account: {}", accnumber);
                                            System.out.println("✅ Returning to main menu...");
                                            break;

                                        default:
                                            logger.warn("Invalid transaction menu choice: {}", transactionChoice);
                                            System.out.println("❌ Invalid choice! Try again.");
                                    }
                                }
                            } catch (Login.UserDataRetrievalException e) {
                                logger.error("Failed to fetch user data for account {}: {}", accnumber, e.getMessage());
                                System.out.println("❌ Unable to proceed due to: " + e.getMessage());
                                break;
                            }
                        } else {
                            logger.warn("Login failed for account: {}", accnumber);
                            System.out.println("❌ Login failed. Please try again.");
                        }
                        break;

                    case 3:
                        Registration regu = new Registration();
                        regu.forgotPassword(connection, sc);
                        break;

                    case 4:
                        exit = true;
                        logger.info("User exited the banking system.");
                        System.out.println("✅ Thank you for using the Banking System!");
                        break;

                    default:
                        logger.warn("Invalid main menu choice: {}", choice);
                        System.out.println("❌ Invalid choice! Try again.");
                }
            }
        } catch (Exception e) { // Catch unexpected exceptions from Scanner or other operations
            logger.error("Unexpected error in banking system: {}", e.getMessage(), e);
            System.out.println("❌ An unexpected error occurred: " + e.getMessage());
        } finally {
            // Close database connection properly
            try {
                if (connection != null && !connection.isClosed()) {
                    connection.close();
                    logger.info("Database connection closed.");
                    System.out.println("✅ Database connection closed.");
                }
            } catch (SQLException e) {
                logger.error("SQLException while closing database connection: {}", e.getMessage(), e);
                System.out.println("❌ Error closing database connection: " + e.getMessage());
            }
        }
    }
}