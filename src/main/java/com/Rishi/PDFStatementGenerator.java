package com.Rishi;

import com.itextpdf.kernel.pdf.*;
import com.itextpdf.layout.*;
import com.itextpdf.layout.element.*;
import java.io.*;
import java.sql.*;
import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;
import javax.activation.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PDFStatementGenerator {
    private static final Logger logger = LogManager.getLogger(PDFStatementGenerator.class);

    // Use a temporary directory compatible with Render (Linux-based)
    public static final String PDF_DIR = System.getenv("PDF_DIR") != null ? System.getenv("PDF_DIR") : "/tmp/bank_statements/";

    // Method to generate the PDF Statement
    public static String generatePDFStatement(String accountNumber, int month, int year, Connection con) throws SQLException, IOException {
        String pdfFileName = PDF_DIR + "Statement_" + accountNumber + "_" + month + "_" + year + ".pdf";

        try {
            // Step 1: Validate Month and Year
            if (month < 1 || month > 12) {
                logger.error("Invalid month: {}. Must be between 1 and 12 for account: {}", month, accountNumber);
                throw new IllegalArgumentException("Invalid month! Must be between 1 and 12.");
            }
            if (year < 1900 || year > 9999) {
                logger.error("Invalid year: {}. Must be between 1900 and 9999 for account: {}", year, accountNumber);
                throw new IllegalArgumentException("Invalid year! Must be between 1900 and 9999.");
            }

            // Step 2: Ensure the directory exists
            File directory = new File(PDF_DIR);
            if (!directory.exists()) {
                if (!directory.mkdirs()) {
                    logger.error("Failed to create directory: {} for account: {}", PDF_DIR, accountNumber);
                    throw new IOException("Failed to create directory: " + PDF_DIR);
                }
                logger.info("Created directory: {} for account: {}", PDF_DIR, accountNumber);
            }

            // Step 3: Fetch Transactions from Database (Only Completed Transactions)
            String query = "SELECT id, sender_account, receiver_account, transaction_type, amount, timestamp " +
                    "FROM transactions " +
                    "WHERE (sender_account = ? OR receiver_account = ?) " +
                    "AND status = 'Completed' " +
                    "AND MONTH(timestamp) = ? AND YEAR(timestamp) = ? " +
                    "ORDER BY timestamp DESC";

            try (PreparedStatement pstmt = con.prepareStatement(query)) {
                pstmt.setString(1, accountNumber);
                pstmt.setString(2, accountNumber);
                pstmt.setInt(3, month);
                pstmt.setInt(4, year);
                try (ResultSet rs = pstmt.executeQuery()) {
                    // Step 4: Create PDF File
                    PdfWriter writer = new PdfWriter(pdfFileName);
                    PdfDocument pdf = new PdfDocument(writer);
                    Document document = new Document(pdf);

                    // Step 5: Add Header
                    document.add(new Paragraph("Bank Account Statement").setBold().setFontSize(16));
                    document.add(new Paragraph("Account Number: " + accountNumber));
                    document.add(new Paragraph("Month: " + month + " | Year: " + year + "\n\n"));

                    // Step 6: Create Table
                    Table table = new Table(7); // 7 columns for Transaction ID, Sender, Receiver, Type, Amount, Date, Debit/Credit
                    table.addCell(new Cell().add(new Paragraph("Transaction ID")));
                    table.addCell(new Cell().add(new Paragraph("Sender")));
                    table.addCell(new Cell().add(new Paragraph("Receiver")));
                    table.addCell(new Cell().add(new Paragraph("Type")));
                    table.addCell(new Cell().add(new Paragraph("Amount")));
                    table.addCell(new Cell().add(new Paragraph("Date")));
                    table.addCell(new Cell().add(new Paragraph("Debit (-) / Credit (+)")));

                    // Step 7: Add Transaction Data to Table
                    boolean hasTransactions = false;
                    while (rs.next()) {
                        hasTransactions = true;
                        int transactionId = rs.getInt("id");
                        String sender = rs.getString("sender_account");
                        String receiver = rs.getString("receiver_account");
                        String type = rs.getString("transaction_type");
                        double amount = rs.getDouble("amount");
                        String date = rs.getString("timestamp");

                        // Determine if it is Debit (-) or Credit (+)
                        String debitCreditIndicator = sender.equals(accountNumber) ? "- " + amount : "+ " + amount;

                        table.addCell(new Cell().add(new Paragraph(String.valueOf(transactionId))));
                        table.addCell(new Cell().add(new Paragraph(sender)));
                        table.addCell(new Cell().add(new Paragraph(receiver)));
                        table.addCell(new Cell().add(new Paragraph(type)));
                        table.addCell(new Cell().add(new Paragraph(String.format("%.2f", amount))));
                        table.addCell(new Cell().add(new Paragraph(date)));
                        table.addCell(new Cell().add(new Paragraph(debitCreditIndicator)));
                    }

                    if (!hasTransactions) {
                        document.add(new Paragraph("No transactions found for the selected period."));
                    } else {
                        document.add(table);
                    }

                    document.close();
                    logger.info("PDF Account Statement Generated: {} for account: {}", pdfFileName, accountNumber);
                    return pdfFileName; // Return file path so it can be used for sending email
                }
            }
        } catch (SQLException e) {
            logger.error("Database error while generating PDF for account {}: {}", accountNumber, e.getMessage(), e);
            throw e;
        } catch (IOException e) {
            logger.error("IO error while generating PDF for account {}: {}", accountNumber, e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error while generating PDF for account {}: {}", accountNumber, e.getMessage(), e);
            throw new IOException("Failed to generate PDF: " + e.getMessage(), e);
        }
    }

    // Method to Send Email with the PDF (Added as requested)
    public static void sendEmailWithPDF(String recipientEmail, String pdfFilePath) throws MessagingException, IOException {
        final String senderEmail = "saltlakesisco@gmail.com";
        final String senderPassword = "wgdl tlfz jmhf itrh";

        // Check if file exists before attempting to send
        File file = new File(pdfFilePath);
        if (!file.exists() || !file.canRead()) {
            logger.error("PDF file not found or cannot be read: {}", pdfFilePath);
            throw new IOException("PDF file not found or cannot be read: " + pdfFilePath);
        }

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
            message.setSubject("Your Bank Account Statement");

            // Create email body part
            BodyPart messageBodyPart = new MimeBodyPart();
            messageBodyPart.setText("Dear Customer,\n\nPlease find attached your bank statement.\n\nBest Regards,\nYour Bank");

            // Attach PDF file
            MimeBodyPart attachmentPart = new MimeBodyPart();
            DataSource source = new FileDataSource(pdfFilePath);
            attachmentPart.setDataHandler(new DataHandler(source));
            attachmentPart.setFileName(file.getName());

            // Combine both parts into multipart
            Multipart multipart = new MimeMultipart();
            multipart.addBodyPart(messageBodyPart);
            multipart.addBodyPart(attachmentPart);

            message.setContent(multipart);

            // Send email
            Transport.send(message);
            logger.info("Email sent successfully with PDF attachment: {} to {}", pdfFilePath, recipientEmail);

        } catch (MessagingException e) {
            logger.error("Failed to send email with PDF to {}: {}", recipientEmail, e.getMessage(), e);
            throw e;
        } finally {
            // Delete the PDF file after sending
            if (file.exists()) {
                if (file.delete()) {
                    logger.info("Deleted temporary PDF file: {}", pdfFilePath);
                } else {
                    logger.warn("Failed to delete temporary PDF file: {}", pdfFilePath);
                }
            }
        }
    }
}