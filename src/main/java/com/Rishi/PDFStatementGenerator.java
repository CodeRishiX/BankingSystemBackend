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

public class PDFStatementGenerator {

    // ✅ Define the directory where PDFs will be saved
    public static final String PDF_DIR = "C:\\Users\\Debangshu\\Documents\\bank_statements(project)\\";

    // ✅ Method to generate the PDF Statement
    public static String generatePDFStatement(String accountNumber, int month, int year, Connection con) {
        String pdfFileName = PDF_DIR + "Statement_" + accountNumber + "_" + month + "_" + year + ".pdf";

        try {
            // ✅ Added Validation for Month and Year
            if (month < 1 || month > 12) {
                System.out.println("❌ Invalid month! Must be between 1 and 12.");
                return null;
            }
            if (year < 1900 || year > 9999) { // Reasonable range for year
                System.out.println("❌ Invalid year! Must be between 1900 and 9999.");
                return null;
            }

            // ✅ Step 1: Ensure the directory exists
            File directory = new File(PDF_DIR);
            if (!directory.exists()) {
                directory.mkdirs(); // ✅ Creates folder if not exists
            }

            // ✅ Step 2: Fetch Transactions from Database (Only Completed Transactions)
            String query = "SELECT id, sender_account, receiver_account, transaction_type, amount, timestamp " +
                    "FROM transactions " +
                    "WHERE (sender_account = ? OR receiver_account = ?) " +
                    "AND status = 'Completed' " + // Filter for completed transactions only
                    "AND MONTH(timestamp) = ? AND YEAR(timestamp) = ? " +
                    "ORDER BY timestamp DESC";

            PreparedStatement pstmt = con.prepareStatement(query);
            pstmt.setString(1, accountNumber);
            pstmt.setString(2, accountNumber);
            pstmt.setInt(3, month);
            pstmt.setInt(4, year);
            ResultSet rs = pstmt.executeQuery();

            // ✅ Step 3: Create PDF File
            PdfWriter writer = new PdfWriter(pdfFileName);
            PdfDocument pdf = new PdfDocument(writer);
            Document document = new Document(pdf);

            // ✅ Step 4: Add Header
            document.add(new Paragraph("Bank Account Statement").setBold().setFontSize(16));
            document.add(new Paragraph("Account Number: " + accountNumber));
            document.add(new Paragraph("Month: " + month + " | Year: " + year + "\n\n"));

            // ✅ Step 5: Create Table
            Table table = new Table(7); // 7 columns for Transaction ID, Sender, Receiver, Type, Amount, Date, Debit/Credit
            table.addCell(new Cell().add(new Paragraph("Transaction ID")));
            table.addCell(new Cell().add(new Paragraph("Sender")));
            table.addCell(new Cell().add(new Paragraph("Receiver")));
            table.addCell(new Cell().add(new Paragraph("Type")));
            table.addCell(new Cell().add(new Paragraph("Amount")));
            table.addCell(new Cell().add(new Paragraph("Date")));
            table.addCell(new Cell().add(new Paragraph("Debit (-) / Credit (+)")));

            // ✅ Step 6: Add Transaction Data to Table
            boolean hasTransactions = false;
            while (rs.next()) {
                hasTransactions = true;
                int transactionId = rs.getInt("id");
                String sender = rs.getString("sender_account");
                String receiver = rs.getString("receiver_account");
                String type = rs.getString("transaction_type");
                double amount = rs.getDouble("amount");
                String date = rs.getString("timestamp");

                // ✅ Determine if it is Debit (-) or Credit (+)
                String debitCreditIndicator = sender.equals(accountNumber) ? "- " + amount : "+ " + amount;

                table.addCell(new Cell().add(new Paragraph(String.valueOf(transactionId))));
                table.addCell(new Cell().add(new Paragraph(sender)));
                table.addCell(new Cell().add(new Paragraph(receiver)));
                table.addCell(new Cell().add(new Paragraph(type)));
                table.addCell(new Cell().add(new Paragraph(String.format("%.2f", amount))));
                table.addCell(new Cell().add(new Paragraph(date)));
                table.addCell(new Cell().add(new Paragraph(debitCreditIndicator))); // ✅ Debit (-) / Credit (+)
            }

            if (!hasTransactions) {
                document.add(new Paragraph("No transactions found for the selected period."));
            } else {
                document.add(table);
            }

            document.close();
            System.out.println("✅ PDF Account Statement Generated: " + pdfFileName);
            return pdfFileName; // ✅ Return file path so it can be used for sending email

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ✅ Method to Send Email with the PDF
    public static void sendEmailWithPDF(String recipientEmail, String pdfFilePath) {
        final String senderEmail = "saltlakesisco@gmail.com";  // ✅ Your email
        final String senderPassword = "wgdl tlfz jmhf itrh"; // ✅ Your App Password (Not Gmail Password)

        // ✅ Check if file exists before attempting to send
        File file = new File(pdfFilePath);
        if (!file.exists() || !file.canRead()) {
            System.out.println("❌ Error: PDF file not found or cannot be read.");
            return;
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

            // ✅ Create email body part
            BodyPart messageBodyPart = new MimeBodyPart();
            messageBodyPart.setText("Dear Customer,\n\nPlease find attached your bank statement.\n\nBest Regards,\nYour Bank");

            // ✅ Attach PDF file
            MimeBodyPart attachmentPart = new MimeBodyPart();
            DataSource source = new FileDataSource(pdfFilePath);
            attachmentPart.setDataHandler(new DataHandler(source));
            attachmentPart.setFileName(file.getName()); // ✅ Dynamically set filename

            // ✅ Combine both parts into multipart
            Multipart multipart = new MimeMultipart();
            multipart.addBodyPart(messageBodyPart);
            multipart.addBodyPart(attachmentPart);

            message.setContent(multipart);

            // ✅ Send email
            Transport.send(message);
            System.out.println("✅ Email sent successfully with PDF attachment: " + pdfFilePath);

        } catch (MessagingException e) {
            e.printStackTrace();
            System.out.println("❌ Failed to send email.");
        }
    }
}