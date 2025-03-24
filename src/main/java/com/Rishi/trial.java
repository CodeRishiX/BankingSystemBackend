//package com.Rishi;
//
//import java.util.*;
//import java.sql.*;
//public class trial {
//    public static void main(String[] args) {
//        Scanner scanner = new Scanner(System.in);
//
//        try (Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/bank", "root", "")) {
//            System.out.print("Enter your account number: ");
//            String accountNumber = scanner.nextLine();
//
//            System.out.print("Enter month (1-12): ");
//            int month = scanner.nextInt();
//
//            System.out.print("Enter year (e.g., 2025): ");
//            int year = scanner.nextInt();
//
//            PDFStatementGenerator.generatePDFStatement(accountNumber, month, year, con);
//
//        } catch (SQLException e) {
//            e.printStackTrace();
//        }
//    }
//}
//
//
//
//Transaction ID  Sender              Receiver            Transaction Type     Type       Amount          Date
//-----------------------------------------------------------------------------------------------------
//        27              987654321098765     123456789012345     Fund Transfer        Debit      5.00            2025-03-09 11:14:54
//        26              987654321098765     123456789012345     Fund Transfer        Credit     500.00          2025-03-09 11:10:41
//        25              123456789012345     987654321098765     Fund Transfer        Credit     500.00          2025-03-09 10:45:08
//        24              987654321012345     987654321098765     Fund Transfer        Credit     10000.00        2025-03-08 21:36:27
//Balance: 26230.0
//
//        3520.00