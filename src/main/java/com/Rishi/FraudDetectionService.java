package com.Rishi;

import java.io.*;
import java.net.*;
import org.json.JSONObject;
import org.apache.logging.log4j.LogManager;  // Import Log4j2
import org.apache.logging.log4j.Logger;      // Import Logger

public class FraudDetectionService {
    // Initialize Logger
    private static final Logger logger = LogManager.getLogger(FraudDetectionService.class);

    public static boolean isTransactionFraudulent(double amount, double oldbalanceOrg, double newbalanceOrig,
                                                  double oldbalanceDest, double newbalanceDest, String transactionType) {
        try {
            // ✅ Flask API URL
            URL url = new URL("http://127.0.0.1:5000/predict");

            // ✅ Open Connection
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            // ✅ Create JSON Request
            JSONObject json = new JSONObject();
            json.put("amount", amount);
            json.put("oldbalanceOrg", oldbalanceOrg);
            json.put("newbalanceOrig", newbalanceOrig);
            json.put("oldbalanceDest", oldbalanceDest);
            json.put("newbalanceDest", newbalanceDest);
            json.put("transaction_type", transactionType);

            // ✅ Send JSON Request
            OutputStream os = conn.getOutputStream();
            os.write(json.toString().getBytes());
            os.flush();
            os.close();

            // ✅ Read Response
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line);
            }
            in.close();

            // ✅ Parse Response
            JSONObject jsonResponse = new JSONObject(response.toString());
            boolean isFraud = jsonResponse.getBoolean("is_fraud");
            double fraudProbability = jsonResponse.getDouble("fraud_probability");

            // ✅ Log API Response
            logger.info("📌 Fraud Probability: {}", fraudProbability);
            logger.info("📌 Is Fraudulent? {}", isFraud);

            return isFraud; // ✅ Return Fraud Detection Result

        } catch (Exception e) {
            logger.error("Error in Fraud Detection API call: {}", e.getMessage(), e);
            return false; // Default to Non-Fraud if API Call Fails
        }
    }
}