package com.Rishi;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FraudDetectionService {
    private static final Logger logger = LogManager.getLogger(FraudDetectionService.class);

    // Custom exception for fraud detection failures
    public static class FraudDetectionException extends Exception {
        public FraudDetectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static boolean isTransactionFraudulent(double amount, double oldbalanceOrg, double newbalanceOrig,
                                                  double oldbalanceDest, double newbalanceDest, String transactionType) throws FraudDetectionException {
        try {
            // Use environment variable for Flask API URL, default to local for development
            String flaskApiUrl = System.getenv("FLASK_API_URL") != null ? System.getenv("FLASK_API_URL") : "http://127.0.0.1:5000/predict";
            logger.info("Calling Fraud Detection API at: {}", flaskApiUrl);

            // Create HttpClient
            HttpClient client = HttpClient.newHttpClient();

            // Create JSON Request
            JSONObject json = new JSONObject();
            json.put("amount", amount);
            json.put("oldbalanceOrg", oldbalanceOrg);
            json.put("newbalanceOrig", newbalanceOrig);
            json.put("oldbalanceDest", oldbalanceDest);
            json.put("newbalanceDest", newbalanceDest);
            json.put("transaction_type", transactionType);
            logger.info("Sending JSON to Flask API: {}", json.toString()); // Add this to log the JSON payload

            // Build HTTP Request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(flaskApiUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
                    .build();

            // Send HTTP Request and get response
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Log response details
            logger.info("Fraud Detection API response status: {}", response.statusCode()); // Add this
            logger.info("Fraud Detection API response body: {}", response.body()); // Add this

            // Check response status
            if (response.statusCode() != 200) {
                logger.error("Fraud Detection API returned non-OK status: {}", response.statusCode());
                throw new FraudDetectionException("Fraud Detection API returned non-OK status: " + response.statusCode(), null);
            }

            // Parse Response
            JSONObject jsonResponse = new JSONObject(response.body());
            boolean isFraud = jsonResponse.getBoolean("is_fraud");
            double fraudProbability = jsonResponse.getDouble("fraud_probability");

            // Log API Response
            logger.info("📌 Fraud Probability: {}", fraudProbability);
            logger.info("📌 Is Fraudulent? {}", isFraud);

            return isFraud; // Return Fraud Detection Result

        } catch (java.net.http.HttpTimeoutException e) {
            logger.error("Timeout error in Fraud Detection API call: {}", e.getMessage(), e);
            throw new FraudDetectionException("Timeout error in Fraud Detection API: " + e.getMessage(), e);
        } catch (java.io.IOException e) {
            logger.error("IO error in Fraud Detection API call: {}", e.getMessage(), e);
            throw new FraudDetectionException("Failed to connect to Fraud Detection API: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            logger.error("Interrupted error in Fraud Detection API call: {}", e.getMessage(), e);
            Thread.currentThread().interrupt(); // Restore interrupted status
            throw new FraudDetectionException("Interrupted during Fraud Detection API call: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error in Fraud Detection API call: {}", e.getMessage(), e);
            throw new FraudDetectionException("Unexpected error in Fraud Detection API: " + e.getMessage(), e);
        }
    }
}