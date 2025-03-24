package com.Rishi;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptionUtil {
    private static final Logger logger = LogManager.getLogger(EncryptionUtil.class);
    private static final String ALGORITHM = "AES";
    private static final String FIXED_KEY = "MySecretKey12345"; // Must be 16, 24, or 32 bytes for AES
    private static final SecretKeySpec key;

    static {
        try {
            // Derive a fixed key from the string (AES requires a 16-byte key for 128-bit)
            byte[] keyBytes = FIXED_KEY.getBytes(StandardCharsets.UTF_8);
            key = new SecretKeySpec(keyBytes, ALGORITHM);
            logger.info("Encryption key initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize encryption key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize encryption key: " + e.getMessage(), e);
        }
    }

    public static String encrypt(String data) {
        if (data == null) {
            logger.warn("Attempted to encrypt null data");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            String encryptedData = Base64.getEncoder().encodeToString(encryptedBytes);
            logger.debug("Encrypted data: {} -> {}", data, encryptedData);
            return encryptedData;
        } catch (Exception e) {
            logger.error("Encryption failed for data {}: {}", data, e.getMessage(), e);
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    public static String decrypt(String encryptedData) {
        if (encryptedData == null) {
            logger.warn("Attempted to decrypt null data");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            String decryptedData = new String(decryptedBytes);
            logger.debug("Decrypted data: {} -> {}", encryptedData, decryptedData);
            return decryptedData;
        } catch (Exception e) {
            logger.error("Decryption failed for data {}: {}", encryptedData, e.getMessage(), e);
            System.out.println("❌ Decryption failed for data: " + encryptedData + ". Error: " + e.getMessage());
            return null;
        }
    }
}