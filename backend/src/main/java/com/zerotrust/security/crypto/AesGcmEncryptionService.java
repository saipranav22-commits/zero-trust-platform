package com.zerotrust.security.crypto;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM Authenticated Encryption Service.
 * Provides authenticated encryption for sensitive synthetic customer data at rest.
 * Uses 96-bit (12-byte) random nonces, 128-bit authentication tags, and versioned ciphertext packaging.
 */
@Slf4j
@Service
public class AesGcmEncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final String VERSION_PREFIX = "v1:";

    private final SecureRandom secureRandom = new SecureRandom();
    private final String configuredKey;
    private final boolean allowLegacyPlaintext;
    private SecretKey secretKey;

    @org.springframework.beans.factory.annotation.Autowired
    public AesGcmEncryptionService(
            @Value("${app.security.encryption.key:}") String configuredKey,
            @Value("${app.security.encryption.allow-legacy-plaintext:false}") boolean allowLegacyPlaintext) {
        this.configuredKey = configuredKey;
        this.allowLegacyPlaintext = allowLegacyPlaintext;
    }

    public AesGcmEncryptionService(String configuredKey) {
        this(configuredKey, false);
    }

    @PostConstruct
    public void validateAndInitialize() {
        if (!StringUtils.hasText(configuredKey)) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: app.security.encryption.key must be configured with a 256-bit Base64-encoded key.");
        }
        try {
            byte[] decodedKey = Base64.getDecoder().decode(configuredKey.trim());
            if (decodedKey.length != 32) {
                throw new IllegalStateException("CRITICAL SECURITY ERROR: app.security.encryption.key must decode to exactly 32 bytes (256 bits). Found: " + decodedKey.length + " bytes.");
            }
            this.secretKey = new SecretKeySpec(decodedKey, "AES");
            log.info("🔐 AES-256-GCM encryption service successfully initialized with 256-bit key.");
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("CRITICAL SECURITY ERROR: app.security.encryption.key is not a valid Base64 string.", ex);
        }
    }

    /**
     * Encrypts plaintext using AES-256-GCM with a cryptographically secure random 12-byte nonce.
     * Formats output as "v1:<Base64(IV + Ciphertext + Tag)>"
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        if (plaintext.isEmpty()) {
            return "";
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherBytes, 0, combined, iv.length, cipherBytes.length);

            return VERSION_PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (Exception ex) {
            log.error("Encryption failure: {}", ex.getClass().getSimpleName());
            throw new SecurityException("Failed to perform authenticated encryption", ex);
        }
    }

    /**
     * Decrypts versioned ciphertext ("v1:<Base64(IV + Ciphertext + Tag)>").
     * Authenticates ciphertext using the GCM tag; throws SecurityException on tamper or invalid key.
     */
    public String decrypt(String ciphertextWithVersion) {
        if (ciphertextWithVersion == null) {
            return null;
        }
        if (ciphertextWithVersion.isEmpty()) {
            return "";
        }
        if (!isEncrypted(ciphertextWithVersion)) {
            if (allowLegacyPlaintext) {
                log.warn("⚠️ Legacy plaintext customer record read. Backfill migration should be executed immediately.");
                return ciphertextWithVersion;
            }
            throw new SecurityException("Decryption error: Unencrypted legacy plaintext encountered while strict encryption policy is active.");
        }
        try {
            String encodedPayload = ciphertextWithVersion.substring(VERSION_PREFIX.length());
            byte[] combined = Base64.getDecoder().decode(encodedPayload);

            if (combined.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
                throw new SecurityException("Malformed ciphertext payload: insufficient length for IV and tag");
            }

            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH_BYTES);

            int cipherLength = combined.length - GCM_IV_LENGTH_BYTES;
            byte[] cipherBytes = new byte[cipherLength];
            System.arraycopy(combined, GCM_IV_LENGTH_BYTES, cipherBytes, 0, cipherLength);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] plainBytes = cipher.doFinal(cipherBytes);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (SecurityException se) {
            throw se;
        } catch (Exception ex) {
            log.warn("Decryption authentication verification failed: {}", ex.getClass().getSimpleName());
            throw new SecurityException("Decryption failed: tampered ciphertext or invalid key", ex);
        }
    }

    /**
     * Checks if a string has the versioned ciphertext prefix.
     */
    public boolean isEncrypted(String text) {
        return text != null && text.startsWith(VERSION_PREFIX);
    }
}
