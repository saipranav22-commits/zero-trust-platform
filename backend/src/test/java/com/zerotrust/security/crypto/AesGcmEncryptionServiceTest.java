package com.zerotrust.security.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmEncryptionServiceTest {

    private static final String VALID_KEY_BASE64 = "k+u7V2Xg4qH8lK9pY0rW3tU6yI8oP1aS4dF7gJ0kM3o="; // 32 bytes (256 bits)
    private static final String ANOTHER_KEY_BASE64 = "9xY7V2Xg4qH8lK9pY0rW3tU6yI8oP1aS4dF7gJ0kM3o="; // Different 32-byte key

    private AesGcmEncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        encryptionService = new AesGcmEncryptionService(VALID_KEY_BASE64);
        encryptionService.validateAndInitialize();
    }

    @Test
    @DisplayName("1. Encrypt and decrypt round trip preserves plaintext")
    void testEncryptionRoundTrip() {
        String plaintext = "SYN-987-6543";

        String ciphertext = encryptionService.encrypt(plaintext);

        assertThat(ciphertext).isNotNull();
        assertThat(ciphertext).startsWith("v1:");
        assertThat(ciphertext).isNotEqualTo(plaintext);
        assertThat(ciphertext).doesNotContain(plaintext);

        String decrypted = encryptionService.decrypt(ciphertext);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("2. Identical plaintexts produce distinct ciphertexts with unique IVs (IND-CPA)")
    void testUniqueNoncesForIdenticalPlaintext() {
        String plaintext = "SYN-123-4567";

        String ciphertext1 = encryptionService.encrypt(plaintext);
        String ciphertext2 = encryptionService.encrypt(plaintext);

        assertThat(ciphertext1).isNotEqualTo(ciphertext2);
        assertThat(encryptionService.decrypt(ciphertext1)).isEqualTo(plaintext);
        assertThat(encryptionService.decrypt(ciphertext2)).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("3. Tampered ciphertext payload throws SecurityException")
    void testTamperedCiphertextThrowsSecurityException() {
        String plaintext = "SYN-CONFIDENTIAL-DATA";
        String ciphertext = encryptionService.encrypt(plaintext);

        // Tamper with the base64-encoded body
        String prefix = "v1:";
        String body = ciphertext.substring(prefix.length());
        byte[] decoded = Base64.getDecoder().decode(body);

        // Flip bits in the ciphertext portion
        decoded[decoded.length - 5] ^= 0x5A;
        String tamperedCiphertext = prefix + Base64.getEncoder().encodeToString(decoded);

        assertThatThrownBy(() -> encryptionService.decrypt(tamperedCiphertext))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("tampered ciphertext or invalid key");
    }

    @Test
    @DisplayName("4. Tampered IV/nonce throws SecurityException")
    void testTamperedIvThrowsSecurityException() {
        String plaintext = "SYN-CONFIDENTIAL-DATA";
        String ciphertext = encryptionService.encrypt(plaintext);

        String prefix = "v1:";
        String body = ciphertext.substring(prefix.length());
        byte[] decoded = Base64.getDecoder().decode(body);

        // Flip bits in the IV portion (first 12 bytes)
        decoded[2] ^= 0xFF;
        String tamperedIvCiphertext = prefix + Base64.getEncoder().encodeToString(decoded);

        assertThatThrownBy(() -> encryptionService.decrypt(tamperedIvCiphertext))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("tampered ciphertext or invalid key");
    }

    @Test
    @DisplayName("5. Decrypting with wrong 256-bit key throws SecurityException")
    void testWrongKeyThrowsSecurityException() {
        String plaintext = "SYN-SECRET-FIELD";
        String ciphertext = encryptionService.encrypt(plaintext);

        AesGcmEncryptionService wrongKeyService = new AesGcmEncryptionService(ANOTHER_KEY_BASE64);
        wrongKeyService.validateAndInitialize();

        assertThatThrownBy(() -> wrongKeyService.decrypt(ciphertext))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("tampered ciphertext or invalid key");
    }

    @Test
    @DisplayName("6. Unencrypted legacy data behavior governed by explicit migration policy")
    void testLegacyUnencryptedDataPolicy() {
        String legacyPlaintext = "SYN-OLD-UNENCRYPTED";

        // Under default strict mode (allowLegacyPlaintext = false), unencrypted records throw SecurityException
        assertThatThrownBy(() -> encryptionService.decrypt(legacyPlaintext))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("Unencrypted legacy plaintext encountered while strict encryption policy is active");

        // Under controlled migration policy (allowLegacyPlaintext = true), unencrypted records pass through for backfill
        AesGcmEncryptionService migrationService = new AesGcmEncryptionService(VALID_KEY_BASE64, true);
        migrationService.validateAndInitialize();
        assertThat(migrationService.decrypt(legacyPlaintext)).isEqualTo(legacyPlaintext);
    }

    @Test
    @DisplayName("7. Startup validation rejects missing encryption key with IllegalStateException")
    void testMissingKeyStartupValidation() {
        AesGcmEncryptionService missingKeyService = new AesGcmEncryptionService("");
        assertThatThrownBy(missingKeyService::validateAndInitialize)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("app.security.encryption.key must be configured");
    }

    @Test
    @DisplayName("8. Startup validation rejects key with invalid byte length (not 32 bytes)")
    void testInvalidKeyLengthStartupValidation() {
        // 16-byte key (128 bits) instead of 32 bytes (256 bits)
        String shortKeyBase64 = Base64.getEncoder().encodeToString(new byte[16]);
        AesGcmEncryptionService invalidKeyService = new AesGcmEncryptionService(shortKeyBase64);
        assertThatThrownBy(invalidKeyService::validateAndInitialize)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("must decode to exactly 32 bytes (256 bits)");
    }
}
