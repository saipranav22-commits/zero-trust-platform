package com.zerotrust.security.crypto;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Safe, idempotent, restartable backfill migration runner for customer synthetic tax identifiers.
 * Detects legacy plaintext customer records created prior to Phase 4, encrypts them using AES-256-GCM,
 * and updates them in-place while preserving customer IDs, account links, and financial transactions.
 */
@Slf4j
@Component
@Order(50)
@RequiredArgsConstructor
public class CustomerEncryptionBackfillService implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;
    private final AesGcmEncryptionService encryptionService;

    @Override
    public void run(ApplicationArguments args) {
        executeBackfill();
    }

    /**
     * Executes backfill migration and verifies complete encryption of customer identifiers.
     *
     * @return count of legacy records migrated and encrypted.
     */
    @Transactional
    public int executeBackfill() {
        try {
            // Find records where synthetic_tax_id does not start with the 'v1:' versioned ciphertext prefix
            String findSql = "SELECT id, synthetic_tax_id FROM customers WHERE synthetic_tax_id IS NOT NULL AND synthetic_tax_id NOT LIKE 'v1:%'";
            List<Map<String, Object>> unencryptedRecords = jdbcTemplate.queryForList(findSql);

            if (unencryptedRecords.isEmpty()) {
                log.info("🔐 AES-256-GCM database verification: All customer records are securely encrypted (0 legacy records).");
                return 0;
            }

            log.warn("⚠️ Found {} legacy unencrypted customer records. Initiating AES-256-GCM backfill migration...", unencryptedRecords.size());
            int migratedCount = 0;

            for (Map<String, Object> record : unencryptedRecords) {
                Object rawId = record.get("id");
                String rawTaxId = (String) record.get("synthetic_tax_id");

                if (rawTaxId != null && !encryptionService.isEncrypted(rawTaxId)) {
                    String ciphertext = encryptionService.encrypt(rawTaxId);
                    int updated = jdbcTemplate.update(
                        "UPDATE customers SET synthetic_tax_id = ? WHERE id = ? AND synthetic_tax_id NOT LIKE 'v1:%'",
                        ciphertext, rawId
                    );
                    migratedCount += updated;
                }
            }

            // Verification check: ensure no unencrypted records remain
            Integer remaining = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM customers WHERE synthetic_tax_id IS NOT NULL AND synthetic_tax_id NOT LIKE 'v1:%'",
                Integer.class
            );

            if (remaining != null && remaining > 0) {
                throw new IllegalStateException("Critical Migration Failure: " + remaining + " customer records remain unencrypted in database!");
            }

            log.info("✅ Database backfill migration complete: Successfully encrypted {} legacy customer records with AES-256-GCM.", migratedCount);
            return migratedCount;
        } catch (Exception ex) {
            log.error("Customer encryption backfill migration failed: {}", ex.getMessage());
            throw ex;
        }
    }
}
