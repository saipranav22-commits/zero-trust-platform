package com.zerotrust.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.entity.IdempotencyRecord;
import com.zerotrust.entity.enums.IdempotencyStatus;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.IdempotencyRecordRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Service managing persistent idempotency for critical financial transactions.
 * Guarantees exactly-once mutation semantics across network retries.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IdempotencyService {

    private final IdempotencyRecordRepository idempotencyRecordRepository;
    private final ObjectMapper objectMapper;

    @FunctionalInterface
    public interface TransactionExecutor<T> {
        T execute() throws Exception;
    }

    /**
     * Executes a financial transaction with strict database-backed idempotency protection.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public <T> T executeWithIdempotency(
            String idempotencyKey,
            String userId,
            Object requestPayload,
            Class<T> responseType,
            TransactionExecutor<T> executor) {

        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new ValidationException("Idempotency-Key header is required for transaction execution");
        }

        String safeUserId = (userId != null && !userId.isBlank()) ? userId : "ANONYMOUS";
        String storageKey = safeUserId + ":" + idempotencyKey;
        String requestHash = computeRequestHash(requestPayload);

        Optional<IdempotencyRecord> existingOpt = idempotencyRecordRepository.findById(storageKey);
        if (existingOpt.isPresent()) {
            IdempotencyRecord existing = existingOpt.get();

            if (existing.getStatus() == IdempotencyStatus.COMPLETED) {
                if (!existing.getRequestHash().equals(requestHash)) {
                    log.warn("Idempotency conflict: Key {} reused with differing payload by user {}", idempotencyKey, safeUserId);
                    throw new ValidationException(
                        "Idempotency-Key collision: Key '" + idempotencyKey + "' was already used for a different transaction request."
                    );
                }
                log.info("Idempotent replay: Returning cached transaction result for key {}", idempotencyKey);
                try {
                    return objectMapper.readValue(existing.getResponseBody(), responseType);
                } catch (JsonProcessingException e) {
                    throw new IllegalStateException("Failed to deserialize cached idempotent response", e);
                }
            }

            if (existing.getStatus() == IdempotencyStatus.IN_PROGRESS) {
                log.warn("Concurrent duplicate request detected for idempotency key {}", idempotencyKey);
                throw new ValidationException(
                    "Transaction is currently in progress for Idempotency-Key: " + idempotencyKey + ". Please wait before retrying."
                );
            }

            // If previously failed, remove failed record to permit clean retry
            idempotencyRecordRepository.delete(existing);
            idempotencyRecordRepository.flush();
        }

        // Register in-progress state
        IdempotencyRecord inProgressRecord = IdempotencyRecord.builder()
            .key(storageKey)
            .userId(safeUserId)
            .requestHash(requestHash)
            .status(IdempotencyStatus.IN_PROGRESS)
            .createdAt(Instant.now())
            .expiresAt(Instant.now().plus(24, ChronoUnit.HOURS))
            .build();
        try {
            idempotencyRecordRepository.saveAndFlush(inProgressRecord);
        } catch (org.springframework.dao.DataIntegrityViolationException dive) {
            log.warn("Concurrent duplicate request detected via database constraint for idempotency key {}", idempotencyKey);
            throw new ValidationException(
                "Transaction is currently in progress for Idempotency-Key: " + idempotencyKey + ". Please wait before retrying."
            );
        }

        try {
            T result = executor.execute();
            String responseJson = objectMapper.writeValueAsString(result);

            inProgressRecord.setStatus(IdempotencyStatus.COMPLETED);
            inProgressRecord.setResponseBody(responseJson);
            inProgressRecord.setStatusCode(201);
            idempotencyRecordRepository.save(inProgressRecord);

            return result;
        } catch (Exception ex) {
            log.error("Transaction execution failed under idempotency key {}: {}", idempotencyKey, ex.getMessage());
            inProgressRecord.setStatus(IdempotencyStatus.FAILED);
            idempotencyRecordRepository.save(inProgressRecord);
            if (ex instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException("Transaction execution failed", ex);
        }
    }

    private String computeRequestHash(Object payload) {
        try {
            String json = (payload != null) ? objectMapper.writeValueAsString(payload) : "";
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(json.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new IllegalStateException("Could not compute request hash for idempotency", e);
        }
    }

    /**
     * Periodic purge of expired idempotency records.
     */
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void purgeExpiredRecords() {
        idempotencyRecordRepository.deleteByExpiresAtBefore(Instant.now());
    }
}
