package com.zerotrust.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.entity.IdempotencyRecord;
import com.zerotrust.entity.enums.IdempotencyStatus;
import com.zerotrust.entity.enums.TransactionStatus;
import com.zerotrust.entity.enums.TransactionType;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.IdempotencyRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IdempotencyIntegrationTest {

    @Mock
    private IdempotencyRecordRepository idempotencyRecordRepository;

    private ObjectMapper objectMapper;
    private IdempotencyService idempotencyService;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        idempotencyService = new IdempotencyService(idempotencyRecordRepository, objectMapper);
    }

    @Test
    @DisplayName("Should execute transaction and save completed idempotency record")
    void shouldExecuteAndPersistIdempotencyRecord() {
        String key = "key-uuid-1001";
        String userId = "user-abc";
        String storageKey = userId + ":" + key;
        TransactionCreateRequest request = new TransactionCreateRequest(
            UUID.randomUUID(),
            new BigDecimal("100.00"),
            TransactionType.DEPOSIT,
            "Deposit test",
            null
        );

        when(idempotencyRecordRepository.findById(storageKey)).thenReturn(Optional.empty());

        TransactionResponse response = idempotencyService.executeWithIdempotency(
            key, userId, request, TransactionResponse.class,
            () -> new TransactionResponse(
                UUID.randomUUID(), request.accountId(), "TXN-1",
                request.amount(), request.type(), TransactionStatus.COMPLETED,
                request.description(), null, null, null, Instant.now()
            )
        );

        assertThat(response).isNotNull();
        assertThat(response.referenceNumber()).isEqualTo("TXN-1");
        verify(idempotencyRecordRepository, times(1)).saveAndFlush(any(IdempotencyRecord.class));
        verify(idempotencyRecordRepository, times(1)).save(any(IdempotencyRecord.class));
    }

    @Test
    @DisplayName("Duplicate request with same idempotency key and payload returns cached response without re-executing")
    void shouldReturnCachedResponseOnDuplicateRequest() throws Exception {
        String key = "key-uuid-1002";
        String userId = "user-abc";
        String storageKey = userId + ":" + key;
        TransactionCreateRequest request = new TransactionCreateRequest(
            UUID.randomUUID(),
            new BigDecimal("50.00"),
            TransactionType.DEPOSIT,
            "Replay deposit",
            null
        );

        // Compute request hash
        String json = objectMapper.writeValueAsString(request);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        String expectedHash = java.util.HexFormat.of().formatHex(md.digest(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        TransactionResponse cachedResponse = new TransactionResponse(
            UUID.randomUUID(), request.accountId(), "TXN-ORIGINAL",
            request.amount(), request.type(), TransactionStatus.COMPLETED,
            request.description(), null, null, null, Instant.now()
        );

        IdempotencyRecord completedRecord = IdempotencyRecord.builder()
            .key(storageKey)
            .userId(userId)
            .requestHash(expectedHash)
            .status(IdempotencyStatus.COMPLETED)
            .responseBody(objectMapper.writeValueAsString(cachedResponse))
            .statusCode(201)
            .createdAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(3600))
            .build();

        when(idempotencyRecordRepository.findById(storageKey)).thenReturn(Optional.of(completedRecord));

        AtomicInteger executionCount = new AtomicInteger(0);
        TransactionResponse replayed = idempotencyService.executeWithIdempotency(
            key, userId, request, TransactionResponse.class,
            () -> {
                executionCount.incrementAndGet();
                return null;
            }
        );

        assertThat(replayed).isNotNull();
        assertThat(replayed.referenceNumber()).isEqualTo("TXN-ORIGINAL");
        assertThat(executionCount.get()).isEqualTo(0); // Underlying business logic NEVER re-executed!
    }

    @Test
    @DisplayName("Reusing same idempotency key with differing payload must throw ValidationException (Conflict)")
    void shouldRejectIdempotencyKeyCollisionWithDifferingPayload() {
        String key = "key-uuid-1003";
        String userId = "user-abc";
        String storageKey = userId + ":" + key;

        TransactionCreateRequest original = new TransactionCreateRequest(
            UUID.randomUUID(), new BigDecimal("100.00"), TransactionType.DEPOSIT, "Original", null
        );
        TransactionCreateRequest altered = new TransactionCreateRequest(
            UUID.randomUUID(), new BigDecimal("200.00"), TransactionType.DEPOSIT, "Altered", null
        );

        IdempotencyRecord completedRecord = IdempotencyRecord.builder()
            .key(storageKey)
            .userId(userId)
            .requestHash("hash-of-original-request")
            .status(IdempotencyStatus.COMPLETED)
            .responseBody("{}")
            .statusCode(201)
            .createdAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(3600))
            .build();

        when(idempotencyRecordRepository.findById(storageKey)).thenReturn(Optional.of(completedRecord));

        assertThatThrownBy(() -> idempotencyService.executeWithIdempotency(
            key, userId, altered, TransactionResponse.class, () -> null
        )).isInstanceOf(ValidationException.class)
          .hasMessageContaining("Idempotency-Key collision");
    }

    @Test
    @DisplayName("Concurrent in-progress request with same key must be rejected")
    void shouldRejectConcurrentDuplicateInProgress() {
        String key = "key-uuid-1004";
        String userId = "user-abc";
        String storageKey = userId + ":" + key;
        TransactionCreateRequest request = new TransactionCreateRequest(
            UUID.randomUUID(), new BigDecimal("100.00"), TransactionType.DEPOSIT, "Concurrent", null
        );

        IdempotencyRecord inProgressRecord = IdempotencyRecord.builder()
            .key(storageKey)
            .userId(userId)
            .requestHash("hash")
            .status(IdempotencyStatus.IN_PROGRESS)
            .createdAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(3600))
            .build();

        when(idempotencyRecordRepository.findById(storageKey)).thenReturn(Optional.of(inProgressRecord));

        assertThatThrownBy(() -> idempotencyService.executeWithIdempotency(
            key, userId, request, TransactionResponse.class, () -> null
        )).isInstanceOf(ValidationException.class)
          .hasMessageContaining("Transaction is currently in progress");
    }
}
