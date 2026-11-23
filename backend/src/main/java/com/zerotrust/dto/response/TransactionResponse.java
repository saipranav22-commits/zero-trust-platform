package com.zerotrust.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zerotrust.entity.Transaction;
import com.zerotrust.entity.enums.TransactionStatus;
import com.zerotrust.entity.enums.TransactionType;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TransactionResponse(
    UUID id,
    UUID accountId,
    String referenceNumber,
    BigDecimal amount,
    TransactionType type,
    TransactionStatus status,
    String description,
    String sourceAccount,
    String destinationAccount,
    UUID correlationId,
    Instant createdAt
) {
    public static TransactionResponse from(Transaction t) {
        return new TransactionResponse(
            t.getId(),
            t.getAccount() != null ? t.getAccount().getId() : null,
            t.getReferenceNumber(),
            t.getAmount(),
            t.getType(),
            t.getStatus(),
            t.getDescription(),
            t.getSourceAccount(),
            t.getDestinationAccount(),
            t.getCorrelationId(),
            t.getCreatedAt()
        );
    }
}
