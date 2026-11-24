package com.zerotrust.dto.request;

import com.zerotrust.entity.enums.TransactionType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.math.BigDecimal;
import java.util.UUID;

public record TransactionCreateRequest(
    @NotNull(message = "Account ID is required")
    UUID accountId,

    @NotNull(message = "Amount is required")
    @Positive(message = "Amount must be strictly positive")
    BigDecimal amount,

    @NotNull(message = "Transaction type is required")
    TransactionType type,

    @NotBlank(message = "Description is required")
    String description,

    String destinationAccount
) {}
