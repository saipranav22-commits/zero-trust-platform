package com.zerotrust.dto.request;

import com.zerotrust.entity.enums.AccountType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

import java.math.BigDecimal;
import java.util.UUID;

public record AccountCreateRequest(
    @NotNull(message = "Customer ID is required")
    UUID customerId,

    @NotBlank(message = "Account number is required")
    String accountNumber,

    @NotNull(message = "Account type is required")
    AccountType accountType,

    @NotNull(message = "Initial deposit balance is required")
    @PositiveOrZero(message = "Initial deposit must be zero or positive")
    BigDecimal initialBalance,

    String currency
) {}
