package com.zerotrust.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zerotrust.entity.Account;
import com.zerotrust.entity.enums.AccountStatus;
import com.zerotrust.entity.enums.AccountType;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AccountResponse(
    UUID id,
    UUID customerId,
    String accountNumber,
    AccountType accountType,
    BigDecimal balance,
    String currency,
    AccountStatus status,
    Instant createdAt,
    Instant updatedAt
) {
    public static AccountResponse from(Account a) {
        return new AccountResponse(
            a.getId(),
            a.getCustomer() != null ? a.getCustomer().getId() : null,
            a.getAccountNumber(),
            a.getAccountType(),
            a.getBalance(),
            a.getCurrency(),
            a.getStatus(),
            a.getCreatedAt(),
            a.getUpdatedAt()
        );
    }
}
