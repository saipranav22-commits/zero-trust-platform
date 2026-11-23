package com.zerotrust.dto.request;

import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.PositiveOrZero;

import java.math.BigDecimal;
import java.util.UUID;

public record CustomerUpdateRequest(
    String firstName,
    String lastName,

    @Email(message = "Valid email is required")
    String email,

    String phoneNumber,
    KycStatus kycStatus,
    RiskTier riskTier,
    UUID assignedEmployeeId,

    @PositiveOrZero(message = "Annual income must be positive or zero")
    BigDecimal annualIncome,

    Integer creditScore
) {}
