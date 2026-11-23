package com.zerotrust.dto.request;

import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;

import java.math.BigDecimal;
import java.util.UUID;

public record CustomerCreateRequest(
    @NotBlank(message = "Customer number is required")
    String customerNumber,

    @NotBlank(message = "First name is required")
    String firstName,

    @NotBlank(message = "Last name is required")
    String lastName,

    @NotBlank(message = "Email is required")
    @Email(message = "Valid email is required")
    String email,

    String phoneNumber,

    KycStatus kycStatus,

    RiskTier riskTier,

    UUID assignedEmployeeId,

    @NotBlank(message = "Synthetic tax ID is required")
    String syntheticTaxId,

    @PositiveOrZero(message = "Annual income must be positive or zero")
    BigDecimal annualIncome,

    Integer creditScore
) {}
