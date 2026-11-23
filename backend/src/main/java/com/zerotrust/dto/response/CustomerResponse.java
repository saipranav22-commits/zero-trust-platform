package com.zerotrust.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zerotrust.entity.Customer;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CustomerResponse(
    UUID id,
    String customerNumber,
    String firstName,
    String lastName,
    String fullName,
    String email,
    String phoneNumber,
    KycStatus kycStatus,
    RiskTier riskTier,
    UUID assignedEmployeeId,
    String maskedTaxId,
    BigDecimal annualIncome,
    Integer creditScore,
    Instant createdAt,
    Instant updatedAt
) {
    public static CustomerResponse from(Customer c) {
        return new CustomerResponse(
            c.getId(),
            c.getCustomerNumber(),
            c.getFirstName(),
            c.getLastName(),
            c.getFullName(),
            c.getEmail(),
            c.getPhoneNumber(),
            c.getKycStatus(),
            c.getRiskTier(),
            c.getAssignedEmployeeId(),
            maskTaxId(c.getSyntheticTaxId()),
            c.getAnnualIncome(),
            c.getCreditScore(),
            c.getCreatedAt(),
            c.getUpdatedAt()
        );
    }

    public static String maskTaxId(String rawTaxId) {
        if (rawTaxId == null || rawTaxId.length() < 4) {
            return "SYN-***-XXXX";
        }
        String lastFour = rawTaxId.substring(rawTaxId.length() - 4);
        return "SYN-***-" + lastFour;
    }
}
