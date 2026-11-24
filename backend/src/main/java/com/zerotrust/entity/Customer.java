package com.zerotrust.entity;

import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Synthetic Customer Profile Entity for Simulated Financial Services.
 * Strictly uses synthetic mock identifiers (no real PII or government IDs).
 */
@Entity
@Table(name = "customers")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String customerNumber;

    @Column(nullable = false, length = 100)
    private String firstName;

    @Column(nullable = false, length = 100)
    private String lastName;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(length = 50)
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    @Builder.Default
    private KycStatus kycStatus = KycStatus.PENDING;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private RiskTier riskTier = RiskTier.LOW;

    /**
     * Dedicated employee (account manager) assigned to this customer.
     * Crucial for Object-Level Ownership and BOLA/IDOR prevention.
     */
    @Column(name = "assigned_employee_id")
    private UUID assignedEmployeeId;

    /**
     * Synthetic Tax Identifier (e.g., SYN-***-1234).
     * Protected sensitive attribute encrypted at rest via AES-256-GCM.
     * Excluded from toString() to prevent accidental plaintext exposure in application logs.
     */
    @ToString.Exclude
    @Convert(converter = com.zerotrust.security.crypto.EncryptedStringConverter.class)
    @Column(nullable = false, length = 255)
    private String syntheticTaxId;

    @Column(precision = 15, scale = 2)
    private BigDecimal annualIncome;

    private Integer creditScore;

    @OneToMany(mappedBy = "customer", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<Account> accounts = new ArrayList<>();

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    public String getFullName() {
        return firstName + " " + lastName;
    }
}
