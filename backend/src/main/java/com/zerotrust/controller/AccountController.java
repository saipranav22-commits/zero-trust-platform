package com.zerotrust.controller;

import com.zerotrust.dto.request.AccountCreateRequest;
import com.zerotrust.dto.response.AccountResponse;
import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.entity.enums.AccountStatus;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.AccountService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/accounts")
@RequiredArgsConstructor
@Tag(name = "Customer Accounts", description = "Financial account management with object-level authorization")
public class AccountController {

    private final AccountService accountService;

    private SecuritySubject getSubject(HttpServletRequest request, Authentication auth) {
        String userId = (String) request.getAttribute("userId");
        return SecuritySubject.from(auth, userId);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get account details by ID (enforces parent customer ownership)")
    public ResponseEntity<ApiResponse<AccountResponse>> getAccount(
            @PathVariable UUID id,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        return ResponseEntity.ok(ApiResponse.success(accountService.getAccountById(id, subject)));
    }

    @GetMapping("/customer/{customerId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get all accounts for a customer (enforces customer ownership)")
    public ResponseEntity<ApiResponse<List<AccountResponse>>> getCustomerAccounts(
            @PathVariable UUID customerId,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        return ResponseEntity.ok(ApiResponse.success(accountService.getAccountsByCustomerId(customerId, subject)));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'EMPLOYEE')")
    @Operation(summary = "Open a new financial account for a customer")
    public ResponseEntity<ApiResponse<AccountResponse>> createAccount(
            @Valid @RequestBody AccountCreateRequest createRequest,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        AccountResponse created = accountService.createAccount(createRequest, subject);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.success(created, "Account opened successfully"));
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'EMPLOYEE')")
    @Operation(summary = "Update account status (e.g. FROZEN, ACTIVE)")
    public ResponseEntity<ApiResponse<AccountResponse>> updateStatus(
            @PathVariable UUID id,
            @RequestParam AccountStatus status,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        return ResponseEntity.ok(ApiResponse.success(
            accountService.updateAccountStatus(id, status, subject), "Account status updated"));
    }
}
