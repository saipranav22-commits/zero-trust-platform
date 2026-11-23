package com.zerotrust.controller;

import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.TransactionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/transactions")
@RequiredArgsConstructor
@Tag(name = "Financial Transactions", description = "Transaction execution and ledger tracking with ABAC verification")
public class TransactionController {

    private final TransactionService transactionService;

    private SecuritySubject getSubject(HttpServletRequest request, Authentication auth) {
        String userId = (String) request.getAttribute("userId");
        return SecuritySubject.from(auth, userId);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get transaction details by ID")
    public ResponseEntity<ApiResponse<TransactionResponse>> getTransaction(
            @PathVariable UUID id,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        return ResponseEntity.ok(ApiResponse.success(transactionService.getTransactionById(id, subject)));
    }

    @GetMapping("/account/{accountId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get paginated transaction ledger for an account")
    public ResponseEntity<ApiResponse<PageResponse<TransactionResponse>>> getAccountTransactions(
            @PathVariable UUID accountId,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        var page = transactionService.getTransactionsByAccountId(accountId, subject, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'EMPLOYEE')")
    @Operation(summary = "Execute a financial transaction (deposit, withdrawal, transfer) with idempotency")
    public ResponseEntity<ApiResponse<TransactionResponse>> executeTransaction(
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @Valid @RequestBody TransactionCreateRequest createRequest,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        TransactionResponse executed = transactionService.executeTransaction(createRequest, subject, idempotencyKey);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.success(executed, "Transaction processed successfully"));
    }
}
