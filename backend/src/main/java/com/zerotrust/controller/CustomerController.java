package com.zerotrust.controller;

import com.zerotrust.dto.request.CustomerCreateRequest;
import com.zerotrust.dto.request.CustomerUpdateRequest;
import com.zerotrust.dto.response.ApiResponse;
import com.zerotrust.dto.response.CustomerDetailResponse;
import com.zerotrust.dto.response.CustomerResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.CustomerService;
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

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/customers")
@RequiredArgsConstructor
@Tag(name = "Customer Management", description = "Enterprise customer profile management with ABAC object-level authorization")
public class CustomerController {

    private final CustomerService customerService;

    private SecuritySubject getSubject(HttpServletRequest request, Authentication auth) {
        String userId = (String) request.getAttribute("userId");
        return SecuritySubject.from(auth, userId);
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get customers (isolated by assigned employee for EMPLOYEE role)")
    public ResponseEntity<ApiResponse<PageResponse<CustomerResponse>>> getCustomers(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) KycStatus kycStatus,
            @RequestParam(required = false) RiskTier riskTier,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        var page = customerService.getCustomers(search, kycStatus, riskTier, subject, pageable);
        return ResponseEntity.ok(ApiResponse.success(PageResponse.of(page)));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get specific customer profile by ID (enforces object ownership)")
    public ResponseEntity<ApiResponse<CustomerResponse>> getCustomer(
            @PathVariable UUID id,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        return ResponseEntity.ok(ApiResponse.success(customerService.getCustomerById(id, subject)));
    }

    @GetMapping("/{id}/details")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'AUDITOR', 'EMPLOYEE')")
    @Operation(summary = "Get full customer profile with linked financial accounts")
    public ResponseEntity<ApiResponse<CustomerDetailResponse>> getCustomerDetails(
            @PathVariable UUID id,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        return ResponseEntity.ok(ApiResponse.success(customerService.getCustomerDetails(id, subject)));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'EMPLOYEE')")
    @Operation(summary = "Create a new customer profile")
    public ResponseEntity<ApiResponse<CustomerResponse>> createCustomer(
            @Valid @RequestBody CustomerCreateRequest createRequest,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        CustomerResponse created = customerService.createCustomer(createRequest, subject);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.success(created, "Customer created successfully"));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'EMPLOYEE')")
    @Operation(summary = "Update customer profile (enforces object ownership)")
    public ResponseEntity<ApiResponse<CustomerResponse>> updateCustomer(
            @PathVariable UUID id,
            @Valid @RequestBody CustomerUpdateRequest updateRequest,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        CustomerResponse updated = customerService.updateCustomer(id, updateRequest, subject);
        return ResponseEntity.ok(ApiResponse.success(updated, "Customer updated successfully"));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete customer profile (Admin only)")
    public ResponseEntity<ApiResponse<Map<String, String>>> deleteCustomer(
            @PathVariable UUID id,
            HttpServletRequest request,
            Authentication auth) {

        SecuritySubject subject = getSubject(request, auth);
        customerService.deleteCustomer(id, subject);
        return ResponseEntity.ok(ApiResponse.success(Map.of("message", "Customer deleted successfully")));
    }
}
