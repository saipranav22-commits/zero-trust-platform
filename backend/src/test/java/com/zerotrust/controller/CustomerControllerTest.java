package com.zerotrust.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.dto.request.CustomerCreateRequest;
import com.zerotrust.dto.response.CustomerResponse;
import com.zerotrust.entity.enums.KycStatus;
import com.zerotrust.entity.enums.RiskTier;
import com.zerotrust.exception.GlobalExceptionHandler;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.CustomerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class CustomerControllerTest {

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @Mock
    private CustomerService customerService;

    @InjectMocks
    private CustomerController customerController;

    private final UUID customerId = UUID.randomUUID();
    private final UUID employeeId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        mockMvc = MockMvcBuilders.standaloneSetup(customerController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
    }

    @Test
    @DisplayName("GET /api/customers/{id} returns customer with masked tax ID for authorized owner")
    void shouldReturnCustomerWithMaskedTaxId() throws Exception {
        CustomerResponse response = new CustomerResponse(
            customerId,
            "CUST-1001",
            "Client",
            "Alpha",
            "Client Alpha",
            "alpha@example.test",
            "+1-555-0100",
            KycStatus.VERIFIED,
            RiskTier.LOW,
            employeeId,
            "SYN-***-8841",
            new BigDecimal("120000.00"),
            780,
            Instant.now(),
            Instant.now()
        );

        when(customerService.getCustomerById(eq(customerId), any(SecuritySubject.class))).thenReturn(response);

        mockMvc.perform(get("/api/customers/" + customerId)
                .requestAttr("userId", employeeId.toString()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.customerNumber").value("CUST-1001"))
            .andExpect(jsonPath("$.data.maskedTaxId").value("SYN-***-8841"));
    }

    @Test
    @DisplayName("GET /api/customers/{id} returns HTTP 403 when BOLA violation occurs")
    void shouldReturn403WhenBolaViolationOccurs() throws Exception {
        when(customerService.getCustomerById(eq(customerId), any(SecuritySubject.class)))
            .thenThrow(new AccessDeniedException("Access Denied: Subject is not authorized (ownership violation)"));

        mockMvc.perform(get("/api/customers/" + customerId)
                .requestAttr("userId", UUID.randomUUID().toString()))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.message").value("Access denied: insufficient permissions"));
    }

    @Test
    @DisplayName("POST /api/customers with missing fields returns HTTP 400 Bad Request")
    void shouldRejectInvalidCustomerCreation() throws Exception {
        CustomerCreateRequest invalidRequest = new CustomerCreateRequest(
            "", // empty customerNumber
            "", // empty firstName
            "", // empty lastName
            "invalid-email", // invalid email
            null,
            null,
            null,
            null,
            "", // empty syntheticTaxId
            new BigDecimal("-100"), // negative income
            null
        );

        mockMvc.perform(post("/api/customers")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.fieldErrors").exists());
    }

    @Test
    @DisplayName("GET /api/customers/{id}/sensitive returns decrypted tax ID for authorized subject")
    void shouldReturnDecryptedTaxIdForAuthorizedSubject() throws Exception {
        when(customerService.getSensitiveCustomerData(eq(customerId), any(SecuritySubject.class), any()))
            .thenReturn("SYN-9876-5432");

        mockMvc.perform(get("/api/customers/" + customerId + "/sensitive")
                .requestAttr("userId", employeeId.toString()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.syntheticTaxId").value("SYN-9876-5432"));
    }

    @Test
    @DisplayName("GET /api/customers/{id}/sensitive returns HTTP 403 when ABAC VIEW_SENSITIVE policy denies")
    void shouldReturn403WhenSensitiveViewingDenied() throws Exception {
        when(customerService.getSensitiveCustomerData(eq(customerId), any(SecuritySubject.class), any()))
            .thenThrow(new AccessDeniedException("Access Denied: Subject is not authorized to perform action [VIEW_SENSITIVE]"));

        mockMvc.perform(get("/api/customers/" + customerId + "/sensitive")
                .requestAttr("userId", employeeId.toString()))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.message").value("Access denied: insufficient permissions"));
    }
}
