package com.zerotrust.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.dto.request.TransactionCreateRequest;
import com.zerotrust.dto.response.TransactionResponse;
import com.zerotrust.entity.enums.TransactionStatus;
import com.zerotrust.entity.enums.TransactionType;
import com.zerotrust.exception.GlobalExceptionHandler;
import com.zerotrust.security.abac.SecuritySubject;
import com.zerotrust.service.TransactionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class TransactionControllerTest {

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @Mock
    private TransactionService transactionService;

    @InjectMocks
    private TransactionController transactionController;

    private final UUID accountId = UUID.randomUUID();
    private final UUID transactionId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        mockMvc = MockMvcBuilders.standaloneSetup(transactionController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
    }

    @Test
    @DisplayName("POST /api/transactions executes successfully with Idempotency-Key header")
    void shouldExecuteTransactionWithIdempotencyKey() throws Exception {
        TransactionCreateRequest request = new TransactionCreateRequest(
            accountId,
            new BigDecimal("150.00"),
            TransactionType.DEPOSIT,
            "Deposit test",
            null
        );

        TransactionResponse response = new TransactionResponse(
            transactionId,
            accountId,
            "TXN-100",
            new BigDecimal("150.00"),
            TransactionType.DEPOSIT,
            TransactionStatus.COMPLETED,
            "Deposit test",
            "ACC-1001",
            null,
            null,
            Instant.now()
        );

        when(transactionService.executeTransaction(any(TransactionCreateRequest.class), any(SecuritySubject.class), eq("idemp-key-123")))
            .thenReturn(response);

        mockMvc.perform(post("/api/transactions")
                .header("Idempotency-Key", "idemp-key-123")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.referenceNumber").value("TXN-100"));

        verify(transactionService).executeTransaction(any(TransactionCreateRequest.class), any(SecuritySubject.class), eq("idemp-key-123"));
    }

    @Test
    @DisplayName("GET /api/transactions/{id} retrieves transaction record")
    void shouldGetTransactionById() throws Exception {
        TransactionResponse response = new TransactionResponse(
            transactionId,
            accountId,
            "TXN-200",
            new BigDecimal("500.00"),
            TransactionType.TRANSFER,
            TransactionStatus.COMPLETED,
            "Transfer test",
            "ACC-1001",
            "ACC-2002",
            UUID.randomUUID(),
            Instant.now()
        );

        when(transactionService.getTransactionById(eq(transactionId), any(SecuritySubject.class)))
            .thenReturn(response);

        mockMvc.perform(get("/api/transactions/" + transactionId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.referenceNumber").value("TXN-200"));
    }
}
