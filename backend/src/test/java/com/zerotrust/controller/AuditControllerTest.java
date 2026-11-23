package com.zerotrust.controller;

import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.enums.AuditStatus;
import com.zerotrust.exception.GlobalExceptionHandler;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.service.AuditService;
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

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuditControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private AuditController auditController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(auditController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
    }

    @Test
    @DisplayName("GET /api/audit/logs/{id} should return matching audit log by UUID")
    void shouldReturnLogMatchingRequestedUuid() throws Exception {
        UUID targetId = UUID.randomUUID();
        AuditLog sampleLog = AuditLog.builder()
            .id(targetId)
            .userId("user-42")
            .userEmail("admin@zerotrust.com")
            .action("USER_LOGIN")
            .status(AuditStatus.SUCCESS)
            .riskScore(0)
            .createdAt(Instant.now())
            .build();

        when(auditService.getById(targetId)).thenReturn(sampleLog);

        mockMvc.perform(get("/api/audit/logs/{id}", targetId)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.id").value(targetId.toString()))
            .andExpect(jsonPath("$.data.action").value("USER_LOGIN"))
            .andExpect(jsonPath("$.data.userEmail").value("admin@zerotrust.com"));

        verify(auditService).getById(targetId);
    }

    @Test
    @DisplayName("GET /api/audit/logs/{id} should return HTTP 404 when log does not exist")
    void shouldReturn404WhenLogNotFound() throws Exception {
        UUID missingId = UUID.randomUUID();
        when(auditService.getById(missingId))
            .thenThrow(new ResourceNotFoundException("Audit log not found: " + missingId));

        mockMvc.perform(get("/api/audit/logs/{id}", missingId)
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.status").value(404))
            .andExpect(jsonPath("$.message").value("Audit log not found: " + missingId));

        verify(auditService).getById(missingId);
    }
}
