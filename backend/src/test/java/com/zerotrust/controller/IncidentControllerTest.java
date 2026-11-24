package com.zerotrust.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zerotrust.dto.request.IncidentAssignRequest;
import com.zerotrust.dto.request.IncidentCreateRequest;
import com.zerotrust.dto.request.IncidentNoteRequest;
import com.zerotrust.dto.request.IncidentStatusUpdateRequest;
import com.zerotrust.dto.response.IncidentResponse;
import com.zerotrust.dto.response.PageResponse;
import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.exception.GlobalExceptionHandler;
import com.zerotrust.service.IncidentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class IncidentControllerTest {

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private IncidentService incidentService;

    @InjectMocks
    private IncidentController incidentController;

    private final UUID incidentId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(incidentController)
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    private IncidentResponse createSampleResponse(IncidentStatus status) {
        return new IncidentResponse(
                incidentId,
                "INC-2026-00001",
                "Test Security Incident",
                "Investigation into suspicious traffic",
                status,
                Severity.HIGH,
                "SQL_INJECTION",
                "CORR-12345",
                UUID.randomUUID(),
                "192.168.1.10",
                "/api/customers",
                "analyst@syvora.local",
                "SYSTEM",
                status == IncidentStatus.RESOLVED ? "Mitigated" : null,
                status == IncidentStatus.RESOLVED ? Instant.now() : null,
                Instant.now(),
                Instant.now(),
                List.of()
        );
    }

    @Test
    @DisplayName("GET /api/incidents returns paginated incident list")
    void shouldReturnPaginatedIncidents() throws Exception {
        when(incidentService.search(any(), any(), any(), any(), any(), any()))
                .thenReturn(new PageImpl<>(List.of(createSampleResponse(IncidentStatus.OPEN))));

        mockMvc.perform(get("/api/incidents"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.content[0].incidentNumber").value("INC-2026-00001"))
                .andExpect(jsonPath("$.data.content[0].status").value("OPEN"));
    }

    @Test
    @DisplayName("GET /api/incidents/{id} returns single incident with details")
    void shouldReturnSingleIncident() throws Exception {
        when(incidentService.getById(incidentId)).thenReturn(createSampleResponse(IncidentStatus.ACKNOWLEDGED));

        mockMvc.perform(get("/api/incidents/{id}", incidentId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.id").value(incidentId.toString()))
                .andExpect(jsonPath("$.data.status").value("ACKNOWLEDGED"));
    }

    @Test
    @DisplayName("PUT /api/incidents/{id}/status updates lifecycle state")
    void shouldUpdateIncidentStatus() throws Exception {
        IncidentStatusUpdateRequest req = new IncidentStatusUpdateRequest(IncidentStatus.INVESTIGATING, "Investigation underway");
        when(incidentService.updateStatus(eq(incidentId), any(), any()))
                .thenReturn(createSampleResponse(IncidentStatus.INVESTIGATING));

        mockMvc.perform(put("/api/incidents/{id}/status", incidentId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.status").value("INVESTIGATING"));
    }

    @Test
    @DisplayName("PUT /api/incidents/{id}/assign assigns incident to analyst")
    void shouldAssignIncident() throws Exception {
        IncidentAssignRequest req = new IncidentAssignRequest("analyst2@syvora.local", "Assignment notes");
        when(incidentService.assignIncident(eq(incidentId), any(), any()))
                .thenReturn(createSampleResponse(IncidentStatus.OPEN));

        mockMvc.perform(put("/api/incidents/{id}/assign", incidentId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("POST /api/incidents/{id}/notes adds timeline note")
    void shouldAddNoteToIncident() throws Exception {
        IncidentNoteRequest req = new IncidentNoteRequest("New malicious IP pattern observed");
        when(incidentService.addNote(eq(incidentId), any(), any()))
                .thenReturn(createSampleResponse(IncidentStatus.INVESTIGATING));

        mockMvc.perform(post("/api/incidents/{id}/notes", incidentId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
}
