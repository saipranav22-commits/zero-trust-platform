package com.zerotrust.controller;

import com.zerotrust.exception.GlobalExceptionHandler;
import com.zerotrust.service.NotificationService;
import com.zerotrust.service.SseService;
import com.zerotrust.service.SseTicketService;
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
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    private MockMvc mockMvc;

    @Mock
    private NotificationService notificationService;

    @Mock
    private SseService sseService;

    @Mock
    private SseTicketService sseTicketService;

    @InjectMocks
    private NotificationController notificationController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(notificationController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
    }

    @Test
    @DisplayName("POST /api/notifications/stream-ticket should generate a short-lived SSE ticket")
    void shouldGenerateStreamTicket() throws Exception {
        when(sseTicketService.createTicket(eq("user-1"), eq("analyst@zerotrust.com"), any()))
            .thenReturn("sample-secure-ticket-abc");

        mockMvc.perform(post("/api/notifications/stream-ticket")
                .requestAttr("userId", "user-1")
                .requestAttr("userEmail", "analyst@zerotrust.com")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.ticket").value("sample-secure-ticket-abc"));

        verify(sseTicketService).createTicket(eq("user-1"), eq("analyst@zerotrust.com"), any());
    }

    @Test
    @DisplayName("GET /api/notifications/stream without ticket should be rejected with HTTP 401")
    void shouldRejectStreamWithoutTicket() throws Exception {
        mockMvc.perform(get("/api/notifications/stream"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.message").value("Authentication ticket is required for SSE subscription"));

        verifyNoInteractions(sseService);
    }

    @Test
    @DisplayName("GET /api/notifications/stream with invalid or expired ticket should be rejected with HTTP 401")
    void shouldRejectStreamWithInvalidTicket() throws Exception {
        when(sseTicketService.validateAndConsume("expired-ticket")).thenReturn(null);

        mockMvc.perform(get("/api/notifications/stream")
                .param("ticket", "expired-ticket"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.message").value("Invalid, expired, or already consumed SSE stream ticket"));

        verifyNoInteractions(sseService);
    }

    @Test
    @DisplayName("GET /api/notifications/stream with valid ticket should establish SSE connection")
    void shouldAcceptStreamWithValidTicket() throws Exception {
        when(sseTicketService.validateAndConsume("valid-ticket"))
            .thenReturn(new SseTicketService.TicketData("user-1", "user@zerotrust.com", java.util.Set.of("ROLE_ADMIN"), Instant.now().plusSeconds(30)));
        when(sseService.registerClient(eq("user-1"), eq("user@zerotrust.com"), any())).thenReturn(new SseEmitter());

        mockMvc.perform(get("/api/notifications/stream")
                .param("ticket", "valid-ticket"))
            .andExpect(status().isOk());

        verify(sseTicketService).validateAndConsume("valid-ticket");
        verify(sseService).registerClient(eq("user-1"), eq("user@zerotrust.com"), any());
    }
}
