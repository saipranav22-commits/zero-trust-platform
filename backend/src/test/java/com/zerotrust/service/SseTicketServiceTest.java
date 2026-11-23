package com.zerotrust.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SseTicketServiceTest {

    private SseTicketService ticketService;

    @BeforeEach
    void setUp() {
        ticketService = new SseTicketService();
    }

    @Test
    @DisplayName("Should create single-use ticket and allow one-time consumption")
    void shouldCreateAndConsumeTicket() {
        String userId = "user-123";
        String email = "analyst@zerotrust.com";

        String ticket = ticketService.createTicket(userId, email);

        assertThat(ticket).isNotBlank();

        // First consume: success
        SseTicketService.TicketData data = ticketService.validateAndConsume(ticket);
        assertThat(data).isNotNull();
        assertThat(data.userId()).isEqualTo(userId);
        assertThat(data.userEmail()).isEqualTo(email);

        // Second consume: must fail (single-use guarantee)
        SseTicketService.TicketData replayData = ticketService.validateAndConsume(ticket);
        assertThat(replayData).isNull();
    }

    @Test
    @DisplayName("Should reject invalid or null ticket")
    void shouldRejectInvalidTickets() {
        assertThat(ticketService.validateAndConsume(null)).isNull();
        assertThat(ticketService.validateAndConsume("")).isNull();
        assertThat(ticketService.validateAndConsume("non-existent-ticket")).isNull();
    }
}
