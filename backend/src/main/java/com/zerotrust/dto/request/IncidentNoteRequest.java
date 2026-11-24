package com.zerotrust.dto.request;

import jakarta.validation.constraints.NotBlank;

public record IncidentNoteRequest(
        @NotBlank(message = "Note content is required")
        String notes
) {}
