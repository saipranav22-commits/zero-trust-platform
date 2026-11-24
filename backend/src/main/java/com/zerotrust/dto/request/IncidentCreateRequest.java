package com.zerotrust.dto.request;

import com.zerotrust.entity.enums.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record IncidentCreateRequest(
        @NotBlank(message = "Title is required")
        @Size(max = 255, message = "Title must not exceed 255 characters")
        String title,

        String description,

        @NotNull(message = "Severity is required")
        Severity severity,

        @NotBlank(message = "Category is required")
        String category,

        String correlationId,
        UUID relatedThreatEventId,
        String sourceIp,
        String targetResource,
        String assignedTo
) {}
