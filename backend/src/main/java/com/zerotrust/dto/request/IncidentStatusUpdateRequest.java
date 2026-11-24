package com.zerotrust.dto.request;

import com.zerotrust.entity.enums.IncidentStatus;
import jakarta.validation.constraints.NotNull;

public record IncidentStatusUpdateRequest(
        @NotNull(message = "New status is required")
        IncidentStatus status,

        String notes
) {}
