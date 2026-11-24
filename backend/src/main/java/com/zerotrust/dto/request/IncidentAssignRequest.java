package com.zerotrust.dto.request;

import jakarta.validation.constraints.NotBlank;

public record IncidentAssignRequest(
        @NotBlank(message = "Assignee identifier is required")
        String assignedTo,

        String notes
) {}
