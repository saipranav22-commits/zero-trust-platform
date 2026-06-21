package com.zerotrust.dto.response;

import java.util.List;
import java.util.UUID;

public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    long expiresIn,
    UserSummary user
) {
    public record UserSummary(
        UUID id,
        String email,
        String firstName,
        String lastName,
        List<String> roles
    ) {}
}
