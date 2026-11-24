package com.zerotrust.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RoleBasedAccessControlTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Anonymous access to /api/users should be rejected with 401 Unauthorized")
    void anonymousUsersForbidden() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "EMPLOYEE")
    @DisplayName("ROLE_EMPLOYEE accessing /api/users should be rejected with 403 Forbidden")
    void employeeCannotAccessUsers() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("ROLE_ADMIN accessing /api/users should be permitted (200 OK)")
    void adminCanAccessUsers() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "EMPLOYEE")
    @DisplayName("ROLE_EMPLOYEE accessing /api/threats should be rejected with 403 Forbidden")
    void employeeCannotAccessThreats() throws Exception {
        mockMvc.perform(get("/api/threats"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "SECURITY_ANALYST")
    @DisplayName("ROLE_SECURITY_ANALYST accessing /api/threats should be permitted (200 OK)")
    void analystCanAccessThreats() throws Exception {
        mockMvc.perform(get("/api/threats"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "SECURITY_ANALYST")
    @DisplayName("ROLE_SECURITY_ANALYST attempting admin-only POST /api/users/{id}/unlock should be 403 Forbidden")
    void analystCannotUnlockUser() throws Exception {
        mockMvc.perform(post("/api/users/{id}/unlock", UUID.randomUUID()))
            .andExpect(status().isForbidden());
    }
}
