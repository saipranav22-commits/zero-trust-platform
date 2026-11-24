package com.zerotrust.integration;

import com.zerotrust.dto.request.IncidentAssignRequest;
import com.zerotrust.dto.request.IncidentCreateRequest;
import com.zerotrust.dto.request.IncidentNoteRequest;
import com.zerotrust.dto.request.IncidentStatusUpdateRequest;
import com.zerotrust.dto.response.IncidentResponse;
import com.zerotrust.entity.Incident;
import com.zerotrust.entity.ThreatEvent;
import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatType;
import com.zerotrust.exception.InvalidStateTransitionException;
import com.zerotrust.repository.IncidentRepository;
import com.zerotrust.repository.ThreatEventRepository;
import com.zerotrust.service.IncidentService;
import com.zerotrust.service.RedisSecurityService;
import com.zerotrust.service.ThreatService;
import com.zerotrust.threat.DetectionResult;
import com.zerotrust.threat.ThreatAction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("test")
class IncidentManagementIntegrationTest {

    @MockBean
    private RedisSecurityService redisSecurityService;

    @Autowired
    private IncidentService incidentService;

    @Autowired
    private IncidentRepository incidentRepository;

    @Autowired
    private ThreatService threatService;

    @Autowired
    private ThreatEventRepository threatEventRepository;

    @Test
    @DisplayName("Incident Lifecycle: Valid transitions OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED and Reopening")
    void testIncidentLifecycleValidTransitions() {
        IncidentCreateRequest createReq = new IncidentCreateRequest(
                "SQL Injection Detected in Customer API",
                "Repeated OR 1=1 injection signatures observed",
                Severity.HIGH,
                "SQL_INJECTION",
                "CORR-" + UUID.randomUUID(),
                UUID.randomUUID(),
                "198.51.100.25",
                "/api/customers/search",
                "analyst-1@syvora.local"
        );

        IncidentResponse inc = incidentService.createIncident(createReq, "ADMIN");
        assertThat(inc.status()).isEqualTo(IncidentStatus.OPEN);
        assertThat(inc.incidentNumber()).startsWith("INC-");
        assertThat(inc.timeline()).hasSize(1);
        assertThat(inc.timeline().get(0).action()).isEqualTo("CREATED");

        // 1. OPEN -> ACKNOWLEDGED
        IncidentResponse ack = incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.ACKNOWLEDGED, "Analyst acknowledged alert"), "analyst-1"
        );
        assertThat(ack.status()).isEqualTo(IncidentStatus.ACKNOWLEDGED);

        // 2. ACKNOWLEDGED -> INVESTIGATING
        IncidentResponse inv = incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.INVESTIGATING, "Investigating IP payload"), "analyst-1"
        );
        assertThat(inv.status()).isEqualTo(IncidentStatus.INVESTIGATING);

        // Add analyst note
        IncidentResponse withNote = incidentService.addNote(
                inc.id(), new IncidentNoteRequest("Blocked attacking CIDR in upstream WAF tier"), "analyst-1"
        );
        assertThat(withNote.timeline()).anyMatch(t -> t.action().equals("NOTE_ADDED"));

        // 3. INVESTIGATING -> RESOLVED
        IncidentResponse resolved = incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.RESOLVED, "WAF rule activated and root cause addressed in query parameters"), "analyst-1"
        );
        assertThat(resolved.status()).isEqualTo(IncidentStatus.RESOLVED);
        assertThat(resolved.resolvedAt()).isNotNull();
        assertThat(resolved.resolutionNotes()).contains("WAF rule activated");

        // 4. Documented Reopening: RESOLVED -> OPEN
        IncidentResponse reopened = incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.OPEN, "Secondary attack spike detected from related ASN"), "analyst-lead"
        );
        assertThat(reopened.status()).isEqualTo(IncidentStatus.OPEN);
        assertThat(reopened.resolvedAt()).isNull();
        assertThat(reopened.timeline()).anyMatch(t -> t.action().equals("REOPENED"));
    }

    @Test
    @DisplayName("Incident Lifecycle: Invalid transitions are rejected with InvalidStateTransitionException")
    void testInvalidStateTransitionsRejected() {
        IncidentCreateRequest req = new IncidentCreateRequest(
                "Unauthorized Access Attempt", "Brute force probe", Severity.MEDIUM,
                "BRUTE_FORCE", "CORR-INV", UUID.randomUUID(), "10.0.0.1", "/api/auth/login", null
        );
        IncidentResponse inc = incidentService.createIncident(req, "SYSTEM");

        // Invalid jump: OPEN -> RESOLVED directly without investigation
        assertThatThrownBy(() -> incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.RESOLVED, "Skip investigation"), "analyst"
        )).isInstanceOf(InvalidStateTransitionException.class)
          .hasMessageContaining("Invalid incident state transition");

        // Move to ACKNOWLEDGED
        incidentService.updateStatus(inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.ACKNOWLEDGED, null), "analyst");

        // Invalid: ACKNOWLEDGED -> RESOLVED directly
        assertThatThrownBy(() -> incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.RESOLVED, "Fast close"), "analyst"
        )).isInstanceOf(InvalidStateTransitionException.class);

        // Move to INVESTIGATING
        incidentService.updateStatus(inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.INVESTIGATING, null), "analyst");

        // Invalid: INVESTIGATING -> RESOLVED without required notes
        assertThatThrownBy(() -> incidentService.updateStatus(
                inc.id(), new IncidentStatusUpdateRequest(IncidentStatus.RESOLVED, "   "), "analyst"
        )).isInstanceOf(InvalidStateTransitionException.class)
          .hasMessageContaining("Resolution notes are required");
    }

    @Test
    @DisplayName("Deduplication: Duplicate incident creation for same threat event is prevented")
    void testDuplicateIncidentPreventionForThreatEvent() {
        UUID threatId = UUID.randomUUID();
        IncidentCreateRequest req1 = new IncidentCreateRequest(
                "Exfiltration Attempt", "Mass download pattern", Severity.CRITICAL,
                "DATA_EXFILTRATION", "CORR-DEDUP", threatId, "1.2.3.4", "/api/customers", "analyst"
        );

        IncidentResponse inc1 = incidentService.createIncident(req1, "ADMIN");
        IncidentResponse inc2 = incidentService.createIncident(req1, "ADMIN");

        assertThat(inc1.id()).isEqualTo(inc2.id());
        assertThat(inc1.incidentNumber()).isEqualTo(inc2.incidentNumber());
    }

    @Test
    @DisplayName("Auto-Promotion: Qualifying Critical/High threat events automatically create incidents")
    void testAutoIncidentCreationFromQualifyingThreat() {
        DetectionResult result = new DetectionResult(
                true, ThreatType.SQL_INJECTION, Severity.CRITICAL,
                "SQL_INJECTION_RULE_01", "UNION SELECT admin password", 95
        );

        ThreatEvent threat = threatService.recordThreatEvent(
                "UNION SELECT * FROM credentials", "attacker-1", "attacker@evil.com",
                "203.0.113.19", "/api/v1/auth", "POST",
                "CORR-AUTO-" + UUID.randomUUID(), result, ThreatAction.BLOCKED, 95
        );

        Optional<Incident> autoIncident = incidentRepository.findByRelatedThreatEventId(threat.getId());
        assertThat(autoIncident).isPresent();
        assertThat(autoIncident.get().getStatus()).isEqualTo(IncidentStatus.OPEN);
        assertThat(autoIncident.get().getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(autoIncident.get().getCreatedBy()).isEqualTo("SYSTEM_DETECTION_ENGINE");
    }

    @Test
    @DisplayName("Analyst Assignment: Authorized assignment persists and updates timeline")
    void testIncidentAssignmentWorkflow() {
        IncidentCreateRequest req = new IncidentCreateRequest(
                "BOLA Probe Detected", "Unauthorized ID enumeration", Severity.HIGH,
                "UNAUTHORIZED_ACCESS", "CORR-BOLA", UUID.randomUUID(), "10.0.0.8", "/api/accounts/1", null
        );
        IncidentResponse inc = incidentService.createIncident(req, "ADMIN");

        IncidentResponse assigned = incidentService.assignIncident(
                inc.id(), new IncidentAssignRequest("sec-analyst-bob@syvora.local", "Assigning to Lead Analyst"), "SOC_SUPERVISOR"
        );

        assertThat(assigned.assignedTo()).isEqualTo("sec-analyst-bob@syvora.local");
        assertThat(assigned.timeline()).anyMatch(t -> t.action().equals("ASSIGNED"));
    }
}
