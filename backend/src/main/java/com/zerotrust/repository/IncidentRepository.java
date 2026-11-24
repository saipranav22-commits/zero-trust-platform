package com.zerotrust.repository;

import com.zerotrust.entity.Incident;
import com.zerotrust.entity.enums.IncidentStatus;
import com.zerotrust.entity.enums.Severity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface IncidentRepository extends JpaRepository<Incident, UUID>, JpaSpecificationExecutor<Incident> {

    Optional<Incident> findByIncidentNumber(String incidentNumber);

    Optional<Incident> findByRelatedThreatEventId(UUID threatEventId);

    boolean existsByRelatedThreatEventId(UUID threatEventId);

    Optional<Incident> findByCorrelationId(String correlationId);

    Optional<Incident> findTopByOrderByCreatedAtDesc();

    long countByStatus(IncidentStatus status);

    long countBySeverity(Severity severity);
}
