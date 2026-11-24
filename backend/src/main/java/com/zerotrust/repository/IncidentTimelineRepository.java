package com.zerotrust.repository;

import com.zerotrust.entity.IncidentTimeline;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface IncidentTimelineRepository extends JpaRepository<IncidentTimeline, UUID> {

    List<IncidentTimeline> findByIncidentIdOrderByCreatedAtAsc(UUID incidentId);
}
