package com.zerotrust.repository;

import com.zerotrust.entity.AuditCheckpoint;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditCheckpointRepository extends JpaRepository<AuditCheckpoint, UUID> {

    Optional<AuditCheckpoint> findTopByOrderBySequenceNumberDesc();

    List<AuditCheckpoint> findTop10ByOrderBySequenceNumberDesc();
}
