package com.zerotrust.repository;

import com.zerotrust.entity.AuditLog;
import com.zerotrust.entity.enums.AuditStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID>,
        JpaSpecificationExecutor<AuditLog> {

    /** Fetch the latest log for hash chaining */
    Optional<AuditLog> findTopByOrderByCreatedAtDesc();

    long countByCreatedAtAfter(Instant after);

    long countByStatusAndCreatedAtAfter(AuditStatus status, Instant after);

    long countByUserIdAndActionAndCreatedAtAfter(String userId, String action, Instant after);

    Page<AuditLog> findByUserId(String userId, Pageable pageable);

    @Query("SELECT a.action, COUNT(a) FROM AuditLog a WHERE a.createdAt > :since GROUP BY a.action ORDER BY COUNT(a) DESC")
    List<Object[]> countByActionSince(@Param("since") Instant since);

    @Query(value = "SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as day, COUNT(*) " +
                   "FROM audit_logs WHERE created_at > :since " +
                   "GROUP BY day ORDER BY day", nativeQuery = true)
    List<Object[]> findDailyActivityCounts(@Param("since") Instant since);

    @Query("SELECT a FROM AuditLog a WHERE a.createdAt > :since AND a.status = 'FAILURE' ORDER BY a.createdAt DESC")
    List<AuditLog> findRecentFailures(@Param("since") Instant since, Pageable pageable);

    List<AuditLog> findTop50ByOrderByCreatedAtDesc();
}
