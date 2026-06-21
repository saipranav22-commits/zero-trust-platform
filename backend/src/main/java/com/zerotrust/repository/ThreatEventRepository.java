package com.zerotrust.repository;

import com.zerotrust.entity.ThreatEvent;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.entity.enums.ThreatStatus;
import com.zerotrust.entity.enums.ThreatType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ThreatEventRepository extends JpaRepository<ThreatEvent, UUID>,
        JpaSpecificationExecutor<ThreatEvent> {

    long countByCreatedAtAfter(Instant after);

    long countByStatusIn(List<ThreatStatus> statuses);

    long countBySeverityAndCreatedAtAfter(Severity severity, Instant after);

    long countByCreatedAtAfterAndSeverity(Instant after, Severity severity);

    List<ThreatEvent> findTop10ByOrderByCreatedAtDesc();

    List<ThreatEvent> findByStatusIn(List<ThreatStatus> statuses, Pageable pageable);

    @Query("SELECT t.threatType, COUNT(t) FROM ThreatEvent t WHERE t.createdAt > :since GROUP BY t.threatType ORDER BY COUNT(t) DESC")
    List<Object[]> countByThreatTypeSince(@Param("since") Instant since);

    @Query("SELECT t.severity, COUNT(t) FROM ThreatEvent t WHERE t.createdAt > :since GROUP BY t.severity")
    List<Object[]> countBySeveritySince(@Param("since") Instant since);

    @Query("SELECT t.sourceIp, COUNT(t) as cnt FROM ThreatEvent t WHERE t.createdAt > :since AND t.sourceIp IS NOT NULL GROUP BY t.sourceIp ORDER BY cnt DESC")
    List<Object[]> findTopSourceIps(@Param("since") Instant since, Pageable pageable);

    @Query(value = "SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as day, COUNT(*) " +
                   "FROM threat_events WHERE created_at > :since " +
                   "GROUP BY day ORDER BY day", nativeQuery = true)
    List<Object[]> findDailyThreatCounts(@Param("since") Instant since);

    @Query("SELECT t.threatType, t.severity, COUNT(t) FROM ThreatEvent t " +
           "WHERE t.createdAt > :since GROUP BY t.threatType, t.severity")
    List<Object[]> findThreatTypeAndSeverityBreakdown(@Param("since") Instant since);

    Page<ThreatEvent> findByUserId(String userId, Pageable pageable);
}
