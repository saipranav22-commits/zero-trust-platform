package com.zerotrust.repository;

import com.zerotrust.entity.AuditChainAnchor;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface AuditChainAnchorRepository extends JpaRepository<AuditChainAnchor, Integer> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM AuditChainAnchor a WHERE a.id = :id")
    Optional<AuditChainAnchor> findByIdForUpdate(@Param("id") Integer id);
}
