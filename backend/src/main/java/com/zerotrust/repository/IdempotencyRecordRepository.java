package com.zerotrust.repository;

import com.zerotrust.entity.IdempotencyRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface IdempotencyRecordRepository extends JpaRepository<IdempotencyRecord, String> {

    void deleteByExpiresAtBefore(Instant now);
}
