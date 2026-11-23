package com.zerotrust.service;

import com.zerotrust.entity.Notification;
import com.zerotrust.entity.enums.Severity;
import com.zerotrust.repository.NotificationRepository;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final NotificationRepository notificationRepository;
    private final SseService sseService;

    @Transactional(readOnly = true)
    public Page<Notification> getNotifications(
            String search, Severity severity, String category, Boolean isRead,
            Instant start, Instant end, Pageable pageable) {

        Specification<Notification> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (search != null && !search.trim().isEmpty()) {
                String searchPattern = "%" + search.trim().toLowerCase() + "%";
                predicates.add(cb.or(
                    cb.like(cb.lower(root.get("title")), searchPattern),
                    cb.like(cb.lower(root.get("description")), searchPattern)
                ));
            }

            if (severity != null) {
                predicates.add(cb.equal(root.get("severity"), severity));
            }

            if (category != null && !category.trim().isEmpty()) {
                predicates.add(cb.equal(cb.lower(root.get("category")), category.trim().toLowerCase()));
            }

            if (isRead != null) {
                predicates.add(cb.equal(root.get("isRead"), isRead));
            }

            if (start != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), start));
            }

            if (end != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), end));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        return notificationRepository.findAll(spec, pageable);
    }

    @Transactional(readOnly = true)
    public long getUnreadCount() {
        return notificationRepository.countByIsReadFalse();
    }

    @Transactional(readOnly = true)
    public Notification getNotification(UUID id) {
        return notificationRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Notification not found with ID: " + id));
    }

    @Transactional
    public Notification createNotification(String title, String description, Severity severity, String category,
                                          UUID incidentId, UUID threatId, UUID userId, String actionUrl,
                                          String createdBy, String iconType) {
        Notification notification = Notification.builder()
            .title(title)
            .description(description)
            .severity(severity)
            .category(category)
            .relatedIncidentId(incidentId)
            .relatedThreatId(threatId)
            .relatedUserId(userId)
            .actionUrl(actionUrl)
            .createdBy(createdBy)
            .iconType(iconType)
            .isRead(false)
            .build();

        Notification saved = notificationRepository.save(notification);
        try {
            sseService.broadcastNotification(saved);
        } catch (Exception e) {
            log.error("Failed to broadcast real-time SSE notification", e);
        }
        return saved;
    }

    @Transactional
    public Notification markAsRead(UUID id) {
        Notification notification = getNotification(id);
        if (!notification.isRead()) {
            notification.setRead(true);
            return notificationRepository.save(notification);
        }
        return notification;
    }

    @Transactional
    public void markAllAsRead() {
        notificationRepository.markAllAsRead();
    }

    @Transactional
    public void deleteNotification(UUID id) {
        if (!notificationRepository.existsById(id)) {
            throw new IllegalArgumentException("Notification not found with ID: " + id);
        }
        notificationRepository.deleteById(id);
    }
}
