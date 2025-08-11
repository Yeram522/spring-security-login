package hashsnap.security.repository;

import hashsnap.security.entity.SecurityAlertHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityAlertHistoryRepository extends JpaRepository<SecurityAlertHistory, Long> {

    /**
     * 알림 키로 이력 조회 (중복 체크용)
     */
    Optional<SecurityAlertHistory> findByAlertKey(String alertKey);

    /**
     * 특정 IP의 알림 이력 조회
     */
    List<SecurityAlertHistory> findByIpAddressOrderByLastAlertedAtDesc(String ipAddress);

    /**
     * 특정 알림 타입의 최근 이력 조회
     */
    List<SecurityAlertHistory> findByAlertTypeOrderByLastAlertedAtDesc(String alertType);

    /**
     * 미확인 알림 목록 조회 (관리자 대시보드용)
     */
    @Query("SELECT h FROM SecurityAlertHistory h WHERE h.acknowledged = false ORDER BY h.lastAlertedAt DESC")
    List<SecurityAlertHistory> findUnacknowledgedAlerts();

    /**
     * 특정 기간 내 알림 이력 조회
     */
    @Query("SELECT h FROM SecurityAlertHistory h WHERE h.lastAlertedAt BETWEEN :startTime AND :endTime ORDER BY h.lastAlertedAt DESC")
    List<SecurityAlertHistory> findByLastAlertedAtBetween(
            @Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime
    );

    /**
     * 활성 억제 상태인 알림들 조회 (현재 시간보다 suppressedUntil이 미래인 것들)
     */
    @Query("SELECT h FROM SecurityAlertHistory h WHERE h.suppressedUntil IS NOT NULL AND h.suppressedUntil > :currentTime")
    List<SecurityAlertHistory> findActivelySuppressedAlerts(@Param("currentTime") LocalDateTime currentTime);

    /**
     * 특정 관리자가 확인한 알림들 조회
     */
    List<SecurityAlertHistory> findByAcknowledgedByOrderByAcknowledgedAtDesc(String acknowledgedBy);

    /**
     * 알림 타입별 통계 (관리자 대시보드용)
     */
    @Query("SELECT h.alertType, COUNT(h), SUM(h.alertCount) FROM SecurityAlertHistory h " +
            "WHERE h.lastAlertedAt >= :since GROUP BY h.alertType")
    List<Object[]> getAlertStatisticsByType(@Param("since") LocalDateTime since);

    /**
     * 상위 공격 IP 조회 (관리자 대시보드용)
     */
    @Query("SELECT h.ipAddress, COUNT(h), SUM(h.alertCount) FROM SecurityAlertHistory h " +
            "WHERE h.ipAddress IS NOT NULL AND h.lastAlertedAt >= :since " +
            "GROUP BY h.ipAddress ORDER BY SUM(h.alertCount) DESC")
    List<Object[]> getTopAttackingIPs(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * 오래된 확인된 알림 정리 (배치 작업용)
     */
    @Modifying
    @Query("DELETE FROM SecurityAlertHistory h WHERE h.acknowledged = true AND h.acknowledgedAt < :cutoffDate")
    int deleteOldAcknowledgedAlerts(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * 페이지네이션을 통한 알림 이력 조회 (관리자 페이지용)
     */
    Page<SecurityAlertHistory> findAllByOrderByLastAlertedAtDesc(Pageable pageable);

    /**
     * 특정 심각도의 알림들 조회
     */
    List<SecurityAlertHistory> findBySeverityOrderByLastAlertedAtDesc(String severity);

    /**
     * 최근 24시간 내 알림 수 조회 (대시보드 요약용)
     */
    @Query("SELECT COUNT(h) FROM SecurityAlertHistory h WHERE h.lastAlertedAt >= :yesterday")
    long countRecentAlerts(@Param("yesterday") LocalDateTime yesterday);

    /**
     * IP별 최근 알림 빈도 체크 (rate limiting 참고용)
     */
    @Query("SELECT COUNT(h) FROM SecurityAlertHistory h WHERE h.ipAddress = :ipAddress " +
            "AND h.lastAlertedAt >= :since")
    long countAlertsByIpSince(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    /**
     * 특정 알림 키의 쿨다운 상태 확인
     */
    @Query("SELECT h FROM SecurityAlertHistory h WHERE h.alertKey = :alertKey " +
            "AND (h.suppressedUntil > :currentTime OR " +
            "     (h.acknowledged = true AND h.acknowledgedAt > :escalationTime))")
    Optional<SecurityAlertHistory> findIfInCooldown(
            @Param("alertKey") String alertKey,
            @Param("currentTime") LocalDateTime currentTime,
            @Param("escalationTime") LocalDateTime escalationTime
    );
}