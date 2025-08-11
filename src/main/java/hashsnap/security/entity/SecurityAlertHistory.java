package hashsnap.security.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_alert_history",
        indexes = {
                @Index(name = "idx_alert_key", columnList = "alertKey"),
                @Index(name = "idx_last_alerted", columnList = "lastAlertedAt"),
                @Index(name = "idx_ip_type", columnList = "ipAddress, alertType"),
                @Index(name = "idx_acknowledged", columnList = "isAcknowledged")
        })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class SecurityAlertHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 알림 유형 (EMAIL_VERIFICATION_ATTACK, API_ABUSE, ADMIN_SCANNING 등)
     */
    @Column(name = "alert_type", nullable = false, length = 50)
    private String alertType;

    /**
     * 공격 IP 주소 (IPv6 지원을 위해 45자)
     */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /**
     * 중복 판단용 고유 키 (alertType:ipAddress 형태)
     */
    @Column(name = "alert_key", nullable = false, unique = true, length = 255)
    private String alertKey;

    /**
     * 최초 탐지 시간
     */
    @Column(name = "first_detected_at", nullable = false)
    private LocalDateTime firstDetectedAt;

    /**
     * 마지막 알림 전송 시간
     */
    @Column(name = "last_alerted_at", nullable = false)
    private LocalDateTime lastAlertedAt;

    /**
     * 총 알림 전송 횟수
     */
    @Column(name = "alert_count", nullable = false)
    @Builder.Default
    private Integer alertCount = 1;

    /**
     * 담당자 확인 여부
     */
    @Column(name = "acknowledged", nullable = false)
    @Builder.Default
    private Boolean acknowledged = false;

    /**
     * 확인한 관리자 이메일
     */
    @Column(name = "acknowledged_by", length = 100)
    private String acknowledgedBy;

    /**
     * 확인 시간
     */
    @Column(name = "acknowledged_at")
    private LocalDateTime acknowledgedAt;

    /**
     * 알림 억제 종료 시간 (이 시간까지 알림 전송 안함)
     */
    @Column(name = "suppressed_until")
    private LocalDateTime suppressedUntil;

    /**
     * 알림 심각도 (참고용)
     */
    @Column(name = "severity", length = 20)
    private String severity;

    /**
     * 마지막 알림 메시지 (디버깅용)
     */
    @Column(name = "last_message", columnDefinition = "TEXT")
    private String lastMessage;

    /**
     * 생성 시간
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * 수정 시간
     */
    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /**
     * 알림 확인 처리
     */
    public void acknowledge(String adminEmail) {
        this.acknowledged = true;
        this.acknowledgedBy = adminEmail;
        this.acknowledgedAt = LocalDateTime.now();
    }

    /**
     * 알림 억제 설정
     */
    public void suppressUntil(LocalDateTime until, String adminEmail) {
        this.suppressedUntil = until;
        this.acknowledgedBy = adminEmail;
        this.acknowledgedAt = LocalDateTime.now();
    }

    /**
     * 새 알림 전송 시 카운트 증가
     */
    public void incrementAlertCount() {
        this.alertCount++;
        this.lastAlertedAt = LocalDateTime.now();
        this.acknowledged = false; // 새 알림이므로 미확인 상태로
    }

    /**
     * 탐지만 되고 알림은 안 보낸 경우 (억제됨)
     */
    public void incrementDetectionOnly() {
        this.alertCount++;
        // lastAlertedAt은 업데이트 안함 (실제로 알림 전송 안했으므로)
    }
}