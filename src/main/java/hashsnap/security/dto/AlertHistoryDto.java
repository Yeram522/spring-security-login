package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 알림 이력 DTO
 * SecurityAlertHistory 엔티티를 클라이언트에게 전달하기 위한 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertHistoryDto {

    /**
     * 알림 이력 ID
     */
    private Long id;

    /**
     * 알림 고유 키 (alertType:ipAddress 형태)
     */
    private String alertKey;

    /**
     * 알림 타입 (한글 변환된 값)
     * 예: "이메일 인증 공격", "관리자 스캐닝", "브루트포스 공격" 등
     */
    private String alertType;

    /**
     * 공격 IP 주소
     */
    private String ipAddress;

    /**
     * 심각도 (CRITICAL, HIGH, MEDIUM, LOW)
     */
    private String severity;

    /**
     * 총 알림 발생 횟수
     */
    private Integer alertCount;

    /**
     * 최초 탐지 시간
     */
    private LocalDateTime firstDetectedAt;

    /**
     * 마지막 알림 발생 시간
     */
    private LocalDateTime lastAlertedAt;

    /**
     * 확인 여부
     */
    private Boolean acknowledged;

    /**
     * 확인한 관리자 이메일
     */
    private String acknowledgedBy;

    /**
     * 확인 처리 시간
     */
    private LocalDateTime acknowledgedAt;

    /**
     * 알림 억제 종료 시간
     */
    private LocalDateTime suppressedUntil;

    /**
     * 마지막 알림 메시지
     */
    private String lastMessage;

    /**
     * 알림이 현재 억제 상태인지 확인
     */
    public boolean isSuppressed() {
        return suppressedUntil != null && suppressedUntil.isAfter(LocalDateTime.now());
    }

    /**
     * 알림의 상태를 문자열로 반환
     */
    public String getStatusText() {
        if (acknowledged) {
            return "확인됨";
        } else if (isSuppressed()) {
            return "억제됨";
        } else {
            return "미확인";
        }
    }

    /**
     * 심각도를 숫자로 변환 (정렬용)
     */
    public int getSeverityLevel() {
        return switch (severity) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}