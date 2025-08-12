package hashsnap.security.service;

import hashsnap.security.entity.SecurityAlertHistory;
import hashsnap.security.repository.SecurityAlertHistoryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AlertDeduplicationService {
    private final SecurityAlertHistoryRepository alertHistoryRepository;
    private final AlertService alertService;

    // 알림 중복 방지 정책 (분 단위)
    private static final Map<String, Integer> ALERT_COOLDOWN_MINUTES = Map.of(
            "EMAIL_VERIFICATION_ATTACK", 30,  // 이메일 공격: 30분간 억제
            "API_ABUSE", 15,                   // API 남용: 15분간 억제
            "ADMIN_SCANNING", 60,              // Admin 스캔: 1시간 억제
            "DIRECTORY_SCANNING", 45,          // 디렉토리 스캔: 45분간 억제
            "DDOS_ATTACK", 10                  // DDoS: 10분간 억제 (심각하므로 짧게)
    );

    public int getConnectedAdminCount() {
        return alertService.getConnectedAdminCount();
    }

    /**
     * 중복 방지 로직을 거쳐 알림 전송
     */
    public void sendAlertWithDeduplication(String alertType, String ipAddress,
                                           String title, String message, String severity) {

        // 1. 알림 키 생성 (중복 판단 기준)
        String alertKey = generateAlertKey(alertType, ipAddress);

        // 2. 기존 알림 이력 확인
        Optional<SecurityAlertHistory> existingAlert =
                alertHistoryRepository.findByAlertKey(alertKey);

        if (existingAlert.isPresent()) {
            SecurityAlertHistory history = existingAlert.get();

            // 3. 쿨다운 기간 확인
            if (isInCooldownPeriod(history, alertType)) {
                log.info("🔇 알림 억제 중: {} - {} (마지막 알림: {})",
                        alertType, ipAddress, history.getLastAlertedAt());
                updateAlertCount(history);
                return;
            }

            // 4. 담당자가 확인했는데 계속 발생하는 경우
            if (history.getAcknowledged() && !isEscalationNeeded(history)) {
                log.info("✅ 확인된 알림 억제: {} - {} (확인자: {})",
                        alertType, ipAddress, history.getAcknowledgedBy());
                updateAlertCount(history);
                return;
            }
        }

        // 5. 알림 전송 허용 - 실제 전송
        alertService.sendSecurityAlert(alertType, title, message, severity, ipAddress);

        // 6. 알림 이력 저장/업데이트
        saveOrUpdateAlertHistory(alertKey, alertType, ipAddress);

        log.info("🚨 새 알림 전송: {} - {}", alertType, ipAddress);
    }

    /**
     * 알림 키 생성 (중복 판단 기준)
     */
    private String generateAlertKey(String alertType, String ipAddress) {
        if ("DDOS_ATTACK".equals(alertType)) {
            // DDoS는 IP 상관없이 전체적인 공격으로 판단
            return alertType;
        }
        return String.format("%s:%s", alertType, ipAddress);
    }

    /**
     * 쿨다운 기간 확인
     */
    private boolean isInCooldownPeriod(SecurityAlertHistory history, String alertType) {
        int cooldownMinutes = ALERT_COOLDOWN_MINUTES.getOrDefault(alertType, 30);
        LocalDateTime cooldownEnd = history.getLastAlertedAt().plusMinutes(cooldownMinutes);

        // 억제 종료 시간이 명시적으로 설정된 경우
        if (history.getSuppressedUntil() != null) {
            cooldownEnd = history.getSuppressedUntil();
        }

        return LocalDateTime.now().isBefore(cooldownEnd);
    }

    /**
     * 에스컬레이션 필요 여부 판단
     */
    private boolean isEscalationNeeded(SecurityAlertHistory history) {
        // 확인 후 1시간이 지났는데 계속 발생하면 재알림
        if (history.getAcknowledgedAt() != null) {
            LocalDateTime escalationTime = history.getAcknowledgedAt().plusHours(1);
            return LocalDateTime.now().isAfter(escalationTime);
        }
        return false;
    }

    /**
     * 알림 이력 저장/업데이트
     */
    private void saveOrUpdateAlertHistory(String alertKey, String alertType, String ipAddress) {
        Optional<SecurityAlertHistory> existingAlert =
                alertHistoryRepository.findByAlertKey(alertKey);

        if (existingAlert.isPresent()) {
            // 기존 이력 업데이트
            SecurityAlertHistory history = existingAlert.get();
            history.setLastAlertedAt(LocalDateTime.now());
            history.setAlertCount(history.getAlertCount() + 1);
            history.setAcknowledged(false); // 새 알림이므로 미확인 상태로
            alertHistoryRepository.save(history);
        } else {
            // 새 이력 생성
            SecurityAlertHistory newHistory = SecurityAlertHistory.builder()
                    .alertType(alertType)
                    .ipAddress(ipAddress)
                    .alertKey(alertKey)
                    .firstDetectedAt(LocalDateTime.now())
                    .lastAlertedAt(LocalDateTime.now())
                    .alertCount(1)
                    .acknowledged(false)
                    .build();
            alertHistoryRepository.save(newHistory);
        }
    }

    /**
     * 알림 카운트만 업데이트 (실제 전송 안함)
     */
    private void updateAlertCount(SecurityAlertHistory history) {
        history.setAlertCount(history.getAlertCount() + 1);
        alertHistoryRepository.save(history);
    }

    /**
     * 관리자가 알림 확인 처리
     */
    @Transactional
    public void acknowledgeAlert(String alertKey, String adminEmail) {
        SecurityAlertHistory history = alertHistoryRepository.findByAlertKey(alertKey)
                .orElseThrow(() -> new IllegalArgumentException("알림 이력을 찾을 수 없습니다: " + alertKey));

        history.setAcknowledged(true);
        history.setAcknowledgedBy(adminEmail);
        history.setAcknowledgedAt(LocalDateTime.now());

        alertHistoryRepository.save(history);
        log.info("✅ 알림 확인 처리: {} by {}", alertKey, adminEmail);
    }

    /**
     * 특정 시간까지 알림 억제
     */
    @Transactional
    public void suppressAlertUntil(String alertKey, LocalDateTime suppressUntil, String adminEmail) {
        SecurityAlertHistory history = alertHistoryRepository.findByAlertKey(alertKey)
                .orElseThrow(() -> new IllegalArgumentException("알림 이력을 찾을 수 없습니다: " + alertKey));

        history.setSuppressedUntil(suppressUntil);
        history.setAcknowledgedBy(adminEmail);
        history.setAcknowledgedAt(LocalDateTime.now());

        alertHistoryRepository.save(history);
        log.info("🔇 알림 억제 설정: {} until {} by {}", alertKey, suppressUntil, adminEmail);
    }

}
