package hashsnap.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class AlertService {
    private final Map<String, SseEmitter> connectedAdmins = new ConcurrentHashMap<>();

    // SSE Emitter 생성
    public SseEmitter createEmitter() {
        String adminId = UUID.randomUUID().toString();
        SseEmitter emitter = new SseEmitter(30 * 60 * 1000L); // 30분

        connectedAdmins.put(adminId, emitter);
        log.info("💻 새로운 관리자 연결: 총 {}명 접속 중", connectedAdmins.size());

        // 즉시 환영 메시지 전송
        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data("연결 성공! 실시간 보안 알림을 받을 준비가 완료되었습니다."));
        } catch (Exception e) {
            log.error("환영 메시지 전송 실패: {}", e.getMessage());
            connectedAdmins.remove(adminId);
            return emitter;
        }

        emitter.onCompletion(() -> {
            connectedAdmins.remove(adminId);
            log.info("👋 관리자 연결 종료: 총 {}명 접속 중", connectedAdmins.size());
        });

        emitter.onTimeout(() -> {
            connectedAdmins.remove(adminId);
            log.info("⏰ 관리자 연결 타임아웃: 총 {}명 접속 중", connectedAdmins.size());
        });

        return emitter;
    }

    // 1. 이메일 인증 공격 알림
    public void sendEmailVerificationAttackAlert(String ipAddress, int failureCount, String failureTypes) {
        String message = String.format("🚨 IP %s에서 %d회 이메일 인증 실패 시도 (유형: %s)",
                ipAddress, failureCount, failureTypes);

        sendAlert("EMAIL_VERIFICATION_ATTACK", "이메일 인증 공격 탐지", message, "HIGH", ipAddress);
    }

    // 2. API 남용 알림
    public void sendApiAbuseAlert(String ipAddress, int callCount, String apiPattern) {
        String message = String.format("🚨 IP %s에서 1분간 %d회 API 호출 (패턴: %s)",
                ipAddress, callCount, apiPattern);

        sendAlert("API_ABUSE", "API 남용 탐지", message, "MEDIUM", ipAddress);
    }

    // 3. Admin 스캐닝 알림
    public void sendAdminScanAlert(String ipAddress, int attemptCount, String endpoints, String statusCodes) {
        String message = String.format("🚨 IP %s에서 %d회 Admin 페이지 스캐닝 시도\n엔드포인트: %s\n응답코드: %s",
                ipAddress, attemptCount, endpoints, statusCodes);

        sendAlert("ADMIN_SCANNING", "Admin 페이지 스캐닝 탐지", message, "HIGH", ipAddress);
    }

    // 4. 디렉토리 스캐닝 알림
    public void sendDirectoryScanAlert(String ipAddress, int errorCount, String scannedPaths, String scanType) {
        String message = String.format("🚨 IP %s에서 %d회 디렉토리 스캐닝 (%s)\n시도 경로: %s",
                ipAddress, errorCount, scanType, scannedPaths);

        sendAlert("DIRECTORY_SCANNING", "디렉토리 스캐닝 탐지", message, "MEDIUM", ipAddress);
    }

    // 5. DDoS 공격 알림
    public void sendDDoSAlert(double currentAvg, double previousAvg, double requestIncrease, String topAttackingIps) {
        String message = String.format("🚨 DDoS 공격 의심 상황\n현재 평균 응답시간: %.2fms\n이전 평균 응답시간: %.2fms\n요청량 증가: %.1f%%\n상위 공격 IP: %s",
                currentAvg, previousAvg, requestIncrease, topAttackingIps);

        sendAlert("DDOS_ATTACK", "DDoS 공격 탐지", message, "CRITICAL", "multiple_ips");
    }

    // 공통 알림 전송 메서드
    private void sendAlert(String type, String title, String message, String severity, String ipAddress) {
        // 연결된 모든 관리자에게 알림 전송
        List<SseEmitter> deadEmitters = new ArrayList<>();

        Map<String, Object> alert = Map.of(
                "type", type,
                "title", title,
                "message", message,
                "severity", severity,
                "ipAddress", ipAddress,
                "timestamp", Instant.now().toString()
        );

        List<String> failedAdmins = new ArrayList<>();

        connectedAdmins.forEach((adminId, emitter) -> {
            try {
                emitter.send(SseEmitter.event()
                        .name("security_alert")
                        .data(alert));
            } catch (Exception e) {
                failedAdmins.add(adminId);
                log.warn("관리자 {} 전송 실패: {}", adminId, e.getMessage());
            }
        });

        // 실패한 연결 제거
        failedAdmins.forEach(connectedAdmins::remove);

        log.warn("🔔 보안 알림 전송: {} - {} ({}명에게 전송)", severity, title, connectedAdmins.size());
    }

    // 현재 연결된 관리자 수 확인
    public int getConnectedAdminCount() {
        return connectedAdmins.size();
    }

    // 테스트용 알림 (개발 중 확인용)
    public void sendTestAlert() {
        log.info("🧪 테스트 알림 전송 시도 - 연결된 관리자: {}명", connectedAdmins.size());
        sendAlert("TEST", "테스트 알림", "SSE 연결이 정상적으로 작동합니다! 🎉\n시간: " + Instant.now(), "MEDIUM", "127.0.0.1");
    }
}
