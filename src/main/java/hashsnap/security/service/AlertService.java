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

    public void sendSecurityAlert(String alertType, String title, String message, String severity, String ipAddress) {
        if (connectedAdmins.isEmpty()) {
            log.info("📭 연결된 관리자가 없어서 알림을 전송하지 않습니다: {}", title);
            return;
        }

        // 🔥 alertKey 생성 (확인 처리용)
        String alertKey = generateAlertKey(alertType, ipAddress);

        Map<String, Object> alert = Map.of(
                "type", alertType,
                "title", title,
                "message", message,
                "severity", severity,
                "ipAddress", ipAddress,
                "alertKey", alertKey,
                "timestamp", Instant.now().toString()
        );

        List<String> failedAdmins = new ArrayList<>();

        connectedAdmins.forEach((adminId, emitter) -> {
            try {
                emitter.send(SseEmitter.event()
                        .name("security_alert")
                        .data(alert));
                log.debug("✅ 관리자 {}에게 알림 전송 성공: {}", adminId, title);
            } catch (Exception e) {
                failedAdmins.add(adminId);
                log.warn("⚠️ 관리자 {} 전송 실패: {}", adminId, e.getMessage());
            }
        });

        // 실패한 연결 제거
        failedAdmins.forEach(connectedAdmins::remove);

        log.warn("🔔 보안 알림 전송 완료: {} - {} ({}명에게 전송)", severity, title, connectedAdmins.size());
    }

    // generateKey 생성 메서드
    private String generateAlertKey(String alertType, String ipAddress) {
        if ("DDOS_ATTACK".equals(alertType)) {
            return alertType;
        }
        return String.format("%s:%s", alertType, ipAddress);
    }

    // 현재 연결된 관리자 수 확인
    public int getConnectedAdminCount() {
        return connectedAdmins.size();
    }

    // 테스트용 알림 (개발 중 확인용)
    public void sendTestAlert() {
        log.info("🧪 테스트 알림 전송 시도 - 연결된 관리자: {}명", connectedAdmins.size());
        sendSecurityAlert("TEST", "테스트 알림", "SSE 연결이 정상적으로 작동합니다! 🎉\n시간: " + Instant.now(), "MEDIUM", "127.0.0.1");
    }
}
