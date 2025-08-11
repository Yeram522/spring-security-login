package hashsnap.security.controller;


import hashsnap.global.response.ApiResponse;
import hashsnap.global.util.JwtUtil;
import hashsnap.global.util.ResponseUtils;
import hashsnap.security.service.AlertDeduplicationService;
import hashsnap.security.service.AlertService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/admin/security")
@RequiredArgsConstructor
@Slf4j
public class AlertController {

    private final AlertService alertService;
    private final AlertDeduplicationService alertDeduplicationService;
    private final JwtUtil jwtUtil; // JWT 유틸 주입

    @GetMapping(value = "/alerts/stream", produces = "text/event-stream")
    public SseEmitter streamAlerts(@RequestParam("token") String token) {
        log.info("🚀 SSE 요청 수신, 토큰: {}자", token.length());

        try {
            if (!jwtUtil.validateToken(token)) {
                log.error("❌ JWT 토큰 검증 실패");
                throw new RuntimeException("Invalid token");
            }

            String email = jwtUtil.getEmail(token);
            log.info("🔗 관리자 {} SSE 연결 성공!", email);

            return alertService.createEmitter();

        } catch (Exception e) {
            log.error("❌ SSE 연결 실패: {}", e.getMessage());
            SseEmitter errorEmitter = new SseEmitter(1000L);
            try {
                errorEmitter.send("인증 실패: " + e.getMessage());
                errorEmitter.complete();
            } catch (Exception ex) {
                // ignore
            }
            return errorEmitter;
        }
    }

    // 연결된 관리자 수 확인
    @GetMapping("/alerts/connected-count")
    public ResponseEntity<Integer> getConnectedCount() {
        return ResponseEntity.ok(alertService.getConnectedAdminCount());
    }

    // 테스트 알림 전송 (개발용)
    @PostMapping("/alerts/test")
    public ResponseEntity<String> sendTestAlert(Authentication auth) {
        log.info("👨‍💻 관리자 {}가 테스트 알림 전송", auth.getName());
        alertService.sendTestAlert();
        return ResponseEntity.ok("테스트 알림 전송 완료");
    }

    /**
     * 알림 확인 처리 API
     */
    @PostMapping("/alerts/acknowledge")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> acknowledgeAlert(
            @RequestBody AlertAcknowledgeRequest request,
            Authentication auth) {

        alertDeduplicationService.acknowledgeAlert(request.getAlertKey(), auth.getName());
        return ResponseUtils.ok("알림이 확인 처리되었습니다");
    }

    /**
     * 알림 억제 처리 API
     */
    @PostMapping("/alerts/suppress")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> suppressAlert(
            @RequestBody AlertSuppressRequest request,
            Authentication auth) {

        LocalDateTime suppressUntil = LocalDateTime.now().plusHours(request.getSuppressHours());
        alertDeduplicationService.suppressAlertUntil(request.getAlertKey(), suppressUntil, auth.getName());
        return ResponseUtils.ok(request.getSuppressHours() + "시간 동안 알림이 억제됩니다");
    }

}

@Data
class AlertAcknowledgeRequest {
    private String alertKey;
}

@Data
class AlertSuppressRequest {
    private String alertKey;
    private int suppressHours;
}

