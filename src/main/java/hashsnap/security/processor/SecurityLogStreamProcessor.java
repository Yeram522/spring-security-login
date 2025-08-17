package hashsnap.security.processor;

import hashsnap.security.entity.SecurityLogEvent;
import hashsnap.security.repository.SecurityLogRepository;
import hashsnap.security.service.AlertDeduplicationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 보안 로그 실시간 스트림 처리기
 * ElasticSearch 저장과 동시에 Redis 기반 실시간 위협 탐지 수행
 * 대용량 로그 처리 시 손실 없는 보안 분석 제공
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityLogStreamProcessor {

    private final RedisTemplate<String, String> redisTemplate;
    private final AlertDeduplicationService alertDeduplicationService;
    private final SecurityLogRepository securityLogRepository;

    /**
     * 실시간 로그 처리 - 저장과 분석을 동시에
     * @param logEvent 보안 로그 이벤트
     */
    @Async
    public void processLogInRealTime(SecurityLogEvent logEvent) {
        try {
            // 1. ElasticSearch에 저장 (기존 로직 유지)
            securityLogRepository.save(logEvent);

            // 2. 카운트 증가 + 임계값 즉시 체크 (손실 방지)
            checkThresholds(logEvent);

        } catch (Exception e) {
            log.error("실시간 로그 처리 실패: endpoint={}, ip={}",
                    logEvent.getEndpoint(), logEvent.getIpAddress(), e);
        }
    }

    /**
     * 실시간 임계값 체크 및 즉시 알림
     */
    private void checkThresholds(SecurityLogEvent logEvent) {
        String ip = logEvent.getIpAddress();
        String minute = getCurrentMinute();

        // 이메일 브루트포스 체크
        if (logEvent.getEndpoint().contains("/auth/email") && logEvent.getStatusCode() >= 400) {
            String key = "email_fail:" + ip + ":" + minute;

            // 동기적 카운트 증가
            Long currentCount = redisTemplate.opsForValue().increment(key);
            redisTemplate.expire(key, Duration.ofMinutes(5));

            if (currentCount >= 5) {
                alertDeduplicationService.sendAlertWithDeduplication(
                        "EMAIL_VERIFICATION_ATTACK",
                        ip,
                        "🚨 이메일 브루트포스 탐지 (실시간)",
                        String.format("IP %s에서 %d회 실패 (실시간 탐지)", ip, currentCount),
                        "CRITICAL"
                );
            }
        }

        // API 남용 체크
        if (logEvent.getEndpoint().startsWith("/api")) {
            String key = "api_call:" + ip + ":" + minute;

            // 동기적 카운트 증가
            Long currentCount = redisTemplate.opsForValue().increment(key);
            redisTemplate.expire(key, Duration.ofMinutes(1));

            if (currentCount >= 50) {
                alertDeduplicationService.sendAlertWithDeduplication(
                        "API_ABUSE",
                        ip,
                        "🚨 API 남용 탐지 (실시간)",
                        String.format("IP %s에서 %d회 호출 (실시간 탐지)", ip, currentCount),
                        "HIGH"
                );
            }
        }

        // Admin 스캐닝
        if (logEvent.getEndpoint().contains("/admin") &&
                (logEvent.getStatusCode() == 302 || logEvent.getStatusCode() >= 400)) {

            String minuteKey = "admin_fail:" + ip + ":" + minute;
            String hourlyKey = "admin_fail_hourly:" + ip + ":" + getCurrentHour();

            Long currentMinuteCount = redisTemplate.opsForValue().increment(minuteKey);

            redisTemplate.expire(minuteKey, Duration.ofMinutes(10));
            redisTemplate.expire(hourlyKey, Duration.ofHours(1));

            if (currentMinuteCount >= 5) {
                alertDeduplicationService.sendAlertWithDeduplication(
                        "ADMIN_SCANNING_IMMEDIATE",
                        ip,
                        "🚨 관리자 페이지 집중 스캐닝 탐지",
                        String.format("IP %s에서 %d회 Admin 접근 시도 (1분간)", ip, currentMinuteCount),
                        "CRITICAL"
                );
            }
        }

        // 디렉토리 스캐닝 체크
        if (logEvent.getStatusCode() == 404) {
            String key = "not_found:" + ip + ":" + minute;

            // 동기적 카운트 증가
            Long currentCount = redisTemplate.opsForValue().increment(key);
            redisTemplate.expire(key, Duration.ofMinutes(2));

            if (currentCount >= 20) {
                alertDeduplicationService.sendAlertWithDeduplication(
                        "DIRECTORY_SCANNING",
                        ip,
                        "🚨 디렉토리 스캐닝 탐지 (실시간)",
                        String.format("IP %s에서 %d회 404 에러 (실시간 탐지)", ip, currentCount),
                        "MEDIUM"
                );
            }
        }
    }

    /**
     * 현재 분을 키로 사용 (Redis 키 생성용)
     */
    private String getCurrentMinute() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm"));
    }

    private String getCurrentHour() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH"));
    }
}