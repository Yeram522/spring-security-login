package hashsnap.security.service;

import hashsnap.security.entity.SecurityLogEvent;
import hashsnap.security.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class SecurityLogService {

    private final SecurityLogRepository securityLogRepository;

    // 동기 로그 저장
    public SecurityLogEvent saveLog(SecurityLogEvent event) {
        try {
            event.setTimestamp(Instant.now());
            SecurityLogEvent saved = securityLogRepository.save(event);
            log.info("보안 로그 저장 완료: {}", saved.getEmail());
            return saved;
        } catch (Exception e) {
            log.error("보안 로그 저장 실패", e);
            throw e;
        }
    }

    // 비동기 로그 저장 (성능 최적화)
    @Async
    public void saveLogAsync(SecurityLogEvent event) {
        saveLog(event);
    }

    // 로그 조회
    public List<SecurityLogEvent> getRecentLogs(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return securityLogRepository.findByTimestampAfter(since);
    }

    public List<SecurityLogEvent> getLogsByEventType(String eventType) {
        return securityLogRepository.findByEventType(eventType);
    }
}
