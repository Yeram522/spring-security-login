package hashsnap.security.service;

import hashsnap.security.dto.*;
import hashsnap.security.entity.SecurityAlertHistory;
import hashsnap.security.entity.SecurityLogEvent;
import hashsnap.security.repository.SecurityAlertHistoryRepository;
import hashsnap.security.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 대시보드 비즈니스 로직 서비스
 * SecurityAlertHistory와 SecurityLogEvent를 활용한 보안 대시보드 데이터 제공
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DashboardService {

    private final SecurityAlertHistoryRepository alertHistoryRepository;
    private final SecurityLogRepository securityLogRepository;

    /**
     * 실시간 보안 메트릭 조회
     */
    public SecurityMetricsDto getSecurityMetrics(String timeRange) {
        LocalDateTime since = getSinceDateTime(timeRange);

        // 1. 긴급 알림 수
        long criticalAlerts = getCriticalAlertsCount(since);

        // 2. 차단 대상 IP 수
        long blockedIps = getBlockedIpsCount(since);

        // 3. 성공적인 로그인 수
        long successfulLogins = getSuccessfulLoginsCount(since);

        // 4. 총 요청 수
        long totalRequests = getTotalRequestsCount(since);

        // 5. 경고 수
        long warningCount = getWarningCount(since);

        return SecurityMetricsDto.builder()
                .criticalAlerts(criticalAlerts)
                .blockedIps(blockedIps)
                .successfulLogins(successfulLogins)
                .totalRequests(totalRequests)
                .warningCount(warningCount)
                .build();
    }

    /**
     * 상위 위협 IP 목록 조회
     */
    public List<ThreatIpDto> getTopThreatIps(String timeRange) {
        LocalDateTime since = getSinceDateTime(timeRange);

        // Repository의 최적화된 쿼리 사용
        List<Object[]> topAttackingIPs = alertHistoryRepository.getTopAttackingIPs(
                since, PageRequest.of(0, 10));

        return topAttackingIPs.stream()
                .map(this::convertToThreatIpDto)
                .collect(Collectors.toList());
    }

    /**
     * 보안 이벤트 타임라인 데이터 조회
     */
    public List<TimelineDataDto> getSecurityTimeline(String timeRange) {
        LocalDateTime since = getSinceDateTime(timeRange);

        // 알림 히스토리에서 타임라인 데이터 생성
        List<SecurityAlertHistory> alerts = alertHistoryRepository.findByLastAlertedAtBetween(
                since, LocalDateTime.now());

        // 5분 단위로 그룹화
        Map<String, List<SecurityAlertHistory>> timeGroups = groupAlertsByTimeInterval(alerts, 5);

        return timeGroups.entrySet().stream()
                .map(this::convertToTimelineData)
                .sorted(Comparator.comparing(TimelineDataDto::getTimestamp))
                .collect(Collectors.toList());
    }

    /**
     * 시간대별 공격 패턴 분석
     */
    public List<HourlyPatternDto> getHourlyPattern() {
        LocalDateTime since = LocalDateTime.now().minusDays(1);

        List<SecurityAlertHistory> dayAlerts = alertHistoryRepository.findByLastAlertedAtBetween(
                since, LocalDateTime.now());

        // 시간별 그룹화
        Map<Integer, List<SecurityAlertHistory>> hourlyGroups = dayAlerts.stream()
                .collect(Collectors.groupingBy(alert -> alert.getLastAlertedAt().getHour()));

        List<HourlyPatternDto> patterns = new ArrayList<>();
        for (int hour = 0; hour < 24; hour++) {
            List<SecurityAlertHistory> hourAlerts = hourlyGroups.getOrDefault(hour, Collections.emptyList());
            long attackCount = hourAlerts.stream()
                    .mapToLong(SecurityAlertHistory::getAlertCount)
                    .sum();

            patterns.add(HourlyPatternDto.builder()
                    .hour(hour)
                    .attackCount(attackCount)
                    .build());
        }

        return patterns;
    }

    /**
     * 응답시간 모니터링 데이터
     */
    public List<ResponseTimeDto> getResponseTimes(String timeRange) {
        LocalDateTime since = getSinceDateTime(timeRange);
        String fromTime = since.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        List<SecurityLogEvent> logsWithResponseTime = securityLogRepository.findLogsWithResponseTimeAfter(fromTime);

        // 5분 단위로 평균 응답시간 계산
        Map<String, List<SecurityLogEvent>> timeGroups = groupLogsByTimeInterval(logsWithResponseTime, 5);

        return timeGroups.entrySet().stream()
                .map(this::convertToResponseTimeData)
                .sorted(Comparator.comparing(ResponseTimeDto::getTimestamp))
                .collect(Collectors.toList());
    }

    /**
     * 알림 이력 페이지네이션 조회
     */
    public Page<AlertHistoryDto> getAlertHistory(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<SecurityAlertHistory> alertPage = alertHistoryRepository.findAllByOrderByLastAlertedAtDesc(pageable);

        return alertPage.map(this::convertToAlertHistoryDto);
    }

    /**
     * 미확인 알림 목록 조회
     */
    public List<AlertHistoryDto> getUnacknowledgedAlerts() {
        List<SecurityAlertHistory> unacknowledgedAlerts = alertHistoryRepository.findUnacknowledgedAlerts();

        return unacknowledgedAlerts.stream()
                .map(this::convertToAlertHistoryDto)
                .collect(Collectors.toList());
    }

    /**
     * 억제된 알림 목록 조회
     */
    public List<AlertHistoryDto> getSuppressedAlerts() {
        List<SecurityAlertHistory> suppressedAlerts = alertHistoryRepository
                .findActivelySuppressedAlerts(LocalDateTime.now());

        return suppressedAlerts.stream()
                .map(this::convertToAlertHistoryDto)
                .collect(Collectors.toList());
    }

    /**
     * 특정 관리자가 확인한 알림 조회
     */
    public List<AlertHistoryDto> getAlertsByAdmin(String adminEmail) {
        List<SecurityAlertHistory> adminAlerts = alertHistoryRepository
                .findByAcknowledgedByOrderByAcknowledgedAtDesc(adminEmail);

        return adminAlerts.stream()
                .map(this::convertToAlertHistoryDto)
                .collect(Collectors.toList());
    }

    /**
     * 오래된 확인된 알림 정리
     */
    public int cleanupOldAlerts(int daysBefore) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysBefore);
        return alertHistoryRepository.deleteOldAcknowledgedAlerts(cutoffDate);
    }

    /**
     * 알림 타입별 통계
     */
    public List<AlertTypeStatDto> getAlertTypeStatistics(String timeRange) {
        LocalDateTime since = getSinceDateTime(timeRange);

        List<Object[]> alertStats = alertHistoryRepository.getAlertStatisticsByType(since);

        return alertStats.stream()
                .map(this::convertToAlertTypeStat)
                .sorted(Comparator.comparing(AlertTypeStatDto::getTotalAlertCount, Comparator.reverseOrder()))
                .collect(Collectors.toList());
    }

    // === Private 헬퍼 메서드들 ===

    private AlertHistoryDto convertToAlertHistoryDto(SecurityAlertHistory alert) {
        return AlertHistoryDto.builder()
                .id(alert.getId())
                .alertKey(alert.getAlertKey())
                .alertType(convertAlertTypeToDisplayName(alert.getAlertType()))
                .ipAddress(alert.getIpAddress())
                .severity(alert.getSeverity())
                .alertCount(alert.getAlertCount())
                .firstDetectedAt(alert.getFirstDetectedAt())
                .lastAlertedAt(alert.getLastAlertedAt())
                .acknowledged(alert.getAcknowledged())
                .acknowledgedBy(alert.getAcknowledgedBy())
                .acknowledgedAt(alert.getAcknowledgedAt())
                .suppressedUntil(alert.getSuppressedUntil())
                .lastMessage(alert.getLastMessage())
                .build();
    }

    private long getCriticalAlertsCount(LocalDateTime since) {
        List<SecurityAlertHistory> unacknowledgedAlerts = alertHistoryRepository.findUnacknowledgedAlerts();
        return unacknowledgedAlerts.stream()
                .filter(alert -> ("CRITICAL".equals(alert.getSeverity()) || "HIGH".equals(alert.getSeverity())))
                .filter(alert -> alert.getLastAlertedAt().isAfter(since))
                .count();
    }

    private long getBlockedIpsCount(LocalDateTime since) {
        List<Object[]> topAttackingIPs = alertHistoryRepository.getTopAttackingIPs(
                since, PageRequest.of(0, 100));
        return topAttackingIPs.stream()
                .map(row -> (Long) row[2]) // alertCount 합계
                .filter(count -> count >= 10) // 10회 이상 공격한 IP들
                .count();
    }

    private long getSuccessfulLoginsCount(LocalDateTime since) {
        List<SecurityLogEvent> allLogs = securityLogRepository.findByTimestampAfter(since);
        return allLogs.stream()
                .filter(log -> "LOGIN_SUCCESS".equals(log.getEventType()) ||
                        (log.getEndpoint() != null && log.getEndpoint().contains("/auth/login") &&
                                log.getStatusCode() != null && log.getStatusCode() == 200))
                .count();
    }

    private long getTotalRequestsCount(LocalDateTime since) {
        return securityLogRepository.findByTimestampAfter(since).size();
    }

    private long getWarningCount(LocalDateTime since) {
        return alertHistoryRepository.findBySeverityOrderByLastAlertedAtDesc("MEDIUM").stream()
                .filter(alert -> alert.getLastAlertedAt().isAfter(since))
                .count();
    }

    private ThreatIpDto convertToThreatIpDto(Object[] row) {
        String ip = (String) row[0];
        Long alertHistoryCount = (Long) row[1];
        Long totalAlertCount = (Long) row[2];

        // 해당 IP의 알림 상세 정보 조회
        List<SecurityAlertHistory> ipAlerts = alertHistoryRepository
                .findByIpAddressOrderByLastAlertedAtDesc(ip);

        // 공격 유형 수집
        Set<String> attackTypes = ipAlerts.stream()
                .map(SecurityAlertHistory::getAlertType)
                .map(this::convertAlertTypeToDisplayName)
                .collect(Collectors.toSet());

        // 위험도 계산 (최고 심각도 기준)
        String riskLevel = ipAlerts.stream()
                .map(SecurityAlertHistory::getSeverity)
                .filter(Objects::nonNull)
                .max(this::compareSeverity)
                .orElse("LOW");

        // 마지막 탐지 시간
        LocalDateTime lastSeen = ipAlerts.stream()
                .map(SecurityAlertHistory::getLastAlertedAt)
                .max(LocalDateTime::compareTo)
                .orElse(LocalDateTime.now());

        return ThreatIpDto.builder()
                .ipAddress(ip)
                .attackCount(totalAlertCount)
                .countryCode(getCountryFromIP(ip))
                .attackTypes(new ArrayList<>(attackTypes))
                .riskLevel(riskLevel)
                .lastSeenAt(lastSeen.atZone(ZoneId.systemDefault()).toInstant())
                .build();
    }

    private Map<String, List<SecurityAlertHistory>> groupAlertsByTimeInterval(
            List<SecurityAlertHistory> alerts, int intervalMinutes) {
        return alerts.stream()
                .collect(Collectors.groupingBy(alert -> {
                    LocalDateTime alertTime = alert.getLastAlertedAt();
                    int minute = (alertTime.getMinute() / intervalMinutes) * intervalMinutes;
                    return alertTime.withMinute(minute).withSecond(0).withNano(0)
                            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                }));
    }

    private Map<String, List<SecurityLogEvent>> groupLogsByTimeInterval(
            List<SecurityLogEvent> logs, int intervalMinutes) {
        return logs.stream()
                .collect(Collectors.groupingBy(log -> {
                    LocalDateTime logTime = LocalDateTime.ofInstant(log.getTimestamp(), ZoneId.systemDefault());
                    int minute = (logTime.getMinute() / intervalMinutes) * intervalMinutes;
                    return logTime.withMinute(minute).withSecond(0).withNano(0)
                            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                }));
    }

    private TimelineDataDto convertToTimelineData(Map.Entry<String, List<SecurityAlertHistory>> entry) {
        String timeKey = entry.getKey();
        List<SecurityAlertHistory> timeAlerts = entry.getValue();

        // 공격 유형별 카운트
        long bruteforceCount = timeAlerts.stream()
                .filter(alert -> isAttackType(alert.getAlertType(), "BRUTE_FORCE", "EMAIL_VERIFICATION_ATTACK"))
                .mapToLong(SecurityAlertHistory::getAlertCount)
                .sum();

        long ddosCount = timeAlerts.stream()
                .filter(alert -> isAttackType(alert.getAlertType(), "API_ABUSE", "HIGH_VOLUME"))
                .mapToLong(SecurityAlertHistory::getAlertCount)
                .sum();

        long scanningCount = timeAlerts.stream()
                .filter(alert -> isAttackType(alert.getAlertType(), "ADMIN_SCANNING", "DIRECTORY_SCANNING"))
                .mapToLong(SecurityAlertHistory::getAlertCount)
                .sum();

        return TimelineDataDto.builder()
                .timestamp(timeKey)
                .bruteforceCount(bruteforceCount)
                .ddosCount(ddosCount)
                .scanningCount(scanningCount)
                .build();
    }

    private ResponseTimeDto convertToResponseTimeData(Map.Entry<String, List<SecurityLogEvent>> entry) {
        String timeKey = entry.getKey();
        List<SecurityLogEvent> events = entry.getValue();

        double avgResponseTime = events.stream()
                .filter(e -> e.getProcessingTimeMs() != null)
                .mapToLong(SecurityLogEvent::getProcessingTimeMs)
                .average()
                .orElse(0.0);

        return ResponseTimeDto.builder()
                .timestamp(timeKey)
                .averageResponseTime(avgResponseTime)
                .requestCount((long) events.size())
                .build();
    }

    private AlertTypeStatDto convertToAlertTypeStat(Object[] row) {
        return AlertTypeStatDto.builder()
                .alertType(convertAlertTypeToDisplayName((String) row[0]))
                .alertHistoryCount((Long) row[1])
                .totalAlertCount((Long) row[2])
                .build();
    }

    private LocalDateTime getSinceDateTime(String timeRange) {
        LocalDateTime now = LocalDateTime.now();
        return switch (timeRange) {
            case "15m" -> now.minus(15, ChronoUnit.MINUTES);
            case "1h" -> now.minus(1, ChronoUnit.HOURS);
            case "24h" -> now.minus(24, ChronoUnit.HOURS);
            case "7d" -> now.minus(7, ChronoUnit.DAYS);
            default -> now.minus(1, ChronoUnit.HOURS);
        };
    }

    private String convertAlertTypeToDisplayName(String alertType) {
        return switch (alertType) {
            case "EMAIL_VERIFICATION_ATTACK" -> "이메일 인증 공격";
            case "API_ABUSE" -> "API 남용";
            case "ADMIN_SCANNING" -> "관리자 스캐닝";
            case "DIRECTORY_SCANNING" -> "디렉토리 스캐닝";
            case "BRUTE_FORCE" -> "브루트포스 공격";
            case "SQL_INJECTION" -> "SQL 인젝션";
            case "XSS_ATTACK" -> "XSS 공격";
            case "HIGH_VOLUME" -> "고볼륨 공격";
            default -> alertType;
        };
    }

    private boolean isAttackType(String alertType, String... targetTypes) {
        return Arrays.asList(targetTypes).contains(alertType);
    }

    private int compareSeverity(String severity1, String severity2) {
        Map<String, Integer> severityOrder = Map.of(
                "CRITICAL", 4,
                "HIGH", 3,
                "MEDIUM", 2,
                "LOW", 1
        );
        return Integer.compare(
                severityOrder.getOrDefault(severity1, 0),
                severityOrder.getOrDefault(severity2, 0)
        );
    }

    private String getCountryFromIP(String ip) {
        // 실제로는 GeoIP 라이브러리 사용
        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
            return "KR";
        }

        String[] countryCodes = {"CN", "RU", "US", "KP", "IR", "VN", "IN", "BR", "TR", "PK"};
        return countryCodes[Math.abs(ip.hashCode()) % countryCodes.length];
    }
}