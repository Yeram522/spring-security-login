package hashsnap.security.service;

import hashsnap.security.entity.SecurityLogEvent;
import hashsnap.security.repository.SecurityLogRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class SecurityAnalysisService {

    private final ElasticsearchOperations elasticsearchOperations;
    private final SecurityLogRepository securityLogRepository;
    private final AlertDeduplicationService alertDeduplicationService;

    // ✨ 임계값 설정
    private static final int EMAIL_VERIFICATION_THRESHOLD = 5;   // 5회 이메일 인증 실패
    private static final int API_ABUSE_THRESHOLD = 50;           // 1분에 50회 API 호출
    private static final int ADMIN_SCAN_THRESHOLD = 10;          // Admin 접근 10회
    private static final int NOT_FOUND_THRESHOLD = 20;           // 404 에러 20회
    private static final double RESPONSE_TIME_MULTIPLIER = 3.0;  // 응답시간 3배 증가

    @Scheduled(fixedDelay = 30000) // 30초마다 실행
    public void runSecurityAnalysis(){
        log.info("🔍 [{}] 보안 검사 시작 - 연결된 관리자: {}명",
                LocalDateTime.now(), alertDeduplicationService.getConnectedAdminCount());

        try{
            detectDDoSAttack();
            log.info("✅ [{}] 보안 분석 완료", LocalDateTime.now());
        }catch(Exception e){
            log.error("❌ [{}] 보안 분석 실패: {}", LocalDateTime.now(), e.getMessage(), e);
        }
    }

    // 디렉토리 스캐닝 탐지
    private void detectDirectoryScanning() {
        try {
            // 최근 2분간 404 에러 조회
            Instant twoMinutesAgo = Instant.now().minus(2, ChronoUnit.MINUTES);

            List<SecurityLogEvent> notFoundErrors = securityLogRepository
                    .findNotFoundErrorsAfter(twoMinutesAgo.toString());

            // IP별로 그룹화
            Map<String, List<SecurityLogEvent>> errorsByIp = notFoundErrors.stream()
                    .collect(Collectors.groupingBy(SecurityLogEvent::getIpAddress));

            // 임계값 초과 IP 찾기
            for (Map.Entry<String, List<SecurityLogEvent>> entry : errorsByIp.entrySet()) {
                String ipAddress = entry.getKey();
                List<SecurityLogEvent> ipErrors = entry.getValue();

                if (ipErrors.size() >= NOT_FOUND_THRESHOLD) {
                    // 스캔 패턴 분석
                    DirectoryScanPattern pattern = analyzeDirectoryScanPattern(ipErrors);
                    String title = "🚨 디렉토리 스캐닝 탐지";
                    String message = String.format(
                            "디렉토리 스캐닝 공격이 탐지되었습니다.\n\n" +
                                    "🔸 공격 IP: %s\n" +
                                    "🔸 404 에러: %d회 (2분간)\n" +
                                    "🔸 스캔 유형: %s\n" +
                                    "🔸 스캔 경로: %s\n" +
                                    "🔸 탐지 시간: %s\n\n" +
                                    "웹 방화벽 설정을 확인하세요.",
                            ipAddress, ipErrors.size(), pattern.getScanType(),
                            pattern.getScannedPaths(), LocalDateTime.now()
                    );

                    // 🔥 AlertDeduplicationService 사용
                    alertDeduplicationService.sendAlertWithDeduplication(
                            "DIRECTORY_SCANNING",
                            ipAddress,
                            title,
                            message,
                            "MEDIUM"
                    );

                    log.warn("🚨 디렉토리 스캐닝 탐지: IP={}, 404에러={}/2분, 패턴={}, 유형={}",
                            ipAddress, ipErrors.size(), pattern.getScannedPaths(), pattern.getScanType());
                }
            }

        } catch (Exception e) {
            log.error("디렉토리 스캐닝 탐지 실패", e);
        }
    }

    private DirectoryScanPattern analyzeDirectoryScanPattern(List<SecurityLogEvent> errors) {
        // 시도한 경로들
        Set<String> uniquePaths = errors.stream()
                .map(SecurityLogEvent::getEndpoint)
                .collect(Collectors.toSet());

        // 스캔 유형 분석
        String scanType = determineScanType(uniquePaths);

        String scannedPaths = uniquePaths.stream()
                .limit(10)
                .collect(Collectors.joining(", "));

        return new DirectoryScanPattern(scannedPaths, scanType);
    }

    private String determineScanType(Set<String> paths) {
        long adminPaths = paths.stream().filter(p -> p.contains("admin")).count();
        long apiPaths = paths.stream().filter(p -> p.startsWith("/api")).count();
        long configPaths = paths.stream().filter(p -> p.contains("config") || p.contains("env")).count();

        if (adminPaths > paths.size() * 0.5) return "관리자페이지탐색";
        if (apiPaths > paths.size() * 0.5) return "API엔드포인트스캐닝";
        if (configPaths > 0) return "설정파일탐색";
        return "일반디렉토리스캐닝";
    }

    @Data
    @AllArgsConstructor
    private static class DirectoryScanPattern {
        private String scannedPaths;
        private String scanType;
    }

    // DDoS 공격 탐지
    private void detectDDoSAttack() {
        try {
            Instant now = Instant.now();
            Instant fiveMinutesAgo = now.minus(5, ChronoUnit.MINUTES);
            Instant tenMinutesAgo = now.minus(10, ChronoUnit.MINUTES);

            // 현재 5분간 응답시간 데이터
            List<SecurityLogEvent> currentPeriodLogs = securityLogRepository
                    .findLogsWithResponseTimeAfter(fiveMinutesAgo.toString());

            // 이전 5분간 응답시간 데이터
            List<SecurityLogEvent> previousPeriodLogs = securityLogRepository
                    .findLogsBetweenTimes(tenMinutesAgo.toString(), fiveMinutesAgo.toString());

            if (currentPeriodLogs.isEmpty() || previousPeriodLogs.isEmpty()) {
                return; // 충분한 데이터가 없음
            }

            // 평균 응답시간 계산
            double currentAvg = currentPeriodLogs.stream()
                    .filter(log -> log.getProcessingTimeMs() != null)
                    .mapToLong(SecurityLogEvent::getProcessingTimeMs)
                    .average()
                    .orElse(0.0);

            double previousAvg = previousPeriodLogs.stream()
                    .filter(log -> log.getProcessingTimeMs() != null)
                    .mapToLong(SecurityLogEvent::getProcessingTimeMs)
                    .average()
                    .orElse(0.0);

            // DDoS 탐지 조건
            if (previousAvg > 0 && currentAvg > previousAvg * RESPONSE_TIME_MULTIPLIER) {
                // 상세 분석
                DDoSAnalysis analysis = analyzeDDoSPattern(currentPeriodLogs, previousPeriodLogs);
                String title = "🚨 DDoS 공격 의심";
                String message = String.format(
                        "DDoS 공격으로 의심되는 패턴이 탐지되었습니다.\n\n" +
                                "🔸 현재 평균 응답시간: %.2fms\n" +
                                "🔸 이전 평균 응답시간: %.2fms\n" +
                                "🔸 응답시간 증가율: %.1f%%\n" +
                                "🔸 요청량 증가율: %.1f%%\n" +
                                "🔸 상위 공격 IP: %s\n" +
                                "🔸 탐지 시간: %s\n\n" +
                                "긴급 대응이 필요합니다!",
                        currentAvg, previousAvg,
                        ((currentAvg - previousAvg) / previousAvg * 100),
                        analysis.getRequestIncrease(), analysis.getTopAttackingIps(),
                        LocalDateTime.now()
                );

                // 🔥 AlertDeduplicationService 사용
                alertDeduplicationService.sendAlertWithDeduplication(
                        "DDOS_ATTACK",
                        "multiple_ips",
                        title,
                        message,
                        "CRITICAL"
                );

                log.warn("🚨 DDoS 공격 의심: 현재평균={}ms, 이전평균={}ms, 요청증가={}%, 상위공격IP={}",
                        currentAvg, previousAvg, analysis.getRequestIncrease(), analysis.getTopAttackingIps());
            }

        } catch (Exception e) {
            log.error("DDoS 공격 탐지 실패", e);
        }
    }

    private DDoSAnalysis analyzeDDoSPattern(List<SecurityLogEvent> currentLogs, List<SecurityLogEvent> previousLogs) {
        // 요청량 증가율 계산
        double requestIncrease = ((double) currentLogs.size() - previousLogs.size()) / previousLogs.size() * 100;

        // 현재 기간 상위 공격 IP 분석 (요청량 기준)
        String topAttackingIps = currentLogs.stream()
                .collect(Collectors.groupingBy(
                        SecurityLogEvent::getIpAddress,
                        Collectors.counting()
                ))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(3)
                .map(entry -> entry.getKey() + ":" + entry.getValue() + "회")
                .collect(Collectors.joining(", "));

        return new DDoSAnalysis(requestIncrease, topAttackingIps);
    }

    @Data
    @AllArgsConstructor
    private static class DDoSAnalysis {
        private double requestIncrease;
        private String topAttackingIps;
    }
}