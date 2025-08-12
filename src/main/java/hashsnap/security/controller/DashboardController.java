package hashsnap.security.controller;

import hashsnap.global.response.ApiResponse;
import hashsnap.global.util.ResponseUtils;
import hashsnap.security.dto.*;
import hashsnap.security.service.DashboardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 보안 대시보드 API 컨트롤러
 * Service 계층으로 비즈니스 로직을 분리하여 깔끔한 구조 유지
 */
@RestController
@RequestMapping("/api/v1/admin/dashboard")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class DashboardController {

    private final DashboardService dashboardService;

    /**
     * 실시간 보안 메트릭 조회
     */
    @GetMapping("/metrics")
    public ResponseEntity<ApiResponse<SecurityMetricsDto>> getSecurityMetrics(
            @RequestParam(defaultValue = "24h") String timeRange) {
        try {
            SecurityMetricsDto metrics = dashboardService.getSecurityMetrics(timeRange);
            return ResponseUtils.ok("보안 메트릭 조회 성공", metrics);
        } catch (Exception e) {
            log.error("보안 메트릭 조회 실패", e);
            return ResponseUtils.internalServerError("메트릭 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 상위 위협 IP 목록 조회
     */
    @GetMapping("/threats/top-ips")
    public ResponseEntity<ApiResponse<List<ThreatIpDto>>> getTopThreatIps(
            @RequestParam(defaultValue = "24h") String timeRange) {
        try {
            List<ThreatIpDto> topThreats = dashboardService.getTopThreatIps(timeRange);
            return ResponseUtils.ok("위협 IP 목록 조회 성공", topThreats);
        } catch (Exception e) {
            log.error("위협 IP 조회 실패", e);
            return ResponseUtils.internalServerError("위협 IP 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 실시간 보안 이벤트 추이 조회
     */
    @GetMapping("/events/timeline")
    public ResponseEntity<ApiResponse<List<TimelineDataDto>>> getSecurityTimeline(
            @RequestParam(defaultValue = "1h") String timeRange) {
        try {
            List<TimelineDataDto> timeline = dashboardService.getSecurityTimeline(timeRange);
            return ResponseUtils.ok("타임라인 데이터 조회 성공", timeline);
        } catch (Exception e) {
            log.error("타임라인 데이터 조회 실패", e);
            return ResponseUtils.internalServerError("타임라인 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 시간대별 공격 패턴 분석
     */
    @GetMapping("/patterns/hourly")
    public ResponseEntity<ApiResponse<List<HourlyPatternDto>>> getHourlyPattern() {
        try {
            List<HourlyPatternDto> patterns = dashboardService.getHourlyPattern();
            return ResponseUtils.ok("시간대별 패턴 조회 성공", patterns);
        } catch (Exception e) {
            log.error("시간대별 패턴 조회 실패", e);
            return ResponseUtils.internalServerError("패턴 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 응답시간 모니터링 데이터 조회
     */
    @GetMapping("/performance/response-times")
    public ResponseEntity<ApiResponse<List<ResponseTimeDto>>> getResponseTimes(
            @RequestParam(defaultValue = "1h") String timeRange) {
        try {
            List<ResponseTimeDto> responseTimes = dashboardService.getResponseTimes(timeRange);
            return ResponseUtils.ok("응답시간 데이터 조회 성공", responseTimes);
        } catch (Exception e) {
            log.error("응답시간 데이터 조회 실패", e);
            return ResponseUtils.internalServerError("응답시간 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 알림 타입별 통계 조회
     */
    @GetMapping("/statistics/alert-types")
    public ResponseEntity<ApiResponse<List<AlertTypeStatDto>>> getAlertTypeStatistics(
            @RequestParam(defaultValue = "24h") String timeRange) {
        try {
            List<AlertTypeStatDto> statistics = dashboardService.getAlertTypeStatistics(timeRange);
            return ResponseUtils.ok("알림 타입별 통계 조회 성공", statistics);
        } catch (Exception e) {
            log.error("알림 타입별 통계 조회 실패", e);
            return ResponseUtils.internalServerError("통계 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 알림 이력 페이지네이션 조회
     */
    @GetMapping("/alerts/history")
    public ResponseEntity<ApiResponse<Page<AlertHistoryDto>>> getAlertHistory(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        try {
            Page<AlertHistoryDto> alertHistory = dashboardService.getAlertHistory(page, size);
            return ResponseUtils.ok("알림 이력 조회 성공", alertHistory);
        } catch (Exception e) {
            log.error("알림 이력 조회 실패", e);
            return ResponseUtils.internalServerError("알림 이력 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 미확인 알림 목록 조회
     */
    @GetMapping("/alerts/unacknowledged")
    public ResponseEntity<ApiResponse<List<AlertHistoryDto>>> getUnacknowledgedAlerts() {
        try {
            List<AlertHistoryDto> unacknowledgedAlerts = dashboardService.getUnacknowledgedAlerts();
            return ResponseUtils.ok("미확인 알림 조회 성공", unacknowledgedAlerts);
        } catch (Exception e) {
            log.error("미확인 알림 조회 실패", e);
            return ResponseUtils.internalServerError("미확인 알림 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 억제된 알림 목록 조회
     */
    @GetMapping("/alerts/suppressed")
    public ResponseEntity<ApiResponse<List<AlertHistoryDto>>> getSuppressedAlerts() {
        try {
            List<AlertHistoryDto> suppressedAlerts = dashboardService.getSuppressedAlerts();
            return ResponseUtils.ok("억제된 알림 조회 성공", suppressedAlerts);
        } catch (Exception e) {
            log.error("억제된 알림 조회 실패", e);
            return ResponseUtils.internalServerError("억제된 알림 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 특정 관리자가 확인한 알림 조회
     */
    @GetMapping("/alerts/by-admin/{adminEmail}")
    public ResponseEntity<ApiResponse<List<AlertHistoryDto>>> getAlertsByAdmin(
            @PathVariable String adminEmail) {
        try {
            List<AlertHistoryDto> adminAlerts = dashboardService.getAlertsByAdmin(adminEmail);
            return ResponseUtils.ok("관리자별 알림 조회 성공", adminAlerts);
        } catch (Exception e) {
            log.error("관리자별 알림 조회 실패", e);
            return ResponseUtils.internalServerError("관리자별 알림 조회 중 오류가 발생했습니다");
        }
    }

    /**
     * 오래된 확인된 알림 정리
     */
    @DeleteMapping("/alerts/cleanup")
    public ResponseEntity<ApiResponse<Integer>> cleanupOldAlerts(
            @RequestParam(defaultValue = "30") int daysBefore) {
        try {
            int deletedCount = dashboardService.cleanupOldAlerts(daysBefore);
            return ResponseUtils.ok(deletedCount + "개의 오래된 알림을 정리했습니다", deletedCount);
        } catch (Exception e) {
            log.error("알림 정리 실패", e);
            return ResponseUtils.internalServerError("알림 정리 중 오류가 발생했습니다");
        }
    }
}