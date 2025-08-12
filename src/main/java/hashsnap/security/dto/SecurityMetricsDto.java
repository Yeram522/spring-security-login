package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 보안 메트릭 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityMetricsDto {
    private Long criticalAlerts;
    private Long blockedIps;
    private Long successfulLogins;
    private Long totalRequests;
    private Long warningCount;
}