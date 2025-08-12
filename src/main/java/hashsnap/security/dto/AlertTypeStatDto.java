package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 알림 타입별 통계 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertTypeStatDto {
    private String alertType;
    private Long alertHistoryCount;
    private Long totalAlertCount;
}