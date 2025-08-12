package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 알림 확인 요청 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertAcknowledgeRequest {
    private String alertKey;
}