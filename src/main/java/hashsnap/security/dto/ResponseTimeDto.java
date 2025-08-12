package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 응답시간 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResponseTimeDto {
    private String timestamp;
    private Double averageResponseTime;
    private Long requestCount;
}