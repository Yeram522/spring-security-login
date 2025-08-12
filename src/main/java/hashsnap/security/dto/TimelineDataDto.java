package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 타임라인 데이터 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TimelineDataDto {
    private String timestamp;
    private Long bruteforceCount;
    private Long ddosCount;
    private Long scanningCount;
}