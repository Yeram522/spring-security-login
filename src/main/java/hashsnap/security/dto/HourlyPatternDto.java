package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 시간대별 패턴 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HourlyPatternDto {
    private Integer hour;
    private Long attackCount;
}