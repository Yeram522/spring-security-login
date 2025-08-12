package hashsnap.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * 위협 IP DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatIpDto {
    private String ipAddress;
    private Long attackCount;
    private String countryCode;
    private List<String> attackTypes;
    private String riskLevel;
    private Instant lastSeenAt;
}