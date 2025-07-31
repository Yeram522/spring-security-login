package hashsnap.login.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Token 발급 요청 DTO
 */
@Data
@Builder
public class TokenRefreshResponseDto {
    private String accessToken;
}
