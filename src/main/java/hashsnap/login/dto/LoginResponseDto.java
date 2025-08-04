package hashsnap.login.dto;

import lombok.Builder;
import lombok.Data;

/**
 * 로그인 API 응답 DTO
 */
@Data
@Builder
public class LoginResponseDto {
    private String accessToken;
    private String refreshToken;
    private String role;
    private String userEmail;
}