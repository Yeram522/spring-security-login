package hashsnap.login.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 로그인 API 요청 DTO
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequestDto {
    private String email;
    private String password;
}
