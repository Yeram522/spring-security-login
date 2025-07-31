package hashsnap.login.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 회원가입 요청 DTO
 * 사용자 등록 시 필요한 정보 전달
 * Bean Validation 어노테이션을 통한 입력값 검증 포함
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequestDto {
    @NotBlank(message = "사용자명은 필수입니다")
    private String username;

    @NotBlank(message = "닉네임은 필수입니다")
    private String nickname;

    @Email(message = "올바른 이메일 형식이 아닙니다")
    @NotBlank(message = "이메일은 필수입니다")
    private String email;

    @Pattern(regexp = "^010-\\d{4}-\\d{4}$", message = "전화번호 형식이 올바르지 않습니다")
    private String phone;

    @NotBlank(message = "비밀번호는 필수입니다")
    @Size(min = 8, message = "비밀번호는 최소 8자 이상이어야 합니다")
    private String password;
}