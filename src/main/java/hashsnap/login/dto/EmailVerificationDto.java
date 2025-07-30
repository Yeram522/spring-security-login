package hashsnap.login.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationDto { // 이메일 인증 DTO
    @NotBlank
    private String action; // "send" or "verify"

    @NotBlank
    private String purpose; // "signup" or "findPwd"

    @Email
    @NotBlank
    private String email;

    private String verificationCode; // verify 시에만 필요
}