package hashsnap.login.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 이메일 인증 요청 DTO
 *
 * 이메일 인증 절차에서 사용되는 요청 데이터 객체입니다.
 * 인증 코드 전송(send) 또는 인증 코드 검증(verify) 요청에 사용됩니다.
 *
 * - action: "send" 또는 "verify" 중 하나
 * - purpose: 인증 목적 ("signup" 또는 "findPwd")
 * - email: 대상 이메일 주소
 * - verificationCode: 인증 코드 (verify 요청 시 필수)
 */
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