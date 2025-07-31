package hashsnap.login.exception;

import hashsnap.global.exception.BusinessException;
import org.springframework.http.HttpStatus;

/**
 * 이메일 인증 관련 예외 클래스
 * 인증번호 발송, 검증 과정에서 발생하는 비즈니스 예외 처리
 *
 * 주요 발생 상황:
 * - 인증번호 만료 시
 * - 잘못된 인증번호 입력 시
 * - 이메일 발송 실패 시
 * - 인증 상태 불일치 시
 */
public class EmailVerificationException extends BusinessException {

    public EmailVerificationException(String message) {
        super(message, "EMAIL_VERIFICATION_FAILED", HttpStatus.BAD_REQUEST);
    }
}
