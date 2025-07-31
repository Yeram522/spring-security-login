package hashsnap.login.exception;

import hashsnap.global.exception.BusinessException;
import org.springframework.http.HttpStatus;

/**
 * 사용자 관련 예외 클래스
 * 회원가입, 사용자 조회, 인증 등 사용자 도메인에서 발생하는 비즈니스 예외들
 * 중첩 클래스로 예외 타입별 세분화하여 명확한 오류 처리 제공
 *
 * - DuplicateUserException: 이메일 중복 등 사용자 정보 중복 시
 * - UserNotFoundException: 존재하지 않는 사용자 조회 시
 * - InvalidCredentialsException: 잘못된 로그인 정보 입력 시
 */
public class UserException {

    public static class DuplicateUserException extends BusinessException {
        public DuplicateUserException(String message) {
            super(message, "DUPLICATE_USER", HttpStatus.CONFLICT);
        }
    }

    public static class UserNotFoundException extends BusinessException {
        public UserNotFoundException(String message) {
            super(message, "USER_NOT_FOUND", HttpStatus.NOT_FOUND);
        }
    }

    public static class InvalidCredentialsException extends BusinessException {
        public InvalidCredentialsException(String message) {
            super(message, "INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED);
        }
    }
}
