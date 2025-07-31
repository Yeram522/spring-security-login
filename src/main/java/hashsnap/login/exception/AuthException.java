package hashsnap.login.exception;

import hashsnap.global.exception.BusinessException;
import org.springframework.http.HttpStatus;

/**
 * 인증 관련 예외 클래스
 * JWT 토큰, 로그인 인증 등 인증 프로세스에서 발생하는 예외들
 * 중첩 클래스로 세분화된 예외 타입 제공
 */
public class AuthException {

    public static class InvalidCredentialsException extends BusinessException {
        public InvalidCredentialsException() {
            super("인증 정보가 올바르지 않습니다", "INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED);
        }

        public InvalidCredentialsException(String message) {
            super(message, "INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED);
        }
    }

    public static class InvalidTokenException extends BusinessException {
        public InvalidTokenException() {
            super("유효하지 않은 토큰입니다", "INVALID_TOKEN", HttpStatus.UNAUTHORIZED);
        }

        public InvalidTokenException(String message) {
            super(message, "INVALID_TOKEN", HttpStatus.UNAUTHORIZED);
        }
    }

    public static class TokenExpiredException extends BusinessException {
        public TokenExpiredException() {
            super("토큰이 만료되었습니다", "TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED);
        }

        public TokenExpiredException(String message) {
            super(message, "TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED);
        }
    }

    public static class AccessDeniedException extends BusinessException {
        public AccessDeniedException() {
            super("접근 권한이 없습니다", "ACCESS_DENIED", HttpStatus.FORBIDDEN);
        }

        public AccessDeniedException(String message) {
            super(message, "ACCESS_DENIED", HttpStatus.FORBIDDEN);
        }
    }

    public static class AccountLockedException extends BusinessException {
        public AccountLockedException() {
            super("계정이 잠겨있습니다.", "ACCOUNT_LOCKED", HttpStatus.LOCKED);
        }

        public AccountLockedException(String message) {
            super(message, "ACCOUNT_LOCKED", HttpStatus.LOCKED);
        }
    }
}
