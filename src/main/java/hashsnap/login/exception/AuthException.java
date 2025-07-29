package hashsnap.login.exception;

import hashsnap.global.exception.BusinessException;

public class AuthException extends BusinessException {

    public AuthException(String message) {
        super("AUTH_ERROR", message, 401);
    }

    public static class InvalidCredentialsException extends AuthException {
        public InvalidCredentialsException() {
            super("아이디 또는 비밀번호가 잘못되었습니다");
        }
    }

    public static class TokenExpiredException extends AuthException {
        public TokenExpiredException() {
            super("토큰이 만료되었습니다");
        }
    }
}
