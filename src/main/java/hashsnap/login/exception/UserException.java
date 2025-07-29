package hashsnap.login.exception;

import hashsnap.global.exception.BusinessException;

public class UserException extends BusinessException {
    public UserException(String message) {
        super("USER_ERROR", message, 400);
    }

    public static class DuplicateUserException extends UserException {
        public DuplicateUserException(String message) {
            super(message);
        }
    }

    public static class UserNotFoundException extends UserException {
        public UserNotFoundException() {
            super("사용자를 찾을 수 없습니다");
        }
    }
}
