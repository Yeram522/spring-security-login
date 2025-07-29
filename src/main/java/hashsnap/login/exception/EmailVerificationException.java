package hashsnap.login.exception;

import hashsnap.global.exception.BusinessException;

public class EmailVerificationException extends BusinessException {

    public EmailVerificationException(String message) {
        super("EMAIL_VERIFICATION_ERROR", message, 400);
    }

    public EmailVerificationException(String message, Throwable cause) {
        super("EMAIL_VERIFICATION_ERROR", message, 400, cause);
    }

    // 구체적인 에러 타입들
    public static class CodeExpiredException extends EmailVerificationException {
        public CodeExpiredException() {
            super("인증번호가 만료되었습니다");
        }
    }

    public static class CodeMismatchException extends EmailVerificationException {
        public CodeMismatchException() {
            super("인증번호가 일치하지 않습니다");
        }
    }

    public static class SendFailedException extends EmailVerificationException {
        public SendFailedException(Throwable cause) {
            super("인증번호 발송에 실패했습니다", cause);
        }
    }
}
