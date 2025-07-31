package hashsnap.global.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * 비즈니스 예외 추상 클래스
 * 모든 커스텀 비즈니스 예외의 부모 클래스
 * errorCode와 httpStatus를 포함한 표준화된 예외 구조 제공
 */
@Getter
public abstract class BusinessException extends RuntimeException {
    private final String errorCode;
    private final HttpStatus httpStatus;

    protected BusinessException(String message, String errorCode, HttpStatus httpStatus) {
        super(message);
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
    }
}
