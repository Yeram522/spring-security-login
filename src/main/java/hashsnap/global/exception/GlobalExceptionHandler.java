package hashsnap.global.exception;

import hashsnap.global.response.ApiResponse;
import hashsnap.global.util.ResponseUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * 전역 예외 처리 핸들러
 * 모든 컨트롤러에서 발생하는 예외를 통합 처리
 * BusinessException, Validation, 시스템 예외 등 타입별 처리
 * 일관된 에러 응답 형식과 적절한 HTTP 상태 코드 제공
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 비즈니스 예외 통합 처리
     * 모든 커스텀 비즈니스 예외를 여기서 처리
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleBusinessException(BusinessException e) {
        log.warn("Business exception occurred: {} - {}", e.getClass().getSimpleName(), e.getMessage());

        Map<String, String> errorData = Map.of("errorCode", e.getErrorCode());

        return ResponseEntity.status(e.getHttpStatus())
                .body(ApiResponse.<Map<String, String>>builder()
                        .success(false)
                        .message(e.getMessage())
                        .data(errorData)
                        .build());
    }

    /**
     * Validation 예외 처리
     * @Valid 어노테이션으로 인한 검증 실패 시 처리
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, Object>>> handleValidationException(MethodArgumentNotValidException e) {
        log.warn("Validation failed: {}", e.getMessage());

        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : e.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }

        Map<String, Object> errorData = Map.of(
                "errorCode", "VALIDATION_FAILED",
                "fieldErrors", fieldErrors
        );

        return ResponseUtils.badRequest("입력값이 올바르지 않습니다", errorData);
    }

    /**
     * IllegalArgumentException 처리
     * 잘못된 파라미터 전달 시 처리
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleIllegalArgumentException(IllegalArgumentException e) {
        log.warn("Illegal argument: {}", e.getMessage());

        Map<String, String> errorData = Map.of("errorCode", "INVALID_ARGUMENT");

        return ResponseUtils.badRequest(e.getMessage(), errorData);
    }

    /**
     * NullPointerException 처리
     * 개발 단계에서 발생할 수 있는 NPE 처리
     */
    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleNullPointerException(NullPointerException e) {
        log.error("Null pointer exception occurred", e);

        Map<String, String> errorData = Map.of("errorCode", "NULL_POINTER");

        return ResponseUtils.internalServerError("서버 내부 오류가 발생했습니다", errorData);
    }

    /**
     * 예상하지 못한 모든 예외 처리
     * 최종 안전망 역할
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleGenericException(Exception e) {
        log.error("Unexpected error occurred: {}", e.getClass().getSimpleName(), e);

        Map<String, String> errorData = Map.of(
                "errorCode", "INTERNAL_SERVER_ERROR",
                "exceptionType", e.getClass().getSimpleName()
        );

        return ResponseUtils.internalServerError("서버 내부 오류가 발생했습니다", errorData);
    }
}
