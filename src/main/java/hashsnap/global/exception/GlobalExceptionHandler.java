package hashsnap.global.exception;

import hashsnap.global.response.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// Global Exception Handler에서 처리
@RestControllerAdvice
public class GlobalExceptionHandler {

    // 비즈니스 예외 통합 처리
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse> handleBusinessException(BusinessException e) {
        ApiResponse response = ApiResponse.builder()
                .success(false)
                .message(e.getMessage())
                .data(Map.of("errorCode", e.getErrorCode()))
                .build();

        return ResponseEntity.status(e.getHttpStatus()).body(response);
    }

    // Validation 예외
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidationException(MethodArgumentNotValidException e) {
        List<String> errors = e.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.toList());

        ApiResponse response = ApiResponse.builder()
                .success(false)
                .message("입력값이 올바르지 않습니다")
                .data(Map.of("errors", errors))
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    // 예상하지 못한 예외
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleGenericException(Exception e) {
        // 로그 기록
        //log.error("Unexpected error occurred", e);

        ApiResponse response = ApiResponse.builder()
                .success(false)
                .message("서버 내부 오류가 발생했습니다")
                .build();

        return ResponseEntity.internalServerError().body(response);
    }
}
