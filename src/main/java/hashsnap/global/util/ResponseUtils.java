package hashsnap.global.util;

import hashsnap.global.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * JWT 인증 필터
 * HTTP 요청의 Authorization 헤더에서 JWT를 추출하고 검증
 * 인증된 사용자 정보로 SecurityContext에 Authentication 등록
 *
 * 유효한 JWT가 있는 경우에만 인증 처리를 수행하며,
 * 이후 필터 체인에서 인증된 사용자로 요청을 이어감
 */

public class ResponseUtils {
    // 성공 응답들
    public static <T> ResponseEntity<ApiResponse<T>> ok(String message) {
        return ResponseEntity.ok(ApiResponse.success(message));
    }

    public static <T> ResponseEntity<ApiResponse<T>> ok(String message, T data) {
        return ResponseEntity.ok(ApiResponse.success(message, data));
    }

    // 에러 응답들
    public static <T> ResponseEntity<ApiResponse<T>> badRequest(String message) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(message));
    }

    public static <T> ResponseEntity<ApiResponse<T>> badRequest(String message, T data) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.<T>builder()
                        .success(false)
                        .message(message)
                        .data(data)
                        .build());
    }

    public static <T> ResponseEntity<ApiResponse<T>> notFound(String message) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(message));
    }

    public static <T> ResponseEntity<ApiResponse<T>> notFound(String message, T data) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.<T>builder()
                        .success(false)
                        .message(message)
                        .data(data)
                        .build());
    }

    public static <T> ResponseEntity<ApiResponse<T>> conflict(String message) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(message));
    }

    public static <T> ResponseEntity<ApiResponse<T>> internalServerError(String message) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(message));
    }

    public static <T> ResponseEntity<ApiResponse<T>> internalServerError(String message, T data) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.<T>builder()
                        .success(false)
                        .message(message)
                        .data(data)
                        .build());
    }

    // 커스텀 상태 코드
    public static <T> ResponseEntity<ApiResponse<T>> status(HttpStatus status, String message) {
        return ResponseEntity.status(status)
                .body(ApiResponse.error(message));
    }

    public static <T> ResponseEntity<ApiResponse<T>> status(HttpStatus status, String message, T data) {
        ApiResponse<T> response = status.is2xxSuccessful()
                ? ApiResponse.success(message, data)
                : ApiResponse.error(message);
        return ResponseEntity.status(status).body(response);
    }
}
