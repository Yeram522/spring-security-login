package hashsnap.global.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse { // 공통 응답 DTO (AJAX 응답용)
    private boolean success;
    private String message;
    private Object data;
}