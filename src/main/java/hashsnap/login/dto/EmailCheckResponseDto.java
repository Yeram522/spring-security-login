package hashsnap.login.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 이메일 중복 체크 응답 DTO
 * 이메일이 이미 존재하면 true, 존재하지 않으면 false 값을 갖는다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailCheckResponseDto {
    private boolean exists;
}