package hashsnap.login.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserStatusResponseDto {
    private String email;
    private boolean isActive;
}