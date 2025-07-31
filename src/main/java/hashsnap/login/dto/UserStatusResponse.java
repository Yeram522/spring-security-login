package hashsnap.login.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserStatusResponse {
    private String email;
    private boolean isActive;
}