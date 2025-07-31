package hashsnap.login.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailSendRequestDto {
    @NotBlank
    private String purpose;

    @Email
    @NotBlank
    private String email;
}
