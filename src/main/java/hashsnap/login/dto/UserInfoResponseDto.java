package hashsnap.login.dto;

import hashsnap.login.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponseDto {
    private String email;
    private String nickname;
    private String username;
    private String phone;

    // Entity에서 DTO로 변환하는 정적 메소드
    public static UserInfoResponseDto from(User user) {
        return UserInfoResponseDto.builder()
                .email(user.getEmail())
                .nickname(user.getNickname())
                .username(user.getUsername())
                .phone(user.getPhone())
                .build();
    }
}