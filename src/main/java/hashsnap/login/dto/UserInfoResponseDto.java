package hashsnap.login.dto;

import hashsnap.login.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 유저 정보 응답 DTO
 * 로그인된 사용자의 프로필 정보 조회 시 사용
 * 민감한 정보(비밀번호) 제외하고 반환
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponseDto {
    private String email;
    private String nickname;
    private String username;
    private String role;
    private String phone;

    // Entity에서 DTO로 변환하는 정적 메소드
    public static UserInfoResponseDto from(User user) {
        return UserInfoResponseDto.builder()
                .email(user.getEmail())
                .nickname(user.getNickname())
                .username(user.getUsername())
                .role(user.getRole().getAuthority())
                .phone(user.getPhone())
                .build();
    }
}