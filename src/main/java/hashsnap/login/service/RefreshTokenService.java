package hashsnap.login.service;

import hashsnap.login.entity.User;
import hashsnap.login.exception.AuthException.InvalidTokenException;
import hashsnap.login.exception.UserException.UserNotFoundException;
import hashsnap.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    private final UserRepository userRepository;

    /**
     * Refresh Token 검증
     * @param email 사용자 이메일
     * @param refreshToken 검증할 refresh token
     * @return 유효성 여부
     * @throws UserNotFoundException 사용자를 찾을 수 없는 경우
     * @throws InvalidTokenException refresh token이 null이거나 비어있는 경우
     */
    public boolean validateRefreshToken(String email, String refreshToken) {
        log.debug("Refresh token 검증 시작: email={}", email);

        // 입력값 검증
        if (email == null || email.trim().isEmpty()) {
            log.warn("이메일이 null 또는 비어있음");
            throw new IllegalArgumentException("이메일은 필수입니다");
        }

        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            log.warn("Refresh token이 null 또는 비어있음: email={}", email);
            throw new InvalidTokenException("Refresh Token이 없습니다");
        }

        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("사용자를 찾을 수 없음: email={}", email);
                        return new UserNotFoundException("사용자를 찾을 수 없습니다: " + email);
                    });

            boolean isValid = Objects.equals(user.getRefreshToken(), refreshToken);

            if (isValid) {
                log.debug("Refresh token 검증 성공: email={}", email);
            } else {
                log.warn("Refresh token 불일치: email={}", email);
            }

            return isValid;

        } catch (Exception e) {
            log.error("Refresh token 검증 중 오류 발생: email={}", email, e);
            throw e; // 이미 BusinessException이면 그대로 전파, 아니면 그대로 던짐
        }
    }

    /**
     * Refresh Token 삭제 (로그아웃 시 사용)
     * @param email 사용자 이메일
     * @throws UserNotFoundException 사용자를 찾을 수 없는 경우
     */
    @Transactional
    public void deleteRefreshToken(String email) {
        log.debug("Refresh token 삭제 시작: email={}", email);

        // 입력값 검증
        if (email == null || email.trim().isEmpty()) {
            log.warn("이메일이 null 또는 비어있음");
            throw new IllegalArgumentException("이메일은 필수입니다");
        }

        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("사용자를 찾을 수 없음: email={}", email);
                        return new UserNotFoundException("사용자를 찾을 수 없습니다: " + email);
                    });

            String previousToken = user.getRefreshToken();
            user.setRefreshToken(null);

            log.info("Refresh token 삭제 완료: email={}, hadToken={}", email, previousToken != null);

        } catch (Exception e) {
            log.error("Refresh token 삭제 중 오류 발생: email={}", email, e);
            throw e;
        }
    }

    /**
     * Refresh Token 저장 (로그인 시 사용)
     * @param email 사용자 이메일
     * @param refreshToken 저장할 refresh token
     * @throws UserNotFoundException 사용자를 찾을 수 없는 경우
     * @throws InvalidTokenException refresh token이 null이거나 비어있는 경우
     */
    @Transactional
    public void saveRefreshToken(String email, String refreshToken) {
        log.debug("Refresh token 저장 시작: email={}", email);

        // 입력값 검증
        if (email == null || email.trim().isEmpty()) {
            log.warn("이메일이 null 또는 비어있음");
            throw new IllegalArgumentException("이메일은 필수입니다");
        }

        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            log.warn("Refresh token이 null 또는 비어있음: email={}", email);
            throw new InvalidTokenException("저장할 Refresh Token이 없습니다");
        }

        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("사용자를 찾을 수 없음: email={}", email);
                        return new UserNotFoundException("사용자를 찾을 수 없습니다: " + email);
                    });

            user.setRefreshToken(refreshToken);

            log.info("Refresh token 저장 완료: email={}", email);

        } catch (Exception e) {
            log.error("Refresh token 저장 중 오류 발생: email={}", email, e);
            throw e;
        }
    }

    /**
     * 사용자의 Refresh Token 존재 여부 확인
     * @param email 사용자 이메일
     * @return refresh token 존재 여부
     * @throws UserNotFoundException 사용자를 찾을 수 없는 경우
     */
    public boolean hasRefreshToken(String email) {
        log.debug("Refresh token 존재 여부 확인: email={}", email);

        if (email == null || email.trim().isEmpty()) {
            log.warn("이메일이 null 또는 비어있음");
            throw new IllegalArgumentException("이메일은 필수입니다");
        }

        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("사용자를 찾을 수 없음: email={}", email);
                        return new UserNotFoundException("사용자를 찾을 수 없습니다: " + email);
                    });

            boolean hasToken = user.getRefreshToken() != null && !user.getRefreshToken().trim().isEmpty();

            log.debug("Refresh token 존재 여부: email={}, hasToken={}", email, hasToken);

            return hasToken;

        } catch (Exception e) {
            log.error("Refresh token 존재 여부 확인 중 오류 발생: email={}", email, e);
            throw e;
        }
    }
}
