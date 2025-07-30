package hashsnap.login.service;

import hashsnap.login.entity.User;
import hashsnap.login.exception.UserException.UserNotFoundException;
import hashsnap.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final UserRepository userRepository;

    public boolean validateRefreshToken(String email, String refreshToken) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(UserNotFoundException::new);

        return Objects.equals(user.getRefreshToken(), refreshToken);
    }

    @Transactional
    public void deleteRefreshToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(UserNotFoundException::new);

        user.setRefreshToken(null); // refreshToken Update
    }

    @Transactional
    public void saveRefreshToken(String email, String refreshToken) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(UserNotFoundException::new);

        user.setRefreshToken(refreshToken); // refreshToken Update
    }
}
