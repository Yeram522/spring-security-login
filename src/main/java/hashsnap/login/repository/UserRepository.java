package hashsnap.login.repository;

import hashsnap.login.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    /**
     * 전체 회원 중 이메일로 사용자 조회
     * (계정 상태와 활성화 여부 무관)
     */
    Optional<User> findByEmail(String email);

    /**
     * 활성 상태이고 활성화된 사용자 중 이메일로 조회
     * (정지 또는 비활성 사용자 제외)
     */
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.status = 'ACTIVE' AND u.enabled = true")
    Optional<User> findActiveUserByEmail(@Param("email") String email);

    /**
     * 이메일 중복 여부 확인
     */
    boolean existsByEmail(String email);
}
