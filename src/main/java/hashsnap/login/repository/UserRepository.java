package hashsnap.login.repository;

import hashsnap.login.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.email = :email AND u.status = 'ACTIVE' AND u.enabled = true")
    Optional<User> findActiveUserByEmail(@Param("email") String email);

    boolean existsByEmail(String email);
}
