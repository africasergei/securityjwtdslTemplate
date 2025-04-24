package SecurityJwtDsl.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import SecurityJwtDsl.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByEmail(String email);

}
