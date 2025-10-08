package org.example.demobuildingjwtwithdatabase.repository;

import org.example.demobuildingjwtwithdatabase.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IRoleRepository extends JpaRepository<Role, Long> {
}
