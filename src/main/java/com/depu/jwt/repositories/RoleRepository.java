package com.depu.jwt.repositories;

import com.depu.jwt.domain.Roles;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Roles,Long> {
    Roles findByName(String name);
}
