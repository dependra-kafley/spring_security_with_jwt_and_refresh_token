package com.depu.jwt.repositories;

import com.depu.jwt.domain.AppUsers;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUsers,Long> {
    AppUsers findByUserName(String userName);
}
