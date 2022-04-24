package com.depu.jwt.services;


import com.depu.jwt.domain.AppUsers;
import com.depu.jwt.domain.Roles;
import com.depu.jwt.repositories.AppUserRepository;
import com.depu.jwt.repositories.RoleRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;


import javax.transaction.Transactional;
import java.util.List;

@Service
@AllArgsConstructor
@Transactional
@Slf4j

public class AppUserServiceImpl implements AppUsersService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    @Override
    public AppUsers saveAppUser(AppUsers appUsers) {
        log.info("Added a user{}",appUsers.getUserName());
        return appUserRepository.save(appUsers);
    }

    @Override
    public Roles saveRoles(Roles roles) {
        log.info("Added a user{}",roles.getName());
        return roleRepository.save(roles);
    }

    @Override
    public void addRolesToAppUsers(String userName, String roleName) {
        AppUsers appUsers = appUserRepository.findByUserName(userName);
        Roles roles = roleRepository.findByName(roleName);
        log.info("Added a user{} with role {}",userName,roleName);

        appUsers.getRoles().add(roles);
    }

    @Override
    public AppUsers getAppUser(String username) {
        return appUserRepository.findByUserName(username);
    }

    @Override
    public List<AppUsers> getAllAppUsers() {
        return appUserRepository.findAll();
    }
}
