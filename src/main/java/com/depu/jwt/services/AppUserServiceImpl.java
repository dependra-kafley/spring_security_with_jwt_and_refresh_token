package com.depu.jwt.services;


import com.depu.jwt.domain.AppUsers;
import com.depu.jwt.domain.Roles;
import com.depu.jwt.repositories.AppUserRepository;
import com.depu.jwt.repositories.RoleRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@AllArgsConstructor
@Transactional
@Slf4j

public class AppUserServiceImpl implements AppUsersService, UserDetailsService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    @Override
    public AppUsers saveAppUser(AppUsers appUsers) {
        log.info("Added a user{}",appUsers.getUserName());
        appUsers.setPassword(passwordEncoder.encode(appUsers.getPassword()));
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

    //This methods loads the usr form the data base and return a spring core user
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUsers appUsers = appUserRepository.findByUserName(username);
        if(username== null){
            throw new UsernameNotFoundException("The user is not avaiable");
        }
        else{

            log.info("The user with {} exits ",username);
        }

        // creating authorities

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        //taking the roles form the users and then adding them one by one  the roles in the authoritiees
        appUsers.getRoles().forEach(roles -> {

            authorities.add(new SimpleGrantedAuthority(roles.getName()));
        });

        return new User(appUsers.getUserName(),appUsers.getPassword(),authorities);
    }
}
