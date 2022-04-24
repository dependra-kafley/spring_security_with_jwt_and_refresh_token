package com.depu.jwt.services;


import com.depu.jwt.domain.AppUsers;
import com.depu.jwt.domain.Roles;

import java.util.List;

public interface AppUsersService {
    AppUsers saveAppUser(AppUsers appUsers);
    Roles saveRoles(Roles roles);
    void addRolesToAppUsers(String userName, String roleName);
    AppUsers getAppUser(String username);
    List<AppUsers> getAllAppUsers();
}
