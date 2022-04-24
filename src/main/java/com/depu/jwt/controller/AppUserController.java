package com.depu.jwt.controller;

import com.depu.jwt.domain.AppUsers;
import com.depu.jwt.domain.Roles;
import com.depu.jwt.dto.AddRoleToUserDto;
import com.depu.jwt.services.AppUsersService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


import java.util.List;

@RestController
@AllArgsConstructor
@Slf4j
public class AppUserController {

    private final AppUsersService appUsersService;

    @GetMapping("/appUsers")
    public ResponseEntity<List<AppUsers>> getAllAppUsers(){
        log.info("Inside the api");
        return ResponseEntity.ok().body(appUsersService.getAllAppUsers());
    }

    @PostMapping("/save/appUsers")
    public ResponseEntity<AppUsers> saveAppUsers(@RequestBody AppUsers appUsers){

        appUsersService.saveAppUser(appUsers);
        return ResponseEntity.ok().body(appUsers);
    }

    @PostMapping("/save/roles")
    public ResponseEntity<Roles> saveRoles(@RequestBody Roles roles){

        appUsersService.saveRoles(roles);
        return ResponseEntity.ok().body(roles);
    }

    @PostMapping("/addRolesToUsers")
    public ResponseEntity<?> addRolesToUsers(@RequestBody AddRoleToUserDto dto){
        appUsersService.addRolesToAppUsers(dto.getUserName(),dto.getRoleName());
        return ResponseEntity.ok().build();
    }


}
