package com.depu.jwt;

import com.depu.jwt.domain.AppUsers;
import com.depu.jwt.domain.Roles;
import com.depu.jwt.services.AppUsersService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	@Bean
	CommandLineRunner run (AppUsersService appUsersService){
		return args -> {
			appUsersService.saveRoles(new Roles(null,"ROLE_ADMIN"));
			appUsersService.saveRoles(new Roles(null,"ROLE_USER"));
			appUsersService.saveRoles(new Roles(null,"ROLE_MANAGER"));
			appUsersService.saveRoles(new Roles(null,"ROLE_SUPERADMIN"));

			appUsersService.saveAppUser(new AppUsers(null, "John Doe","john","1234",new ArrayList<>()));
			appUsersService.saveAppUser(new AppUsers(null, "Uncle Scrooge","uncle","1234",new ArrayList<>()));
			appUsersService.saveAppUser(new AppUsers(null, "William Blanc","william","1234",new ArrayList<>()));
			appUsersService.saveAppUser(new AppUsers(null, "Austin Doe","austin","1234",new ArrayList<>()));

			appUsersService.addRolesToAppUsers("john","ROLE_ADMIN");
			appUsersService.addRolesToAppUsers("uncle","ROLE_USER");
			appUsersService.addRolesToAppUsers("john","ROLE_MANAGER");
			appUsersService.addRolesToAppUsers("john","ROLE_USER");
			appUsersService.addRolesToAppUsers("william","ROLE_MANAGER");
			appUsersService.addRolesToAppUsers("austin","ROLE_SUPERADMIN");
		};
	}
}
