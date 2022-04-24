package com.depu.jwt.dto;

import lombok.Data;

@Data
public class AddRoleToUserDto {
    private String userName;
    private String roleName;
}
