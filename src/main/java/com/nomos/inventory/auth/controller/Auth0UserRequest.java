package com.nomos.inventory.auth.controller;

import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.util.Set; 

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Auth0UserRequest {

    private String auth0Id;
    private String email;

    private Set<String> roles;
}