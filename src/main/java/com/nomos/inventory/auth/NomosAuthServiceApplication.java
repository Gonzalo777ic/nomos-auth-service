package com.nomos.inventory.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"com.nomos.inventory.auth", "com.valeerp.kernel"})
public class NomosAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(NomosAuthServiceApplication.class, args);
    }

}
