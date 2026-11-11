package com.nomos.inventory.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {"com.nomos.inventory.auth", "com.valeerp.kernel", "com.valeerp.hr"})
@EntityScan(basePackages = {"com.nomos.inventory.auth", "com.valeerp.kernel", "com.valeerp.hr"})
@EnableJpaRepositories(basePackages = {"com.nomos.inventory.auth", "com.valeerp.kernel", "com.valeerp.hr"})
public class NomosAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(NomosAuthServiceApplication.class, args);
    }

}
