package com.valeerp.inventory.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {"com.valeerp.inventory.auth", "com.valeerp.kernel", "com.valeerp.hr"})
@EntityScan(basePackages = {"com.valeerp.inventory.auth", "com.valeerp.kernel", "com.valeerp.hr"})
@EnableJpaRepositories(basePackages = {"com.valeerp.inventory.auth", "com.valeerp.kernel", "com.valeerp.hr"})
public class ValeErpAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ValeErpAuthApplication.class, args);
    }

}
