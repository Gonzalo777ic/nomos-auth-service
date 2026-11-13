package com.valeerp.inventory.auth.acl;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(AclProperties.class)
public class AclConfiguration {
}
