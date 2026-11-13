package com.valeerp.inventory.auth.impersonation;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(ImpersonationProperties.class)
public class ImpersonationConfiguration {
}
