package com.valeerp.kernel.company;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(CompanyProperties.class)
public class CompanyConfiguration {
}
