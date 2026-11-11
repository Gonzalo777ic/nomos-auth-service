package com.valeerp.hr;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(HrProperties.class)
public class HrConfiguration {
}
