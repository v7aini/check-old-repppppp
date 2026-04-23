package com.cybersec;

import org.springframework.boot.SpringApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableAsync
public class CybersecPlatformApplication {
    public static void main(String[] args) {
        SpringApplication.run(CybersecPlatformApplication.class, args);
        System.out.println("\n============================================");
        System.out.println("  CyberSec Platform STARTED on port 9090");
        System.out.println("  Dashboard : http://localhost:9090/dashboard");
        System.out.println("  IDS       : http://localhost:9090/ids");
        System.out.println("  WAF       : http://localhost:9090/waf");
        System.out.println("  TIP       : http://localhost:9090/tip");
        System.out.println("  API Docs  : http://localhost:9090/swagger-ui.html");
        System.out.println("  H2 DB     : http://localhost:9090/h2-console");
        System.out.println("  Login     : admin / admin123");
        System.out.println("============================================\n");
    }
}
