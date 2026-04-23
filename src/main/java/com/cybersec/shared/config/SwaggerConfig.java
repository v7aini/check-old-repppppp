package com.cybersec.shared.config;

import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.info.*;
import io.swagger.v3.oas.models.security.*;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Swagger / OpenAPI 3 configuration.
 *
 * HOW TO USE SWAGGER:
 *  1. Open: http://localhost:9090/swagger-ui.html
 *  2. Find "Authentication" section → POST /api/auth/login
 *  3. Click "Try it out" → paste: {"username":"admin","password":"admin123"} → Execute
 *  4. Copy the "token" value from the response
 *  5. Click the green "Authorize" button at the top of Swagger
 *  6. In the "BearerAuth" field type:  Bearer <paste_token_here>
 *  7. Click Authorize → Close → all API endpoints now work
 */
@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("CyberSec Platform — REST API")
                .description(
                    "**How to authenticate:**\n\n" +
                    "1. Use `POST /api/auth/login` with `{\"username\":\"admin\",\"password\":\"admin123\"}`\n" +
                    "2. Copy the `token` from the response\n" +
                    "3. Click the **Authorize** button (top right) → paste: `Bearer <token>`\n" +
                    "4. All protected endpoints will now work\n\n" +
                    "**Modules:** IDS · WAF · TIP · Network Capture · Investigation Tool · Telegram Bot"
                )
                .version("1.0.0")
                .contact(new Contact().name("CyberSec Platform").email("admin@cybersec.local"))
            )
            .addServersItem(new Server().url("http://localhost:9090").description("Local server"))
            .addSecurityItem(new SecurityRequirement().addList("BearerAuth"))
            .components(new Components()
                .addSecuritySchemes("BearerAuth", new SecurityScheme()
                    .name("BearerAuth")
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("Paste your JWT token here (without the word 'Bearer'). Get it from POST /api/auth/login")
                )
            );
    }
}
