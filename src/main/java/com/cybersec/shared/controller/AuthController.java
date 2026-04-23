package com.cybersec.shared.controller;

import com.cybersec.shared.auth.AppUserDetailsService;
import com.cybersec.shared.auth.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

/**
 * Auth endpoint — get a JWT token to use in Swagger UI.
 * This endpoint requires NO authentication (it is public).
 */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Step 1: Call this to get a JWT token, then click Authorize in Swagger")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtUtils jwtUtils;

    @Autowired
    public AuthController(AuthenticationManager authManager, JwtUtils jwtUtils) {
        this.authManager = authManager;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/login")
    @Operation(
        summary = "Get JWT token for Swagger",
        description = "POST this with admin credentials to get a JWT token. " +
                      "Copy the 'token' field, click 'Authorize' in Swagger, paste as: Bearer <token>",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name  = "Admin login",
                    value = "{\"username\":\"admin\",\"password\":\"admin123\"}"
                )
            )
        ),
        responses = {
            @ApiResponse(responseCode = "200", description = "Login successful — copy the token"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
        }
    )
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body) {
        try {
            String username = body.getOrDefault("username", "");
            String password = body.getOrDefault("password", "");

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, password);
            var auth = authManager.authenticate(authToken);

            UserDetails ud = (UserDetails) auth.getPrincipal();
            String role  = ud.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");
            String token = jwtUtils.generateToken(username, role);

            return ResponseEntity.ok(Map.of(
                "token",   token,
                "type",    "Bearer",
                "username", username,
                "role",    role,
                "howToUse", "Click 'Authorize' button in Swagger → paste: Bearer " + token
            ));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(401).body(Map.of(
                "error",   "Invalid credentials",
                "hint",    "Try: username=admin, password=admin123"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }
}
