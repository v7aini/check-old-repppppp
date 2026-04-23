package com.cybersec.shared.controller;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
public class PublicApiController {
    @GetMapping("/status")
    public ResponseEntity<Map<String,Object>> status() {
        return ResponseEntity.ok(Map.of("status","active","modules",new String[]{"IDS","WAF","TIP"},"version","1.0.0"));
    }
}
