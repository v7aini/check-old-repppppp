package com.cybersec.telegram;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/telegram")
@Tag(name = "Telegram Bot", description = "Configure and test Telegram alert notifications")
public class TelegramController {

    private final TelegramAlertService svc;

    @Autowired
    public TelegramController(TelegramAlertService svc) { this.svc = svc; }

    @GetMapping("/status")
    @Operation(summary = "Get bot status and configuration",
               description = "Shows whether Telegram is enabled and configured")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of(
            "enabled",    svc.isEnabled(),
            "configured", svc.isEnabled(),
            "chatId",     svc.getChatId(),
            "botToken",   svc.getBotToken(),
            "setup", "Set telegram.enabled=true, telegram.bot-token=..., telegram.chat-id=... in application.properties"
        ));
    }

    @PostMapping("/test")
    @Operation(summary = "Send a test message to Telegram",
               description = "Tests the bot connection. Returns success=true if message delivered.")
    public ResponseEntity<Map<String, Object>> test() {
        boolean ok = svc.testConnection();
        return ResponseEntity.ok(Map.of(
            "success", ok,
            "message", ok
                ? "Test message sent! Check your Telegram chat."
                : "Failed. Steps: 1) Set telegram.enabled=true in application.properties  " +
                  "2) Set telegram.bot-token from @BotFather  " +
                  "3) Set telegram.chat-id from https://api.telegram.org/bot<TOKEN>/getUpdates  " +
                  "4) Restart the app"
        ));
    }

    @PostMapping("/send")
    @Operation(summary = "Send a custom message",
               description = "Sends any text to your configured Telegram chat. Body: {\"message\": \"your text\"}")
    public ResponseEntity<Map<String, Object>> send(@RequestBody Map<String, String> body) {
        String msg = body.getOrDefault("message", "Hello from CyberSec Platform!");
        svc.sendCustomMessage(msg);
        return ResponseEntity.ok(Map.of("sent", true, "message", msg));
    }
}
