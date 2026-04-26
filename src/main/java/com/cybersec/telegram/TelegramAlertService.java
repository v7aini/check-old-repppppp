package com.cybersec.telegram;

import com.cybersec.ids.model.Alert;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Telegram Alert Service — sends messages using Telegram Bot HTTP API directly.
 * Uses Java 11+ HttpClient (no extra library needed).
 *
 * HOW TO SETUP:
 *  Step 1: Open Telegram, search @BotFather, send /newbot
 *          Follow the prompts. Copy the token like: 123456789:ABCdefGhI...
 *
 *  Step 2: Start a conversation with your new bot.
 *          Then visit this URL in your browser:
 *          https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
 *          Find the "id" field inside "chat" — that is your chat_id
 *
 *  Step 3: Edit application.properties:
 *          telegram.enabled=true
 *          telegram.bot-token=123456789:ABCdefGhI...
 *          telegram.chat-id=987654321
 *
 *  Step 4: Test via Swagger: POST /api/telegram/test
 */
@Service
public class TelegramAlertService {

    private static final Logger log = LoggerFactory.getLogger(TelegramAlertService.class);
    private static final String API_URL = "https://api.telegram.org/bot";
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss");

    @Value("${telegram.enabled:false}")           private boolean enabled;
    @Value("${telegram.bot-token:}")              private String botToken;
    @Value("${telegram.chat-id:}")                private String chatId;
    @Value("${telegram.alert-min-severity:HIGH}") private String minSeverity;

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Autowired
    public TelegramAlertService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /** Called by AlertService on every HIGH/CRITICAL alert. Runs async. */
    @Async
    public void sendAlert(Alert alert) {
        if (!isConfigured() || !shouldSend(alert.getSeverity())) return;

        String emoji = switch (alert.getSeverity()) {
            case CRITICAL -> "🚨"; case HIGH -> "⚠️"; case MEDIUM -> "🔔"; default -> "ℹ️";
        };
        String detail = alert.getDetail().length() > 200
                ? alert.getDetail().substring(0, 200) + "..."
                : alert.getDetail();

        String safeDetail = escapeMarkdown(detail);
        String safeType = escapeMarkdown(alert.getAttackType());
        String safeIp = escapeMarkdown(alert.getSourceIp());
        String safeBy = escapeMarkdown(alert.getDetectedBy() != null ? alert.getDetectedBy() : "UNKNOWN");

        String message = emoji + " *CYBERSEC ALERT — " + alert.getSeverity().name() + "*\n\n"
                + "Type: " + safeType + "\n"
                + "Source IP: " + safeIp + "\n"
                + "Detected by: " + safeBy + "\n"
                + "Threat Score: " + (alert.getThreatScore() != null ? alert.getThreatScore() : 0) + "/100\n"
                + "Time: " + alert.getDetectedAt().format(FMT) + "\n"
                + "Detail: " + safeDetail + "\n\n"
                + "View: http://localhost:9090/ids/alert/" + alert.getId();
        sendMessage(message);
    }

    /** Send a custom message — used by Investigation tool when blocking a device. */
    @Async
    public void sendCustomMessage(String message) {
        if (!isConfigured()) {
            log.info("[TELEGRAM] Not configured — message not sent. Set telegram.enabled=true in application.properties");
            return;
        }
        sendMessage(message);
    }

    /** Test the bot connection. Returns true if message sent successfully. */
    public boolean testConnection() {
        if (!isConfigured()) return false;
        try {
            sendMessage("✅ *CyberSec Platform* connected!\n\nYour Telegram bot is working correctly. Alerts will be sent here for HIGH and CRITICAL events.");
            return true;
        } catch (Exception e) {
            log.error("[TELEGRAM] Test failed: {}", e.getMessage());
            return false;
        }
    }

    private void sendMessage(String text) {
        if (!isConfigured()) return;
        try {
            Map<String, String> payload = Map.of(
                "chat_id",    chatId,
                "text",       text,
                "parse_mode", "Markdown"
            );
            String json = objectMapper.writeValueAsString(payload);
            String url  = API_URL + botToken + "/sendMessage";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                log.info("[TELEGRAM] Message sent successfully to chat {}", chatId);
            } else {
                log.error("[TELEGRAM] API error {}: {}", response.statusCode(), response.body());
            }
        } catch (Exception e) {
            log.error("[TELEGRAM] Failed to send message: {}", e.getMessage());
        }
    }

    private boolean isConfigured() {
        return enabled && botToken != null && !botToken.isBlank()
                && !botToken.equals("YOUR_BOT_TOKEN_HERE")
                && chatId != null && !chatId.isBlank()
                && !chatId.equals("YOUR_CHAT_ID_HERE");
    }

    private boolean shouldSend(Alert.Severity severity) {
        try {
            Alert.Severity min = Alert.Severity.valueOf(minSeverity.toUpperCase());
            return severity.ordinal() >= min.ordinal();
        } catch (Exception e) {
            return severity == Alert.Severity.HIGH || severity == Alert.Severity.CRITICAL;
        }
    }

    /** Escape special Markdown characters that break Telegram's parser */
    private String escapeMarkdown(String text) {
        if (text == null) return "";
        return text
            .replace("\\", "\\\\")
            .replace("*", "\\*")
            .replace("_", "\\_")
            .replace("`", "\\`")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("~", "\\~")
            .replace(">", "\\>")
            .replace("#", "\\#")
            .replace("+", "\\+")
            .replace("-", "\\-")
            .replace("=", "\\=")
            .replace("|", "\\|")
            .replace("{", "\\{")
            .replace("}", "\\}")
            .replace(".", "\\.")
            .replace("!", "\\!");
    }

    public boolean isEnabled()  { return enabled; }
    public String  getChatId()   { return chatId != null ? chatId : "not set"; }
    public String  getBotToken() {
        if (botToken == null || botToken.isBlank() || botToken.equals("YOUR_BOT_TOKEN_HERE"))
            return "not set";
        return botToken.substring(0, Math.min(botToken.length(), 10)) + "...";
    }
}
