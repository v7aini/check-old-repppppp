package com.cybersec;

import com.cybersec.ids.model.Alert;
import com.cybersec.ids.service.AlertService;
import com.cybersec.waf.service.RateLimiterService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class CybersecPlatformTests {

    @Autowired MockMvc mockMvc;
    @Autowired RateLimiterService rateLimiter;
    @Autowired AlertService alertService;

    @Test @DisplayName("WAF: SQLi in URL returns 403")
    void wafBlocksSqli() throws Exception {
        mockMvc.perform(get("/dashboard?id=1%27%20UNION%20SELECT%20*%20FROM%20users--"))
               .andExpect(status().isForbidden());
    }

    @Test @DisplayName("WAF: XSS in URL returns 403")
    void wafBlocksXss() throws Exception {
        mockMvc.perform(get("/dashboard?q=%3Cscript%3Ealert(1)%3C/script%3E"))
               .andExpect(status().isForbidden());
    }

    @Test @DisplayName("WAF: LFI path traversal returns 403")
    void wafBlocksLfi() throws Exception {
        mockMvc.perform(get("/dashboard?path=../../etc/passwd"))
               .andExpect(status().isForbidden());
    }

    @Test @DisplayName("WAF: Scanner user-agent blocked")
    void wafBlocksScanner() throws Exception {
        mockMvc.perform(get("/dashboard").header("User-Agent","sqlmap/1.7"))
               .andExpect(status().isForbidden());
    }

    @Test @DisplayName("Rate limiter: allows normal traffic")
    void rateLimiterAllows() {
        rateLimiter.clearStrikes("10.0.0.1");
        for (int i = 0; i < 10; i++) assertThat(rateLimiter.isAllowed("10.0.0.1")).isTrue();
    }

    @Test @DisplayName("Rate limiter: blocks over limit")
    void rateLimiterBlocks() {
        String ip = "10.0.0.200";
        rateLimiter.clearStrikes(ip);
        for (int i = 0; i < 101; i++) rateLimiter.isAllowed(ip);
        assertThat(rateLimiter.isAllowed(ip)).isFalse();
        assertThat(rateLimiter.getStrikeCount(ip)).isGreaterThan(0);
    }

    @Test @DisplayName("IDS: alert is created and persisted")
    void idsAlertCreated() {
        long before = alertService.countAlertsToday();
        alertService.fireAlert("1.2.3.4","TEST","Unit test","UNIT_TEST","HIGH");
        assertThat(alertService.countAlertsToday()).isGreaterThan(before);
    }

    @Test @DisplayName("IDS: alert retrieved by IP")
    void idsAlertByIp() {
        alertService.fireAlert("192.0.2.99","RECON","Test","UNIT_TEST","LOW");
        assertThat(alertService.getAlertsByIp("192.0.2.99")).isNotEmpty();
    }

    @Test @DisplayName("IDS: alert status updated to RESOLVED")
    void idsAlertStatusUpdate() {
        Alert a = alertService.fireAlert("10.0.0.5","SCAN","Test","UNIT","LOW");
        Alert updated = alertService.updateStatus(a.getId(), Alert.AlertStatus.RESOLVED, "done");
        assertThat(updated.getStatus()).isEqualTo(Alert.AlertStatus.RESOLVED);
        assertThat(updated.getResolvedAt()).isNotNull();
    }

    @Test @DisplayName("Login page accessible without auth")
    void loginPageAccessible() throws Exception {
        mockMvc.perform(get("/login")).andExpect(status().isOk());
    }

    @Test @DisplayName("Dashboard redirects without auth")
    void dashboardRequiresAuth() throws Exception {
        mockMvc.perform(get("/dashboard")).andExpect(status().is3xxRedirection());
    }

    @Test @DisplayName("Dashboard loads for admin")
    @WithMockUser(username="admin",roles="ADMIN")
    void dashboardLoads() throws Exception {
        mockMvc.perform(get("/dashboard")).andExpect(status().isOk());
    }

    @Test @DisplayName("IDS page loads for analyst")
    @WithMockUser(username="analyst",roles="ANALYST")
    void idsPageLoads() throws Exception {
        mockMvc.perform(get("/ids")).andExpect(status().isOk());
    }

    @Test @DisplayName("API stats returns 200")
    @WithMockUser(username="analyst",roles="ANALYST")
    void idsStatsApi() throws Exception {
        mockMvc.perform(get("/api/ids/stats")).andExpect(status().isOk()).andExpect(jsonPath("$.alertsToday").exists());
    }
}
