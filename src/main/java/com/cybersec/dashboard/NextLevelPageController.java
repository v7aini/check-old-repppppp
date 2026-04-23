package com.cybersec.dashboard;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class NextLevelPageController {

    @GetMapping("/phishing")
    public String phishing() {
        return "phishing/index";
    }

    @GetMapping("/wifi")
    public String wifi() {
        return "wifi/index";
    }

    @GetMapping("/policy")
    public String policy() {
        return "policy/index";
    }

    @GetMapping("/blockchain")
    public String blockchain() {
        return "blockchain/index";
    }
}
