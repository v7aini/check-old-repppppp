package com.cybersec.shared.policy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/policy")
public class PolicyApiController {

    @Autowired
    private SecurityPolicyService policyService;

    @GetMapping("/rules")
    public Set<String> getRules() {
        return policyService.getActiveRules();
    }
}
