package com.cybersec.shared.blockchain;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/blockchain")
public class BlockchainApiController {

    @Autowired
    private BlockchainService blockchainService;

    @GetMapping("/chain")
    public List<Block> getChain() {
        return blockchainService.getChain();
    }

    @GetMapping("/verify")
    public boolean verify() {
        return blockchainService.isChainValid();
    }

    @PostMapping("/tamper")
    public void tamper() {
        blockchainService.simulateTamper();
    }
}
