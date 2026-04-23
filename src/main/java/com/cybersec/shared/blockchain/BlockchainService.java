package com.cybersec.shared.blockchain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight Blockchain for Security Alert Integrity
 */
@Service
public class BlockchainService {
    private static final Logger logger = LoggerFactory.getLogger(BlockchainService.class);
    private final List<Block> chain = new ArrayList<>();

    @PostConstruct
    public void init() {
        // Create Genesis Block
        logger.info("Initializing Security Blockchain...");
        chain.add(new Block(0, "Genesis Block - Security Ledger Start", "0"));
    }

    public synchronized void addAlertToChain(String alertData) {
        Block lastBlock = chain.get(chain.size() - 1);
        Block newBlock = new Block(chain.size(), alertData, lastBlock.getHash());
        chain.add(newBlock);
        logger.info("Alert hash added to blockchain. Index: {}, Hash: {}", newBlock.getIndex(), newBlock.getHash().substring(0, 8));
    }

    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block currentBlock = chain.get(i);
            Block previousBlock = chain.get(i - 1);

            // Verify current hash
            if (!currentBlock.getHash().equals(currentBlock.calculateHash())) {
                logger.error("Blockchain TAMPERED! Block {} hash mismatch.", i);
                return false;
            }

            // Verify linkage
            if (!currentBlock.getPreviousHash().equals(previousBlock.getHash())) {
                logger.error("Blockchain DISCONTINUITY! Block {} pointer mismatch.", i);
                return false;
            }
        }
        return true;
    }

    public List<Block> getChain() {
        return new ArrayList<>(chain);
    }

    /**
     * DEBUG ONLY: Manually corrupt a block to test integrity verification
     */
    public void simulateTamper() {
        if (chain.size() > 1) {
            Block block = chain.get(1); // Corrupt the first alert block
            // Use reflection or a "hack" to change final data if it was final, 
            // but here we just need to provide a new chain with one bad block.
            // Simplified: replace the block with a "forged" one
            Block tamperedBlock = new Block(block.getIndex(), "FORGED DATA: Attacker deleted logs", block.getPreviousHash());
            chain.set(1, tamperedBlock);
            logger.error("SYSTEM ALERT: Block 1 has been manually tampered for testing!");
        }
    }
}
