import { createTwoFilesPatch, parsePatch } from "diff";

export type ExtractedDiff = {
    unifiedDiff: string;
    hunksJson: Array<{
        oldStart: number;
        oldLines: number;
        newStart: number;
        newLines: number;
        lines: string[];
        changesOnly: string[];
    }>;
    changesOnlyText: string;
    stats: {
        added: number;
        removed: number;
        hunks: number;
    };
};

function countLinePrefixes(lines: string[]) {
    let added = 0;
    let removed = 0;
    for (const l of lines) {
        if (l.startsWith("+") && !l.startsWith("+++")) added += 1;
        if (l.startsWith("-") && !l.startsWith("---")) removed += 1;
    }
    return { added, removed };
}

export function extractDiff(oldText: string, newText: string): ExtractedDiff {
    const unifiedDiff = createTwoFilesPatch(
        "old.conf",
        "new.conf",
        oldText,
        newText,
        "",
        "",
        { context: 3 }
    );

    const parsed = parsePatch(unifiedDiff);
    const file = parsed[0];

    const hunksJson = (file?.hunks ?? []).map((h) => {
        const changesOnly = h.lines.filter((l) => {
            // Exclude header lines if present (usually dealt with by parsePatch but safe to check)
            if (l.startsWith("@@")) return false;
            if (l.startsWith("+++")) return false;
            if (l.startsWith("---")) return false;
            if (l.startsWith("\\ No newline")) return false;
            return l.startsWith("+") || l.startsWith("-");
        });

        return {
            oldStart: h.oldStart,
            oldLines: h.oldLines,
            newStart: h.newStart,
            newLines: h.newLines,
            lines: h.lines,
            changesOnly
        };
    });

    const changesOnlyLines = hunksJson.flatMap((h) => h.changesOnly);
    const { added, removed } = countLinePrefixes(changesOnlyLines);

    return {
        unifiedDiff,
        hunksJson,
        changesOnlyText: changesOnlyLines.join("\n"),
        stats: {
            added,
            removed,
            hunks: hunksJson.length
        }
    };
}

/**
 * Optimizes diff text for AI consumption by removing critical/long secrets
 * and truncating noisy blobs (certificates, large private keys).
 */
export function optimizeDiffForAI(diffText: string): string {
    const lines = diffText.split("\n");
    const optimized: string[] = [];
    let skippingCert = false;
    let skippingKey = false;

    for (const line of lines) {
        // 1. Truncate Encrypted Passwords & Secrets (Broad match for Fortinet secrets)
        // Matches 'set password ENC ...', 'set passphrase ENC ...', 'set fixed-key ENC ...'
        if (line.match(/set (?:password|passwd|enc-password|scrt-enc|fixed-key|passphrase|private-key|ca|crl) ENC /)) {
            const parts = line.split(" ENC ");
            const indent = line.substring(0, line.indexOf("set"));
            // Deduplicate consecutive secret truncations
            const lastLine = optimized[optimized.length - 1];
            if (!lastLine || !lastLine.includes("[TRUNCATED_SECRET_HASH]")) {
                optimized.push(`${indent}set [SECRET] ENC [TRUNCATED_SECRET_HASH]`);
            }
            continue;
        }

        // 2. Truncate Private Keys & Certificates (Block detection)
        // Detect "BEGIN" headers and start skipping
        if (line.includes("-----BEGIN")) {
            if (line.includes("PRIVATE KEY")) skippingKey = true;
            if (line.includes("CERTIFICATE")) skippingCert = true;
            optimized.push(line);
            continue;
        }
        // Detect "END" headers and stop skipping
        if (line.includes("-----END")) {
            if (line.includes("PRIVATE KEY")) skippingKey = false;
            if (line.includes("CERTIFICATE")) skippingCert = false;
            optimized.push(line);
            continue;
        }

        // Collapse skipped content efficiently
        if (skippingKey) {
            if (!optimized[optimized.length - 1]?.includes("[KEY_BLOCK_CONTENT_HIDDEN]")) {
                optimized.push("    [KEY_BLOCK_CONTENT_HIDDEN]");
            }
            continue;
        }
        if (skippingCert) {
            if (!optimized[optimized.length - 1]?.includes("[CERTIFICATE_CONTENT_HIDDEN]")) {
                optimized.push("    [CERTIFICATE_CONTENT_HIDDEN]");
            }
            continue;
        }

        // 3. Heuristic for Orphaned Base64 Blobs (e.g. middle of diff without headers)
        const trimmed = line.replace(/^[-+]\s*/, "").trim();
        // Check for pure base64 characteristics
        const isBase64 = /^[A-Za-z0-9+/=]+$/.test(trimmed);

        // Aggressive filter: Long lines (50+) OR Medium lines (20+) that look purely like random base64 (no common config keywords)
        // Avoid "set" or "edit" to not kill config
        if (isBase64 && !line.includes("set ") && !line.includes("edit ") && !line.includes("next") && !line.includes("end")) {
            // Check if ANY previous line was a truncation marker to avoid noise sequences
            const lastIndex = optimized.length - 1;
            const lastLine = optimized[lastIndex];
            const previousWasTruncated = lastLine && (
                lastLine.includes("[TRUNCATED_SECRET_HASH]") ||
                lastLine.includes("[TRUNCATED_BASE64_BLOB]") ||
                lastLine.includes("[KEY_BLOCK_CONTENT_HIDDEN]") ||
                lastLine.includes("[CERTIFICATE_CONTENT_HIDDEN]")
            );

            if (trimmed.length > 50) {
                if (!previousWasTruncated) {
                    optimized.push("    [TRUNCATED_BASE64_BLOB]");
                }
                continue;
            }
            // Catch tail end of certs (shorter lines)
            if (trimmed.length > 20) {
                if (previousWasTruncated) {
                    continue; // Merge into previous truncation
                }
                // If not previous truncated, it might be a short key line, but risky to hide if isolated. 
                // We only hide if we are sure it's part of a block (captured by previousWasTruncated).
            }
        }

        // 4. General Length Cap
        if (line.length > 300) {
            optimized.push(`${line.substring(0, 100)}...[TRUNCATED_LINE_LENGTH]`);
            continue;
        }

        optimized.push(line);
    }

    return optimized.join("\n");
}
