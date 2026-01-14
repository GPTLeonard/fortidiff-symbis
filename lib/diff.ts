import { createTwoFilesPatch, parsePatch, diffLines } from "diff";

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
    contextualDiff: string;
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
        contextualDiff: generateContextualDiff(oldText, newText),
        stats: {
            added,
            removed,
            hunks: hunksJson.length
        }
    };
}

/**
 * Generates a "Smart Context" diff that includes the full parent block (config/edit ... next/end)
 * for any change, ensuring the AI sees the full hierarchy.
 */
export function generateContextualDiff(oldText: string, newText: string): string {
    const differences = diffLines(oldText, newText);

    // We basically want to walk the diff, and whenever we hit a change,
    // we assume the "New" version of the block is the authority for context,
    // but we show the +/- for the specific lines.

    // Actually, reconstructing the tree is hard from just the diff stream.
    // Simpler structures:
    // 1. Split newText into lines.
    // 2. Identify "Dirty" indices (lines that are part of an add or close to a remove).

    // Let's stick to a robust heuristics based on the standard Unified Diff approach
    // but with massive context, then filtering lines that are NOT relevant parents.

    // Alternate Strategy:
    // 1. Create a map of "Changed Lines" in the new File.
    // 2. Walk the new file.
    // 3. Keep a stack of "Parent Headers" (config/edit).
    // 4. If we encounter a changed line, mark the current stack as "Relevant".
    // 5. If a stack is Relevant, we must print it.

    // Let's implement this Strategy.

    // Step 1: Map changed lines in New File
    // We need to know which lines in `newText` correspond to an `added` or `modified` change.
    const newLines = newText.split("\n");
    const changedIndices = new Set<number>(); // 0-indexed line numbers in newText

    let currentNewIndex = 0;

    // Temporarily tracking changes to map them
    // Note: Re-running diffLines is cheap for text files.
    for (const part of differences) {
        if (part.added) {
            for (let i = 0; i < part.count!; i++) {
                changedIndices.add(currentNewIndex + i);
            }
            currentNewIndex += part.count!;
        } else if (part.removed) {
            // Removed lines don't exist in newFile, so we can't map them to an index directly.
            // But we want to show them!
            // We'll handle removals by checking if the *previous* or *next* line is touched.
            // Actually, we can assume the "context point" is the current index.
            changedIndices.add(currentNewIndex); // Mark this insertion point as dirty
        } else {
            currentNewIndex += part.count!;
        }
    }

    // Step 2: Identify Blocks to Keep
    // A block is defined by indent level or keywords. 
    // FortiGate: 'config' starts a block. 'edit' starts a sub-block. 'next'/'end' ends them.
    // We want: If line K is changed, keep its parent blocks recursively.
    // AND keep all siblings in the immediate parent block (user request: "Alles tussen config en end").

    const linesToKeep = new Set<number>();

    // Helper to add a range to keep
    const keepRange = (start: number, end: number) => {
        for (let i = start; i <= end; i++) linesToKeep.add(i);
    };

    const openBlocks: { start: number; type: "config" | "edit"; hasChange: boolean }[] = [];

    for (let i = 0; i < newLines.length; i++) {
        const line = newLines[i];
        const trimmed = line.trim();

        // Start Block
        if (trimmed.startsWith("config ")) {
            openBlocks.push({ start: i, type: "config", hasChange: false });
        } else if (trimmed.startsWith("edit ")) {
            openBlocks.push({ start: i, type: "edit", hasChange: false });
        }

        // Check Change
        // Use a lax check: if this line is changed, or if it's an "edit/set" that is adjacent to a removal?
        if (changedIndices.has(i)) {
            // Mark all open blocks as having a change
            for (const b of openBlocks) b.hasChange = true;
        }

        // End Block
        if (trimmed === "next" || trimmed === "end") {
            const block = openBlocks.pop();
            if (block) {
                if (block.hasChange || changedIndices.has(i)) {
                    if (block.type === "edit") {
                        // Keep only the changed edit block for focused context.
                        keepRange(block.start, i);
                    } else {
                        // Keep just the config header and end marker.
                        linesToKeep.add(block.start);
                        linesToKeep.add(i);
                    }
                    // Also mark the parent as having a change (bubble up)
                    if (openBlocks.length > 0) openBlocks[openBlocks.length - 1].hasChange = true;
                }
            }
        }

        // Global/orphan lines (like 'set ...' at root level? unlikely but possible)
        // If a line is changed and logically top-level?
        if (changedIndices.has(i) && openBlocks.length === 0) {
            linesToKeep.add(i);
        }
    }

    // Step 3: Construct the Result
    // ensuring we include the +/- markers. This is the hardest part: injecting the diff markers into the "New File" view.
    // A pure "New File" dump misses the "Old Values".

    // HYBRID APPROACH:
    // We will build the output by iterating the `diffLines` again.
    // But we only output context lines if they are in `linesToKeep`.
    // Changed lines (add/remove) are ALWAYS output.

    // We need a mapping from "Diff Part" to "New File Line Index" to check `linesToKeep`.

    let result = "";
    currentNewIndex = 0;

    const MAX_CONTEXT_LINE = 180;
    const CONTEXT_TRUNCATE_TO = 140;
    const truncateContextLine = (line: string) => {
        if (line.length <= MAX_CONTEXT_LINE) return line;
        return `${line.substring(0, CONTEXT_TRUNCATE_TO)}...[TRUNCATED_UNCHANGED_LINE]`;
    };

    // We need to inject "..." markers if we skip lines?
    let skipping = false;

    for (const part of differences) {
        if (part.added) {
            // Output all added lines with "+"
            // Also these are "New File" lines, so they update index.
            for (const line of part.value.split("\n")) {
                if (line === "") continue; // split cleanup
                result += `+ ${line}\n`;
            }
            skipping = false;
            currentNewIndex += part.count!;
        } else if (part.removed) {
            // Output all removed lines with "-"
            // These DO NOT advance newIndex.
            for (const line of part.value.split("\n")) {
                if (line === "") continue;
                result += `- ${line}\n`;
            }
            skipping = false;
        } else {
            // Context lines (Unchanged)
            // We check if these lines are in `linesToKeep`.
            const contextLines = part.value.split("\n");
            // Remove trailing empty from split
            if (contextLines[contextLines.length - 1] === "") contextLines.pop();

            for (let i = 0; i < contextLines.length; i++) {
                const line = contextLines[i];
                const realIndex = currentNewIndex + i;

                if (linesToKeep.has(realIndex)) {
                    if (skipping) {
                        // result += "  ...\n"; // Optional visual separator
                        skipping = false;
                    }
                    result += `  ${truncateContextLine(line)}\n`;
                } else {
                    skipping = true;
                }
            }
            currentNewIndex += part.count!;
        }
    }

    return result;
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
