import {
  checkDefinitions,
  type ConfigCheckDefinition,
  type ConfigCheckType,
} from "@/lib/checks-data";
import {
  type ConfigIndex,
  type FgBlock,
  createConfigIndex,
  findBlock,
  findBlocksByPrefix,
  getBlockSnippet,
  parseConfigHeader,
  parseEdits,
} from "@/lib/fortigate";

export type UniversalCheckStatus = "pass" | "fail" | "manual";

export type UniversalCheckResult = {
  id: string;
  name: string;
  type: ConfigCheckType;
  section: string | null;
  status: UniversalCheckStatus;
  evidence?: string;
  note?: string;
};

type CheckOutcome = {
  status: UniversalCheckStatus;
  evidence?: string;
  note?: string;
};

type ReferenceEdit = {
  name: string | null;
  lines: string[];
};

type ReferenceBlock = {
  header: string;
  edits: ReferenceEdit[];
};

const REQUIRED_MALICIOUS_SERVICES = [
  "Botnet-C&C.Server",
  "Hosting-Bulletproof.Hosting",
  "Malicious-Malicious.Server",
  "Phishing-Phishing.Server",
  "Proxy-Proxy.Server",
  "Tor-Exit.Node",
  "Tor-Relay.Node",
  "VPN-Anonymous.VPN",
];

const ALLOWED_WEBFILTER_PROFILES = new Set(["symbis", "symbis-monitor"]);
const ALLOWED_APPLICATION_LISTS = new Set(["symbis", "symbis-default-port", "symbis-monitor"]);
const ALLOWED_SSL_SSH_PROFILES = new Set(["symbis-certificate-inspection"]);

const SSL_VPN_CHECKS = new Set(["ssl_vpn_loopback", "ssl_vpn_cipher_suites", "ssl_vpn_timeout_10_uur"]);

const MANUAL_CHECKS = new Set([
  "server_protecting_actief_op_vips",
  "malicious_block_op_vips_v3",
]);

const MANUAL_NOTES: Record<string, string> = {
  server_protecting_actief_op_vips: "Nog niet geautomatiseerd",
  malicious_block_op_vips_v3: "Nog niet geautomatiseerd",
};

const LOW_END_MODELS = new Set(
  [
    "FG-40F",
    "FG-40F-3G4G",
    "FG-50G",
    "FG-50G-5G",
    "FG-50G-DSL",
    "FG-50G-SFP",
    "FG-50G-SFP-POE",
    "FG-51G",
    "FG-51G-5G",
    "FG-51G-SFP-POE",
    "FG-60E",
    "FG-60E-DSL",
    "FG-60E-POE",
    "FG-60F",
    "FG-61E",
    "FG-61F",
    "FG-70F",
    "FG-70G-POE",
    "FG-71F",
    "FG-71G",
    "FG-71G-POE",
    "FG-80E",
    "FG-80E-POE",
    "FG-81E",
    "FG-81E-POE",
    "FG-90E",
    "FG-91E",
  ].map((model) => normalizeModelName(model) as string)
);

function normalizeModelName(model: string | null) {
  if (!model) return null;
  return model.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^FGT/, "FG");
}

function isSslVpnSupported(model: string | null) {
  if (!model) return true;
  const normalized = model.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (normalized.includes("VM")) return true;
  const gMatch = normalized.match(/(\d+)G/);
  if (gMatch) {
    const value = Number(gMatch[1]);
    if ([30, 50, 70, 90].includes(value)) return false;
  }
  return true;
}

function extractSetLines(lines: string[]) {
  return lines
    .map((line) => line.trim())
    .filter((line) => line.startsWith("set ") || line.startsWith("unset "));
}

function splitAlternatives(reference: string) {
  const lines = reference.split(/\r?\n/);
  const parts: string[] = [];
  let current: string[] = [];
  for (const line of lines) {
    if (/^\s*(of|or)\s*$/i.test(line)) {
      if (current.length > 0) {
        parts.push(current.join("\n"));
        current = [];
      }
      continue;
    }
    current.push(line);
  }
  if (current.length > 0) {
    parts.push(current.join("\n"));
  }
  return parts.length > 0 ? parts : [reference];
}

function buildReferenceBlocks(reference: string): ReferenceBlock[] {
  const refIndex = createConfigIndex(reference);
  return refIndex.blocks.map((block) => {
    const edits = parseEdits(block);
    if (edits.length > 0) {
      return {
        header: block.header,
        edits: edits.map((edit) => ({
          name: edit.name,
          lines: extractSetLines(edit.lines),
        })),
      };
    }
    return {
      header: block.header,
      edits: [{ name: null, lines: extractSetLines(block.lines) }],
    };
  });
}

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripQuotes(token: string) {
  return token.replace(/^"|"$/g, "");
}

function tokenizeLine(line: string) {
  return line
    .trim()
    .split(/\s+/)
    .map(stripQuotes)
    .filter(Boolean);
}

function lineHasToken(line: string, token: string) {
  if (!token) return true;
  if (/^[a-z0-9_-]+$/i.test(token)) {
    const regex = new RegExp(`\\b${escapeRegex(token)}\\b`, "i");
    if (regex.test(line)) return true;
    return token.length > 6 ? line.includes(token) : false;
  }
  return line.includes(token);
}

function lineMatches(requiredLine: string, actualLine: string) {
  const requiredTokens = tokenizeLine(requiredLine.toLowerCase());
  if (requiredTokens.length === 0) return false;
  const [command, ...args] = requiredTokens;
  const actual = actualLine.replace(/"/g, "").trim().toLowerCase();
  if (!(actual === command || actual.startsWith(`${command} `))) return false;
  return args.every((token) => lineHasToken(actual, token));
}

function matchLines(requiredLines: string[], actualLines: string[]) {
  return requiredLines.every((required) =>
    actualLines.some((actual) => lineMatches(required, actual))
  );
}

function toBlockEdits(block: FgBlock) {
  const edits = parseEdits(block);
  if (edits.length > 0) {
    return edits.map((edit) => ({ name: edit.name, lines: edit.lines }));
  }
  return [{ name: null, lines: block.lines }];
}

function blockSatisfiesReference(
  block: FgBlock,
  refBlock: ReferenceBlock,
  requireEditName: boolean
) {
  if (refBlock.edits.length === 1 && refBlock.edits[0].name === null) {
    return matchLines(refBlock.edits[0].lines, block.lines);
  }

  const actualEdits = toBlockEdits(block);

  for (const refEdit of refBlock.edits) {
    const hasName = typeof refEdit.name === "string" && refEdit.name.trim() !== "";
    const mustMatchName = (requireEditName && hasName) || (hasName && refEdit.lines.length === 0);
    const matches = actualEdits.filter((edit) => {
      if (mustMatchName) {
        return edit.name?.toLowerCase() === refEdit.name?.toLowerCase();
      }
      return true;
    });

    const satisfied = matches.some((edit) => matchLines(refEdit.lines, edit.lines));
    if (!satisfied) return false;
  }

  return true;
}

function findReferenceMatch(
  index: ConfigIndex,
  refBlocks: ReferenceBlock[],
  requireEditName: boolean
) {
  for (const refBlock of refBlocks) {
    const actualBlocks = index.blocksByHeader.get(refBlock.header) ?? [];
    if (actualBlocks.length === 0) {
      return { ok: false, evidence: "" };
    }

    const match = actualBlocks.find((block) =>
      blockSatisfiesReference(block, refBlock, requireEditName)
    );

    if (!match) {
      return { ok: false, evidence: getBlockSnippet(index, actualBlocks[0]) };
    }
  }
  return { ok: true, evidence: "" };
}

function findAnyReferenceMatch(
  index: ConfigIndex,
  refBlocks: ReferenceBlock[],
  requireEditName: boolean
) {
  for (const refBlock of refBlocks) {
    const actualBlocks = index.blocksByHeader.get(refBlock.header) ?? [];
    for (const block of actualBlocks) {
      if (blockSatisfiesReference(block, refBlock, requireEditName)) {
        return { ok: true, evidence: getBlockSnippet(index, block) };
      }
    }
  }
  return { ok: false, evidence: "" };
}

function evaluateReference(
  def: ConfigCheckDefinition,
  index: ConfigIndex,
  requireEditName: boolean,
  negative: boolean
): CheckOutcome {
  if (!def.reference) {
    return { status: "manual", note: "Geen referentie beschikbaar" };
  }

  const alternatives = splitAlternatives(def.reference);

  if (negative) {
    for (const alternative of alternatives) {
      const refBlocks = buildReferenceBlocks(alternative);
      const match = findAnyReferenceMatch(index, refBlocks, requireEditName);
      if (match.ok) {
        return { status: "fail", evidence: match.evidence };
      }
    }
    return { status: "pass" };
  }

  let lastEvidence = "";
  for (const alternative of alternatives) {
    const refBlocks = buildReferenceBlocks(alternative);
    const match = findReferenceMatch(index, refBlocks, requireEditName);
    if (match.ok) {
      return { status: "pass" };
    }
    lastEvidence = match.evidence;
  }
  return { status: "fail", evidence: lastEvidence };
}

function parseServiceTokens(line: string) {
  const matches = line.match(/"([^"]+)"/g);
  if (matches && matches.length > 0) {
    return matches.map((match) => match.replace(/"/g, ""));
  }
  const parts = line.replace(/^set service\s+/, "").trim();
  if (!parts) return [];
  return parts.split(/\s+/);
}

function parseQuotedTokens(line: string) {
  const matches = line.match(/"([^"]+)"/g);
  if (matches && matches.length > 0) {
    return matches.map((match) => match.replace(/"/g, ""));
  }
  return line.split(/\s+/).slice(2);
}

function parseFirewallPolicyEdits(index: ConfigIndex) {
  const block = findBlock(index, "config firewall policy");
  if (!block) return [];
  return parseEdits(block);
}

function isHaConfigured(block: FgBlock | null) {
  if (!block) return false;
  const lines = block.lines
    .map((line) => line.trim())
    .filter((line) => line.startsWith("set "));
  const meaningful = lines.filter((line) => !line.startsWith("set override "));
  return meaningful.length > 0;
}

function checkCentralManagement(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config system central-management");
  if (!block) return { status: "fail" };
  const text = block.lines.join("\n").toLowerCase();
  const hasType =
    text.includes("set type fortiguard") ||
    text.includes("set type fortimanager") ||
    text.includes("set type forticloud") ||
    text.includes("set type faz") ||
    text.includes("set type fmg");
  const enabled = hasType && !text.includes("set type none");
  return {
    status: enabled ? "pass" : "fail",
    evidence: getBlockSnippet(index, block),
  };
}

function checkLogging(index: ConfigIndex): CheckOutcome {
  const logBlocks = [
    findBlock(index, "config log fortiguard setting"),
    findBlock(index, "config log fortianalyzer setting"),
    findBlock(index, "config log fortianalyzer2 setting"),
  ].filter(Boolean) as FgBlock[];

  for (const block of logBlocks) {
    const text = block.lines.join("\n").toLowerCase();
    if (text.includes("set status enable") || text.includes("set upload-option")) {
      return { status: "pass", evidence: getBlockSnippet(index, block) };
    }
  }

  return {
    status: "fail",
    evidence: logBlocks[0] ? getBlockSnippet(index, logBlocks[0]) : "",
  };
}

function checkIdleTimeout(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config system global");
  if (!block) return { status: "fail" };
  const line = block.lines.find((item) => item.trim().startsWith("set admintimeout"));
  if (!line) return { status: "fail", evidence: getBlockSnippet(index, block) };
  const value = Number(line.trim().split(/\s+/).pop());
  return {
    status: Number.isFinite(value) && value <= 15 ? "pass" : "fail",
    evidence: getBlockSnippet(index, block),
  };
}

function checkHaSessionPickup(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config system ha");
  if (!isHaConfigured(block)) {
    return {
      status: "pass",
      evidence: block ? getBlockSnippet(index, block) : "",
    };
  }
  const match = block?.lines.some((line) => line.trim().toLowerCase() === "set session-pickup enable");
  return {
    status: match ? "pass" : "fail",
    evidence: getBlockSnippet(index, block),
  };
}

function checkHaDevicePriority(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config system ha");
  if (!block || !isHaConfigured(block)) {
    return { status: "pass", evidence: block ? getBlockSnippet(index, block) : "" };
  }

  const text = block.lines.join("\n").toLowerCase();
  if (text.includes("set override disable")) {
    return { status: "pass", evidence: getBlockSnippet(index, block) };
  }

  const hasPriority = block.lines.some((line) => line.trim().toLowerCase().startsWith("set priority "));
  return {
    status: hasPriority ? "fail" : "pass",
    evidence: getBlockSnippet(index, block),
  };
}

function checkLdapsOnly(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config user ldap");
  if (!block) return { status: "pass" };
  const entries = parseEdits(block);
  if (entries.length === 0) return { status: "pass" };

  const offenders = entries.filter((entry) => {
    const text = entry.lines.join("\n").toLowerCase();
    return !(text.includes("set secure ldaps") || text.includes("set secure starttls"));
  });

  if (offenders.length === 0) return { status: "pass" };
  const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
  return { status: "fail", evidence: preview };
}

function checkRadiusMsChap(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config user radius");
  if (!block) return { status: "pass" };
  const entries = parseEdits(block);
  if (entries.length === 0) return { status: "pass" };

  const offenders = entries.filter((entry) => {
    const text = entry.lines.join("\n").toLowerCase();
    return !text.includes("set auth-type ms_chap_v2");
  });

  if (offenders.length === 0) return { status: "pass" };
  const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
  return { status: "fail", evidence: preview };
}

function checkLocalUsers(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config user local");
  if (!block) return { status: "pass" };
  const entries = parseEdits(block);
  if (entries.length === 0) return { status: "pass" };

  const offenders = entries.filter((entry) => {
    const statusLine = entry.lines.find((line) => line.trim().startsWith("set status"));
    if (!statusLine) return true;
    return !/set status\s+disable/i.test(statusLine.trim());
  });

  if (offenders.length === 0) return { status: "pass" };
  const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
  return { status: "fail", evidence: preview };
}

function checkIpsecEncryption(index: ConfigIndex): CheckOutcome {
  const phase1Blocks = findBlocksByPrefix(index, "config vpn ipsec phase1");
  const phase2Blocks = findBlocksByPrefix(index, "config vpn ipsec phase2");
  if (phase1Blocks.length === 0 && phase2Blocks.length === 0) {
    return { status: "manual", note: "Geen IPsec-config gevonden" };
  }

  const offenders: string[] = [];
  let total = 0;

  for (const block of phase1Blocks) {
    const entries = parseEdits(block);
    for (const entry of entries) {
      total += 1;
      const text = entry.lines.join("\n").toLowerCase();
      const hasProposal = text.includes("aes256gcm-prfsha384");
      const dhLine = entry.lines.find((line) => line.trim().startsWith("set dhgrp"));
      const hasDh20 = dhLine ? /\b20\b/.test(dhLine) : false;
      if (!hasProposal || !hasDh20) {
        offenders.push(entry.lines.join("\n"));
      }
    }
  }

  for (const block of phase2Blocks) {
    const entries = parseEdits(block);
    for (const entry of entries) {
      total += 1;
      const text = entry.lines.join("\n").toLowerCase();
      const hasProposal = text.includes("aes256gcm");
      const dhLine = entry.lines.find((line) => line.trim().startsWith("set dhgrp"));
      const hasDh20 = dhLine ? /\b20\b/.test(dhLine) : false;
      if (!hasProposal || !hasDh20) {
        offenders.push(entry.lines.join("\n"));
      }
    }
  }

  if (offenders.length === 0) {
    return { status: "pass", evidence: total ? `Alle ${total} IPsec entries voldoen.` : "" };
  }

  const preview = offenders.slice(0, 2).join("\n\n");
  const evidence = [`Afwijkingen: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
  return { status: "fail", evidence };
}

function checkIpsecKeylife(index: ConfigIndex): CheckOutcome {
  const phase1Blocks = findBlocksByPrefix(index, "config vpn ipsec phase1");
  const phase2Blocks = findBlocksByPrefix(index, "config vpn ipsec phase2");
  if (phase1Blocks.length === 0 && phase2Blocks.length === 0) {
    return { status: "manual", note: "Geen IPsec-config gevonden" };
  }

  const offenders: string[] = [];
  let total = 0;

  for (const block of phase1Blocks) {
    const entries = parseEdits(block);
    for (const entry of entries) {
      total += 1;
      const text = entry.lines.join("\n").toLowerCase();
      if (!text.includes("set keylife 28800")) {
        offenders.push(entry.lines.join("\n"));
      }
    }
  }

  for (const block of phase2Blocks) {
    const entries = parseEdits(block);
    for (const entry of entries) {
      total += 1;
      const text = entry.lines.join("\n").toLowerCase();
      if (!text.includes("set keylifeseconds 3600")) {
        offenders.push(entry.lines.join("\n"));
      }
    }
  }

  if (offenders.length === 0) {
    return { status: "pass", evidence: total ? `Alle ${total} IPsec entries voldoen.` : "" };
  }

  const preview = offenders.slice(0, 2).join("\n\n");
  const evidence = [`Afwijkingen: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
  return { status: "fail", evidence };
}

function checkIpsecBlackholes(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config router static");
  if (!block) return { status: "fail" };
  const entries = parseEdits(block);
  if (entries.length === 0) return { status: "fail", evidence: getBlockSnippet(index, block) };

  const blackholeByDst = new Map<string, boolean>();
  const badBlackholes: string[] = [];

  const getDst = (lines: string[]) => {
    const dstLine =
      lines.find((line) => line.trim().startsWith("set dstaddr")) ??
      lines.find((line) => line.trim().startsWith("set dst "));
    if (!dstLine) return null;
    return dstLine.split(/\s+/).slice(2).join(" ").replace(/"/g, "").trim();
  };

  const isSdwan = (lines: string[]) =>
    lines.some((line) => line.toLowerCase().includes('set sdwan-zone "virtual-wan-link"'));

  const getDistance = (lines: string[]) => {
    const line = lines.find((item) => item.trim().startsWith("set distance"));
    if (!line) return null;
    const value = Number(line.trim().split(/\s+/).pop());
    return Number.isFinite(value) ? value : null;
  };

  const isBlackhole = (lines: string[]) =>
    lines.some((line) => line.toLowerCase().includes("set blackhole enable"));

  for (const entry of entries) {
    const dst = getDst(entry.lines);
    if (!dst) continue;
    if (isBlackhole(entry.lines)) {
      const distance = getDistance(entry.lines);
      if (distance === 254) {
        blackholeByDst.set(dst, true);
      } else {
        badBlackholes.push(entry.lines.join("\n"));
      }
    }
  }

  const missing: string[] = [];
  for (const entry of entries) {
    const dst = getDst(entry.lines);
    if (!dst) continue;
    if (isSdwan(entry.lines)) continue;
    if (isBlackhole(entry.lines)) continue;
    if (!blackholeByDst.get(dst)) {
      missing.push(entry.lines.join("\n"));
    }
  }

  if (missing.length === 0 && badBlackholes.length === 0) {
    return { status: "pass", evidence: getBlockSnippet(index, block) };
  }

  const preview = [...missing, ...badBlackholes].slice(0, 2).join("\n\n");
  const evidence = [
    missing.length ? `Missende blackhole routes: ${missing.length}` : "",
    badBlackholes.length ? `Blackhole distance niet 254: ${badBlackholes.length}` : "",
    preview,
  ]
    .filter(Boolean)
    .join("\n\n");

  return { status: "fail", evidence };
}

function checkDoHBlocked(index: ConfigIndex): CheckOutcome {
  const entries = parseFirewallPolicyEdits(index);
  const offenders = entries.filter((entry) => {
    const actionLine = entry.lines.find((line) => line.trim().startsWith("set action"));
    const isDeny = actionLine?.toLowerCase().includes("deny");
    if (!isDeny) return false;
    return entry.lines.some((line) => line.trim().toLowerCase().startsWith("set internet-service-name") && line.toLowerCase().includes("dns-doh_dot"));
  });

  if (offenders.length > 0) {
    return { status: "pass", evidence: offenders[0].lines.join("\n") };
  }

  return { status: "fail" };
}

function checkQuicPolicy(index: ConfigIndex): CheckOutcome {
  const entries = parseFirewallPolicyEdits(index);
  const offenders = entries.filter((entry) => {
    const actionLine = entry.lines.find((line) => line.trim().startsWith("set action"));
    const isAccept = actionLine?.toLowerCase().includes("accept");
    if (!isAccept) return false;
    const serviceLine = entry.lines.find((line) => line.trim().startsWith("set service"));
    if (!serviceLine) return false;
    const tokens = parseServiceTokens(serviceLine).map((token) => token.toUpperCase());
    return tokens.includes("QUIC") || tokens.includes("ALL");
  });

  if (offenders.length === 0) {
    return { status: "pass", evidence: getBlockSnippet(index, findBlock(index, "config firewall policy")) };
  }
  const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
  const evidence = [`QUIC accept policies: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
  return { status: "fail", evidence };
}

function checkIpsCpAccel(index: ConfigIndex): CheckOutcome {
  const header = parseConfigHeader(index.text);
  const normalizedModel = normalizeModelName(header.model);
  if (!normalizedModel || !LOW_END_MODELS.has(normalizedModel)) {
    return {
      status: "pass",
      evidence: normalizedModel ? `Niet 2GB model (${normalizedModel})` : "Model onbekend",
    };
  }
  const block = findBlock(index, "config ips global");
  const match = block?.lines.some((line) => line.trim().toLowerCase() === "set cp-accel-mode none");
  return {
    status: match ? "pass" : "fail",
    evidence: getBlockSnippet(index, block),
  };
}

function checkInterfaceRole(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config system interface");
  if (!block) return { status: "fail" };
  const hasRole = block.lines.some((line) => line.trim().toLowerCase().startsWith("set role "));
  return {
    status: "pass",
    evidence: hasRole ? getBlockSnippet(index, block) : "",
  };
}

function checkLocalInPolicy(index: ConfigIndex): CheckOutcome {
  const definition = checkDefinitions.find((item) => item.id === "local_in_policy_v7");
  if (!definition?.reference) return { status: "manual", note: "Geen referentie beschikbaar" };
  return evaluateReference(definition, index, false, false);
}

function checkExternalSymbisLists(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config system external-resource");
  if (!block) return { status: "fail" };
  const entries = parseEdits(block);
  const required = [
    {
      label: "symbis-dns-blocklist",
      resource: "https://raw.githubusercontent.com/symbis/Public/main/FortiGate/blocklist",
      category: "192",
    },
    {
      label: "symbis-dns-allowlist",
      resource: "https://raw.githubusercontent.com/symbis/Public/main/FortiGate/allowlist",
      category: "193",
    },
    {
      label: "symbis-webfilter-blocklist",
      resource: "https://raw.githubusercontent.com/symbis/Public/main/FortiGate/blocklist",
      category: "194",
    },
    {
      label: "symbis-webfilter-allowlist",
      resource: "https://raw.githubusercontent.com/symbis/Public/main/FortiGate/allowlist",
      category: "195",
    },
  ];

  const matchesRequired = (entry: (typeof entries)[number], req: (typeof required)[number]) => {
    const resourceLine = entry.lines.find((line) => line.trim().startsWith("set resource"));
    const categoryLine = entry.lines.find((line) => line.trim().startsWith("set category"));
    if (!resourceLine || !categoryLine) return false;
    return resourceLine.includes(req.resource) && categoryLine.includes(`set category ${req.category}`);
  };

  const missing = required.filter((req) => !entries.some((entry) => matchesRequired(entry, req)));
  if (missing.length === 0) {
    return { status: "pass", evidence: getBlockSnippet(index, block) };
  }

  const evidence = `Missende lists:\n${missing.map((req) => `- ${req.label}`).join("\n")}`;
  return { status: "fail", evidence };
}

function checkServicesNotStacked(index: ConfigIndex): CheckOutcome {
  const entries = parseFirewallPolicyEdits(index);
  for (const entry of entries) {
    const serviceLine = entry.lines.find((line) => line.trim().startsWith("set service"));
    if (serviceLine) {
      const tokens = parseServiceTokens(serviceLine);
      if (tokens.length > 7) {
        const evidence = `Services count: ${tokens.length}\n${entry.lines.join("\n")}`;
        return { status: "fail", evidence };
      }
    }
  }
  return { status: "pass", evidence: getBlockSnippet(index, findBlock(index, "config firewall policy")) };
}

function checkLogtrafficStartDisabled(index: ConfigIndex): CheckOutcome {
  const entries = parseFirewallPolicyEdits(index);
  const offenders = entries.filter((entry) =>
    entry.lines.some((line) => /^set logtraffic-start\s+enable/i.test(line.trim()))
  );
  if (offenders.length === 0) {
    return { status: "pass", evidence: getBlockSnippet(index, findBlock(index, "config firewall policy")) };
  }
  const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
  const evidence = [`logtraffic-start enable policies: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
  return { status: "fail", evidence };
}

function checkSslLabsObject(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config firewall address");
  if (!block) return { status: "fail" };
  const entries = parseEdits(block);
  const entry = entries.find((item) => item.name.toLowerCase() === "s-qualys_ssl_labs");
  if (!entry) {
    return { status: "fail", evidence: "SSL Labs object ontbreekt." };
  }

  const text = entry.lines.join("\n");
  const hasComment = /set comment\\s+\"Symbis default v2\"/i.test(text);
  const hasSubnet = /set subnet\\s+69\\.67\\.183\\.0\\s+255\\.255\\.255\\.0/i.test(text);
  if (hasComment && hasSubnet) {
    return { status: "pass", evidence: entry.lines.join("\n") };
  }

  const missing = [!hasComment ? "comment" : "", !hasSubnet ? "subnet" : ""].filter(Boolean).join(", ");
  const evidence = [`Ontbrekend: ${missing}`, entry.lines.join("\n")].filter(Boolean).join("\n\n");
  return { status: "fail", evidence };
}

function checkAllServiceNotUsed(index: ConfigIndex): CheckOutcome {
  const entries = parseFirewallPolicyEdits(index);
  const offenders = entries.filter((entry) => {
    const actionLine = entry.lines.find((line) => line.trim().startsWith("set action"));
    const isAccept = actionLine?.toLowerCase().includes("accept");
    if (!isAccept) return false;
    const serviceLine = entry.lines.find((line) => line.trim().startsWith("set service"));
    if (!serviceLine) return false;
    const tokens = parseServiceTokens(serviceLine).map((token) => token.toUpperCase());
    return tokens.includes("ALL");
  });

  if (offenders.length === 0) {
    return { status: "pass", evidence: getBlockSnippet(index, findBlock(index, "config firewall policy")) };
  }

  const preview = offenders.slice(0, 3).map((entry) => entry.lines.join("\n")).join("\n\n");
  const evidence = [`ALL accept policies: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
  return { status: "fail", evidence };
}

function checkAllServiceRed(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config firewall service custom");
  if (!block) return { status: "fail" };
  const entries = parseEdits(block);
  const entry = entries.find((item) => item.name.toUpperCase() === "ALL");
  if (!entry) return { status: "fail", evidence: getBlockSnippet(index, block) };
  const hasColor = entry.lines.some((line) => /^set color\s+6$/i.test(line.trim()));
  return {
    status: hasColor ? "pass" : "fail",
    evidence: entry.lines.join("\n"),
  };
}

function checkSymbisUtmProfiles(index: ConfigIndex): CheckOutcome {
  const definition = checkDefinitions.find((item) => item.id === "symbis_utm_profiles_v7");
  if (definition?.reference) {
    const refBlocks = buildReferenceBlocks(definition.reference);
    const missing: string[] = [];

    for (const refBlock of refBlocks) {
      const actualBlocks = index.blocksByHeader.get(refBlock.header) ?? [];
      if (actualBlocks.length === 0) {
        missing.push(`${refBlock.header}: block ontbreekt`);
        continue;
      }

      const actualEdits = actualBlocks.flatMap((block) => parseEdits(block));
      for (const refEdit of refBlock.edits) {
        if (refEdit.name) {
          const refName = refEdit.name ?? "";
          const actualEdit = actualEdits.find(
            (edit) => edit.name.toLowerCase() === refName.toLowerCase()
          );
          if (!actualEdit) {
            missing.push(`${refBlock.header}: profiel \"${refName}\" ontbreekt`);
            continue;
          }
          if (!matchLines(refEdit.lines, actualEdit.lines)) {
            missing.push(`${refBlock.header}: profiel \"${refName}\" wijkt af`);
          }
        } else if (!matchLines(refEdit.lines, actualBlocks[0].lines)) {
          missing.push(`${refBlock.header}: inhoud wijkt af`);
        }
      }
    }

    if (missing.length > 0) {
      return {
        status: "fail",
        evidence: `Ontbrekende of afwijkende profielen:\n${missing.map((item) => `- ${item}`).join("\n")}`,
      };
    }
  }

  const entries = parseFirewallPolicyEdits(index);
  const deviations: string[] = [];

  const getPolicyLabel = (entry: (typeof entries)[number]) => {
    const nameLine = entry.lines.find((line) => line.trim().startsWith("set name"));
    const name = nameLine ? nameLine.split(/\s+/).slice(2).join(" ").replace(/"/g, "").trim() : "";
    return name ? `${entry.name} (${name})` : entry.name;
  };

  const getValue = (line: string) => {
    const tokens = parseQuotedTokens(line);
    return tokens.join(" ").replace(/"/g, "").trim();
  };

  for (const entry of entries) {
    const policyLabel = getPolicyLabel(entry);
    const utmEnabled = entry.lines.some((line) => line.trim().toLowerCase() === "set utm-status enable");
    const sslLine = entry.lines.find((line) => line.trim().startsWith("set ssl-ssh-profile"));
    const webLine = entry.lines.find((line) => line.trim().startsWith("set webfilter-profile"));
    const appLine = entry.lines.find((line) => line.trim().startsWith("set application-list"));

    if (!utmEnabled && !sslLine && !webLine && !appLine) continue;

    if (sslLine) {
      const value = getValue(sslLine);
      const normalized = value.toLowerCase();
      if (!ALLOWED_SSL_SSH_PROFILES.has(normalized)) {
        deviations.push(`${policyLabel}: ssl-ssh-profile "${value}"`);
      }
    } else if (utmEnabled) {
      deviations.push(`${policyLabel}: ssl-ssh-profile ontbreekt`);
    }

    if (webLine) {
      const value = getValue(webLine);
      const normalized = value.toLowerCase();
      if (!ALLOWED_WEBFILTER_PROFILES.has(normalized)) {
        deviations.push(`${policyLabel}: webfilter-profile "${value}"`);
      }
    } else if (utmEnabled) {
      deviations.push(`${policyLabel}: webfilter-profile ontbreekt`);
    }

    if (appLine) {
      const value = getValue(appLine);
      const normalized = value.toLowerCase();
      if (!ALLOWED_APPLICATION_LISTS.has(normalized)) {
        deviations.push(`${policyLabel}: application-list "${value}"`);
      }
    } else if (utmEnabled) {
      deviations.push(`${policyLabel}: application-list ontbreekt`);
    }
  }

  if (deviations.length === 0) {
    return { status: "pass" };
  }

  const preview = deviations.slice(0, 6).join("\n");
  return { status: "fail", evidence: preview };
}

function checkSymbisCertificateInspection(index: ConfigIndex): CheckOutcome {
  const block = findBlock(index, "config firewall ssl-ssh-profile");
  const hasSymbisProfile = block?.lines.join("\n").toLowerCase().includes('edit "symbis-certificate-inspection"') ?? false;

  const offenders: string[] = [];
  const entries = parseFirewallPolicyEdits(index);
  const getPolicyLabel = (entry: (typeof entries)[number]) => {
    const nameLine = entry.lines.find((line) => line.trim().startsWith("set name"));
    const name = nameLine ? nameLine.split(/\s+/).slice(2).join(" ").replace(/"/g, "").trim() : "";
    return name ? `${entry.name} (${name})` : entry.name;
  };
  for (const entry of entries) {
    const profileLine = entry.lines.find((line) => line.trim().startsWith("set ssl-ssh-profile"));
    if (!profileLine) continue;
    const value = parseQuotedTokens(profileLine).join(" ").replace(/"/g, "").trim();
    const normalized = value.toLowerCase();
    if (!ALLOWED_SSL_SSH_PROFILES.has(normalized)) {
      offenders.push(`${getPolicyLabel(entry)}: ssl-ssh-profile "${value}"`);
    }
  }

  if (offenders.length > 0) {
    const preview = offenders.slice(0, 6).join("\n");
    return { status: "fail", evidence: preview };
  }

  return {
    status: hasSymbisProfile ? "pass" : "fail",
    evidence: getBlockSnippet(index, block),
  };
}

function checkMaliciousBlock(index: ConfigIndex): CheckOutcome {
  const entries = parseFirewallPolicyEdits(index);
  const required = new Set(REQUIRED_MALICIOUS_SERVICES.map((item) => item.toLowerCase()));
  const srcCoverage = new Map<string, boolean>();
  const offenders: string[] = [];

  const parseQuoted = (line: string) => {
    const matches = line.match(/"([^"]+)"/g);
    if (matches && matches.length > 0) {
      return matches.map((match) => match.replace(/"/g, ""));
    }
    return line.split(/\s+/).slice(2);
  };

  for (const entry of entries) {
    const dstLine = entry.lines.find((line) => line.trim().startsWith("set dstintf"));
    if (!dstLine) continue;
    const dstTokens = parseQuoted(dstLine).map((token) => token.toLowerCase());
    if (!dstTokens.includes("virtual-wan-link")) continue;

    const srcLine = entry.lines.find((line) => line.trim().startsWith("set srcintf"));
    const srcTokens = srcLine ? parseQuoted(srcLine).map((token) => token.toLowerCase()) : [];
    for (const src of srcTokens) {
      if (!srcCoverage.has(src)) srcCoverage.set(src, false);
    }

    const actionLine = entry.lines.find((line) => line.trim().startsWith("set action"));
    const isDeny = actionLine?.toLowerCase().includes("deny");
    const serviceLines = entry.lines.filter((line) => line.trim().startsWith("set internet-service-name"));
    const serviceTokens = serviceLines.flatMap((line) => parseQuoted(line)).map((token) => token.toLowerCase());

    const hasAllServices = [...required].every((token) => serviceTokens.includes(token));
    if (!isDeny) continue;
    if (hasAllServices) {
      for (const src of srcTokens) {
        srcCoverage.set(src, true);
      }
    } else {
      offenders.push(entry.lines.join("\n"));
    }
  }

  const missingSrc = [...srcCoverage.entries()].filter(([, ok]) => !ok).map(([src]) => src);
  if (missingSrc.length === 0 && offenders.length === 0 && srcCoverage.size > 0) {
    return { status: "pass" };
  }

  const evidenceParts = [];
  if (srcCoverage.size === 0) {
    evidenceParts.push('Geen policies gevonden met dstintf "virtual-wan-link".');
  }
  if (missingSrc.length > 0) {
    evidenceParts.push(`Geen Malicious_deny voor: ${missingSrc.join(", ")}`);
  }
  if (offenders.length > 0) {
    evidenceParts.push(offenders.slice(0, 2).join("\n\n"));
  }

  return {
    status: "fail",
    evidence: evidenceParts.filter(Boolean).join("\n\n"),
  };
}

function checkDefaultRouteSdwan(index: ConfigIndex): CheckOutcome {
  const sdwan = findBlock(index, "config system sdwan");
  const sdwanEnabled = sdwan ? sdwan.lines.join("\n").toLowerCase().includes("set status enable") : false;
  const block = findBlock(index, "config router static");
  const evidence = getBlockSnippet(index, block);
  if (!sdwanEnabled) {
    return { status: "manual", note: "SD-WAN niet actief", evidence };
  }
  const match = block?.lines.some((line) => /set (device|sdwan-zone) "virtual-wan-link"/i.test(line.trim()));
  return {
    status: match ? "pass" : "fail",
    evidence,
  };
}

const CUSTOM_HANDLERS: Record<string, (index: ConfigIndex) => CheckOutcome> = {
  central_management_ingeschakeld: checkCentralManagement,
  logging_naar_cloud_of_analyzer: checkLogging,
  idle_timeout_maximaal_15_minuten: checkIdleTimeout,
  ha_session_pickup: checkHaSessionPickup,
  geen_verschil_in_ha_device_priority: checkHaDevicePriority,
  interface_role_gedefinieerd: checkInterfaceRole,
  uitsluitend_ldaps_gebruik: checkLdapsOnly,
  uitsluitend_radius_ms_chap_v2: checkRadiusMsChap,
  geen_local_users: checkLocalUsers,
  ipsec_minimaal_aes256gcm_prfsha384_en_dh_group_20: checkIpsecEncryption,
  ipsec_keylife_28800_3600: checkIpsecKeylife,
  ipsec_static_blackhole_routes: checkIpsecBlackholes,
  bekende_doh_servers_geblocked_via_isdb: checkDoHBlocked,
  quic_protocol_is_niet_toegestaan: checkQuicPolicy,
  ips_cp_accel_mode_none: checkIpsCpAccel,
  firewall_policies_logtraffic_start_disabled: checkLogtrafficStartDisabled,
  ssl_labs_object: checkSslLabsObject,
  services_in_firewall_policies_zijn_niet_gestapeld: checkServicesNotStacked,
  all_service_wordt_niet_gebruikt_in_firewall_policies: checkAllServiceNotUsed,
  local_in_policy_v7: checkLocalInPolicy,
  global_black_en_whitelist_github: checkExternalSymbisLists,
  all_service_is_rood: checkAllServiceRed,
  symbis_utm_profiles_v7: checkSymbisUtmProfiles,
  symbis_certificate_inspection: checkSymbisCertificateInspection,
  uitgaande_malicious_block_v2: checkMaliciousBlock,
  default_route_is_sd_wan_zone: checkDefaultRouteSdwan,
};

function evaluateDefinition(
  def: ConfigCheckDefinition,
  index: ConfigIndex,
  header: ReturnType<typeof parseConfigHeader>
): CheckOutcome {
  if (MANUAL_CHECKS.has(def.id)) {
    return { status: "manual", note: MANUAL_NOTES[def.id] ?? "Handmatig controleren" };
  }

  if (SSL_VPN_CHECKS.has(def.id) && !isSslVpnSupported(header.model)) {
    return { status: "manual", note: "Model ondersteunt geen SSL-VPN" };
  }

  const custom = CUSTOM_HANDLERS[def.id];
  if (custom) return custom(index);

  if (def.type === "positive_statement") {
    return evaluateReference(def, index, false, false);
  }
  if (def.type === "negative_statement") {
    return evaluateReference(def, index, false, true);
  }
  if (def.type === "positive_block") {
    return evaluateReference(def, index, true, false);
  }
  if (def.type === "negative_block") {
    return evaluateReference(def, index, true, true);
  }

  return { status: "manual", note: "Nog niet geautomatiseerd" };
}

export function formatCheckType(type: ConfigCheckType) {
  switch (type) {
    case "positive_statement":
      return "Positief statement";
    case "negative_statement":
      return "Negatief statement";
    case "positive_block":
      return "Positief blok";
    case "negative_block":
      return "Negatief blok";
    case "aggregation":
      return "Aggregatie";
    default:
      return type;
  }
}

export function evaluateUniversalChecks(confText: string): UniversalCheckResult[] {
  const index = createConfigIndex(confText);
  const header = parseConfigHeader(confText);
  return checkDefinitions.map((def) => {
    const outcome = evaluateDefinition(def, index, header);
    return {
      id: def.id,
      name: def.name,
      type: def.type,
      section: def.section,
      status: outcome.status,
      evidence: outcome.evidence,
      note: outcome.note,
    };
  });
}
