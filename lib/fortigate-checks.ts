import {
  type ConfigIndex,
  type FgBlock,
  createConfigIndex,
  findBlock,
  findBlocksByPrefix,
  findLineIndex,
  getBlockSnippet,
  makeSnippet,
  parseEdits,
  parseConfigHeader,
} from "@/lib/fortigate";

export type CheckResult = {
  satisfied: boolean;
  evidence?: string;
  note?: string;
  skip?: boolean;
};

export type CheckDefinition = {
  id: string;
  label: string;
  manual?: boolean;
  manualNote?: string;
  run: (index: ConfigIndex) => CheckResult;
};

type Match = {
  index: number;
  snippet: string;
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

const SYMBIS_OBJECT_SENTINELS = [
  'edit "s-apple_inc."',
  'edit "s-wildcard.teamviewer.com"',
  'edit "s-european_union"',
  'edit "s-qualys_ssl_labs"',
];

const SYMBIS_ENTRA_TENANT_ID = "4f4b99f3-8fde-4ffa-8989-04680bb56aa7";
const SYMBIS_ENTRA_ENTITY_ID = `https://sts.windows.net/${SYMBIS_ENTRA_TENANT_ID}/`;

const ALLOWED_WEBFILTER_PROFILES = new Set(["symbis", "symbis-monitor"]);
const ALLOWED_APPLICATION_LISTS = new Set(["symbis", "symbis-default-port", "symbis-monitor"]);
const ALLOWED_SSL_SSH_PROFILES = new Set(["symbis-certificate-inspection"]);

const MANUAL_CHECKS = new Set([
  "admin_interface_bereikbaar_vanaf_symbis_en_mgmt_servers",
  "publieke_domein_en_uitgezonderd_van_filtering_dns_web",
  "fortigate_primaire_dns_server",
  "enforce_default_port_app_control",
  "ssl_vpn_dns",
  "webfilter_override",
  "fortigate_mgmt_policy_rule",
  "deep_inspection_uitgaand",
  "geo_ip_blocking",
  "certificaat_path_volledig_remote_ca_correct_installed",
  "internet_services_policy_v4",
  "ipsec_phase_2_op_basis_van_0_0_0_0_0_routes",
  "ssl_vpn_password_safe_off",
  "ssl_vpn_geldig_certificaat",
  "interface_alias_ingevuld",
  "estimated_bandwidth_wan",
  "dns_service_on_interface_staat_voor_guest_naar_system_dns",
  "interne_zone_uitgezonderd_in_het_dns_filter",
  "alle_firewall_policys_0_bytes_controle",
  "implicit_deny_dns_ntp_en_utm_log_gecontroleerd",
  "symbis_objecten_toegepast_waar_mogelijk",
  "administrative_access_less_is_more",
  "standaard_objecten_aanwezig_v29",
  "naamgeving_policys",
  "server_protecting_actief_op_vips",
  "malicious_block_op_vips_v3",
  "alle_certificaten_zijn_geldig_valid",
  "devices_in_fabric_zijn_registered",
  "itboost_bijgewerkt",
  "bitwarden_bijgewerkt_en_opgeschoond",
]);

const MANUAL_NOTES: Record<string, string> = {
  internet_services_policy_v4: "Check verwijderd",
  ipsec_phase_2_op_basis_van_0_0_0_0_0_routes: "Check verwijderd",
  ssl_vpn_password_safe_off: "Check verwijderd",
  interface_alias_ingevuld: "Check verwijderd",
  standaard_objecten_aanwezig_v29: "Check verwijderd",
};

const IGNORE_WHEN_EMPTY = new Set(["firewall_policys_logtraffic_start_disabled"]);

function normalizeModelName(model: string | null) {
  if (!model) return null;
  return model.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^FGT/, "FG");
}

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

function findFirstMatch(index: ConfigIndex, matcher: RegExp): Match | null {
  const idx = findLineIndex(index.lines, matcher);
  if (idx === -1) return null;
  return {
    index: idx,
    snippet: makeSnippet(index.lines, idx, idx),
  };
}

function blockHasTokens(block: FgBlock | null, tokens: string[]): boolean {
  if (!block) return false;
  const text = block.lines.join("\n").toLowerCase();
  return tokens.every((token) => text.includes(token));
}

function findInBlock(index: ConfigIndex, block: FgBlock | null, matcher: RegExp): Match | null {
  if (!block) return null;
  const idx = findLineIndex(index.lines, matcher, block.start, block.end);
  if (idx === -1) return null;
  return {
    index: idx,
    snippet: makeSnippet(index.lines, idx, idx),
  };
}

function getPolicyBlock(index: ConfigIndex): FgBlock | null {
  return findBlock(index, "config firewall policy");
}

function getLocalInBlock(index: ConfigIndex): FgBlock | null {
  return findBlock(index, "config firewall local-in-policy");
}

function isHaConfigured(block: FgBlock | null): boolean {
  if (!block) return false;
  const lines = block.lines
    .map((line) => line.trim())
    .filter((line) => line.startsWith("set "));
  const meaningful = lines.filter((line) => !line.startsWith("set override "));
  return meaningful.length > 0;
}

function parseInterfaceEdits(index: ConfigIndex): ReturnType<typeof parseEdits> {
  const block = findBlock(index, "config system interface");
  if (!block) return [];
  return parseEdits(block);
}

function parseFirewallPolicyEdits(index: ConfigIndex): ReturnType<typeof parseEdits> {
  const block = getPolicyBlock(index);
  if (!block) return [];
  return parseEdits(block);
}

function parseServiceTokens(line: string): string[] {
  const matches = line.match(/\"([^\"]+)\"/g);
  if (matches && matches.length > 0) {
    return matches.map((match) => match.replace(/\"/g, ""));
  }
  const parts = line.replace(/^set service\s+/, "").trim();
  if (!parts) return [];
  return parts.split(/\s+/);
}

function parseQuotedTokens(line: string): string[] {
  const matches = line.match(/\"([^\"]+)\"/g);
  if (matches && matches.length > 0) {
    return matches.map((match) => match.replace(/\"/g, ""));
  }
  return line.split(/\s+/).slice(2);
}

export const CHECKS: Record<string, CheckDefinition> = {
  admin_interface_bereikbaar_vanaf_symbis_en_mgmt_servers: {
    id: "admin_interface_bereikbaar_vanaf_symbis_en_mgmt_servers",
    label: "Admin interface bereikbaar vanaf Symbis en MGMT servers",
    run: (index) => {
      const block = getLocalInBlock(index);
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const hasMgmt = text.includes("mgmt_ips");
      const hasService = text.includes("tcp_8443") && text.includes("ssh");
      return {
        satisfied: hasMgmt && hasService,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  sftp_backup: {
    id: "sftp_backup",
    label: "SFTP backup",
    run: (index) => {
      const match = findFirstMatch(index, /execute backup config sftp/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  saml_admin_webinterface: {
    id: "saml_admin_webinterface",
    label: "SAML admin webinterface",
    run: (index) => {
      const block = findBlock(index, "config system saml");
      const match = findInBlock(index, block, /set status enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  forticloud_sso_uitgeschakeld: {
    id: "forticloud_sso_uitgeschakeld",
    label: "FortiCloud SSO uitgeschakeld",
    run: (index) => {
      const cloud = findBlock(index, "config system sso-fortigate-cloud-admin");
      const admin = findBlock(index, "config system sso-admin");
      const combined = `${cloud?.lines.join("\n") ?? ""}\n${admin?.lines.join("\n") ?? ""}`.toLowerCase();
      const enabled = combined.includes("set status enable");
      return {
        satisfied: !enabled,
        evidence: getBlockSnippet(index, cloud ?? admin ?? null),
      };
    },
  },
  publieke_domein_en_uitgezonderd_van_filtering_dns_web: {
    id: "publieke_domein_en_uitgezonderd_van_filtering_dns_web",
    label: "Publieke domein(en) uitgezonderd van filtering (DNS/Web)",
    run: (index) => {
      const block = findBlock(index, "config system external-resource");
      const hasDnsAllow = index.textLower.includes("symbis-dns-allowlist");
      const hasWebAllow = index.textLower.includes("symbis-webfilter-allowlist");
      return {
        satisfied: hasDnsAllow && hasWebAllow,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  auto_firmware_upgrade: {
    id: "auto_firmware_upgrade",
    label: "Auto firmware upgrade",
    run: (index) => {
      const block = findBlock(index, "config system fortiguard");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const hasSchedule =
        text.includes("auto-firmware-upgrade-start-hour") &&
        text.includes("auto-firmware-upgrade-end-hour");
      const hasDelay = text.includes("auto-firmware-upgrade-delay");
      const hasEnable = text.includes("auto-firmware-upgrade enable");
      return {
        satisfied: hasSchedule && (hasDelay || hasEnable),
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ha_session_pickup: {
    id: "ha_session_pickup",
    label: "HA session pickup",
    run: (index) => {
      const block = findBlock(index, "config system ha");
      if (!isHaConfigured(block)) {
        return { satisfied: false, skip: true, note: "Geen HA-config" };
      }
      const match = findInBlock(index, block, /set session-pickup(-connectionless)? enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  geen_veschil_in_ha_device_priority: {
    id: "geen_veschil_in_ha_device_priority",
    label: "Geen veschil in HA Device priority",
    run: (index) => {
      const block = findBlock(index, "config system ha");
      if (!block || !isHaConfigured(block)) {
        return { satisfied: false, skip: true, note: "Geen HA-config" };
      }
      const hasPriority = /set priority\s+/i.test(block.lines.join("\n"));
      return {
        satisfied: !hasPriority,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  fortigate_primaire_dns_server: {
    id: "fortigate_primaire_dns_server",
    label: "FortiGate primaire DNS server",
    run: (index) => {
      const block = findBlock(index, "config system dns");
      const match = findInBlock(index, block, /set primary\s+\\d+\\.\\d+\\.\\d+\\.\\d+/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  bekende_doh_servers_geblocked_via_isdb: {
    id: "bekende_doh_servers_geblocked_via_isdb",
    label: "Bekende DoH servers geblocked via ISDB",
    run: (index) => {
      const match = findFirstMatch(index, /dns-doh_dot/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  proxy_cat_blocked_by_dns: {
    id: "proxy_cat_blocked_by_dns",
    label: "Proxy cat. blocked by DNS",
    run: (index) => {
      const block = findBlock(index, "config dnsfilter profile");
      const blockText = block?.lines.join("\n").toLowerCase() ?? "";
      const hasCategory = blockText.includes("set category 59");
      const hasBlock = blockText.includes("set action block");
      return {
        satisfied: hasCategory && hasBlock,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ipsec_minimaal_op_basis_van_aes256gcm_prfsha384_en_dh_20: {
    id: "ipsec_minimaal_op_basis_van_aes256gcm_prfsha384_en_dh_20",
    label: "IPsec minimaal op basis van AES256GCM-PRFSHA384 en DH 20",
    run: (index) => {
      const blocks = findBlocksByPrefix(index, "config vpn ipsec phase1");
      if (blocks.length === 0) return { satisfied: false };
      const offenders: string[] = [];
      let total = 0;
      for (const block of blocks) {
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
      if (total === 0) {
        return { satisfied: false, evidence: getBlockSnippet(index, blocks[0]) };
      }
      if (offenders.length === 0) {
        return { satisfied: true, evidence: total ? `Alle ${total} IPsec phase1 entries voldoen.` : "" };
      }
      const preview = offenders.slice(0, 2).join("\n\n");
      const evidence = [`Afwijkingen: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
      return { satisfied: false, evidence };
    },
  },
  ipsec_phase_2_op_basis_van_0_0_0_0_0_routes: {
    id: "ipsec_phase_2_op_basis_van_0_0_0_0_0_routes",
    label: "IPsec phase 2 op basis van 0.0.0.0/0 routes",
    run: (index) => {
      const block = findBlock(index, "config vpn ipsec phase2-interface");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      for (const entry of entries) {
        if (entry.lines.join("\n").includes("0.0.0.0 0.0.0.0")) {
          return { satisfied: true, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: false, evidence: getBlockSnippet(index, block) };
    },
  },
  ipsec_static_blackhole_routes: {
    id: "ipsec_static_blackhole_routes",
    label: "IPsec Static Blackhole routes",
    run: (index) => {
      const block = findBlock(index, "config router static");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      if (entries.length === 0) return { satisfied: false, evidence: getBlockSnippet(index, block) };

      const blackholeByDst = new Map<string, boolean>();
      const badBlackholes: string[] = [];

      const getDst = (lines: string[]) => {
        const dstLine = lines.find((line) => line.trim().startsWith("set dstaddr")) ??
          lines.find((line) => line.trim().startsWith("set dst "));
        if (!dstLine) return null;
        return dstLine.split(/\s+/).slice(2).join(" ").replace(/\"/g, "").trim();
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
        return { satisfied: true, evidence: getBlockSnippet(index, block) };
      }

      const preview = [...missing, ...badBlackholes].slice(0, 2).join("\n\n");
      const evidence = [
        missing.length ? `Missende blackhole routes: ${missing.length}` : "",
        badBlackholes.length ? `Blackhole distance niet 254: ${badBlackholes.length}` : "",
        preview,
      ]
        .filter(Boolean)
        .join("\n\n");

      return { satisfied: false, evidence };
    },
  },
  system_dns_1_1_1_1_8_8_8_8_doh: {
    id: "system_dns_1_1_1_1_8_8_8_8_doh",
    label: "System DNS 1.1.1.1/8.8.8.8 DoH",
    run: (index) => {
      const block = findBlock(index, "config system dns");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const hasPrimary = text.includes("set primary 1.1.1.1");
      const hasSecondary = text.includes("set secondary 8.8.8.8");
      const hasProtocol = text.includes("set protocol doh");
      return {
        satisfied: hasPrimary && hasSecondary && hasProtocol,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ssl_vpn_lookback: {
    id: "ssl_vpn_lookback",
    label: "SSL-VPN lookback",
    run: (index) => {
      const block = findBlock(index, "config system interface");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      const entry = entries.find((item) => item.name.toLowerCase() === "sslvpn_loopback" || item.name === "SSLVPN_Loopback");
      if (!entry) {
        return { satisfied: false, evidence: getBlockSnippet(index, block) };
      }
      const text = entry.lines.join("\n").toLowerCase();
      const hasType = text.includes("set type loopback");
      const hasIp = /set ip\s+192\.168\.192\.168\s+255\.255\.255\.255/i.test(text);
      const hasAllow = text.includes("set allowaccess ping");
      const hasRole = text.includes("set role lan");
      const hasDescription = text.includes("symbis default v1");
      const satisfied = hasType && hasIp && hasAllow && hasRole && hasDescription;
      return {
        satisfied,
        evidence: entry.lines.join("\n"),
      };
    },
  },
  ssl_vpn_symbis_via_entraid: {
    id: "ssl_vpn_symbis_via_entraid",
    label: "SSL-VPN Symbis via EntraID",
    run: (index) => {
      const block = findBlock(index, "config user saml");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      for (const entry of entries) {
        const text = entry.lines.join("\n").toLowerCase();
        const hasEntity = text.includes(SYMBIS_ENTRA_ENTITY_ID.toLowerCase());
        const hasSso = text.includes(`login.microsoftonline.com/${SYMBIS_ENTRA_TENANT_ID}/saml2`);
        const hasUser = text.includes("set user-name");
        if (hasEntity && hasSso && hasUser) {
          return { satisfied: true, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: false, evidence: getBlockSnippet(index, block) };
    },
  },
  uitsluitend_ldaps_gebruik: {
    id: "uitsluitend_ldaps_gebruik",
    label: "Uitsluitend LDAPS gebruik",
    run: (index) => {
      const block = findBlock(index, "config user ldap");
      if (!block) return { satisfied: true };
      const entries = parseEdits(block);
      if (entries.length === 0) return { satisfied: true, evidence: getBlockSnippet(index, block) };
      for (const entry of entries) {
        const text = entry.lines.join("\n").toLowerCase();
        if (text.includes("set server-identity-check disable")) {
          return { satisfied: false, evidence: entry.lines.join("\n") };
        }
        const hasSecure =
          text.includes("set secure ldaps") ||
          text.includes("set secure starttls") ||
          text.includes("ldaps://") ||
          text.includes("set port 636");
        if (!hasSecure) return { satisfied: false, evidence: entry.lines.join("\n") };
      }
      return { satisfied: true, evidence: getBlockSnippet(index, block) };
    },
  },
  uitsluitend_radius_ms_chap_v2: {
    id: "uitsluitend_radius_ms_chap_v2",
    label: "Uitsluitend RADIUS MS-CHAP-v2",
    run: (index) => {
      const block = findBlock(index, "config user radius");
      if (!block) return { satisfied: true };
      const entries = parseEdits(block);
      if (entries.length === 0) return { satisfied: true, evidence: getBlockSnippet(index, block) };
      for (const entry of entries) {
        const text = entry.lines.join("\n").toLowerCase();
        if (!text.includes("set auth-type ms_chap_v2") && !text.includes("set auth-type mschapv2")) {
          return { satisfied: false, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: true, evidence: getBlockSnippet(index, block) };
    },
  },
  geen_local_users: {
    id: "geen_local_users",
    label: "Geen local users",
    run: (index) => {
      const block = findBlock(index, "config user local");
      if (!block) return { satisfied: true };
      const entries = parseEdits(block);
      const nonGuest = entries.filter((entry) => entry.name.toLowerCase() !== "guest");
      return {
        satisfied: nonGuest.length === 0,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ssl_vpn_dns: {
    id: "ssl_vpn_dns",
    label: "SSL-VPN DNS",
    run: (index) => {
      const block = findBlock(index, "config vpn ssl settings");
      const match = findInBlock(index, block, /set dns-server\\d+/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ssl_vpn_cipher_suites: {
    id: "ssl_vpn_cipher_suites",
    label: "SSL-VPN cipher suites",
    run: (index) => {
      const block = findBlock(index, "config vpn ssl settings");
      if (!block) return { satisfied: false };
      const line = block.lines.find((item) => item.toLowerCase().includes("set banned-cipher"));
      const satisfied =
        !!line &&
        ["rsa", "dhe", "sha1", "sha256", "sha384", "aria"].every((token) => line.toLowerCase().includes(token));
      return {
        satisfied,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ssl_vpn_timeout_10_uur: {
    id: "ssl_vpn_timeout_10_uur",
    label: "SSL-VPN timeout 10 uur",
    run: (index) => {
      const block = findBlock(index, "config vpn ssl settings");
      const match = findInBlock(index, block, /set auth-timeout 36000/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  system_chipers: {
    id: "system_chipers",
    label: "System chipers",
    run: (index) => {
      const block = findBlock(index, "config system global");
      if (!block) return { satisfied: false };
      const line = block.lines.find((item) => item.toLowerCase().includes("admin-https-ssl-banned-cipher"));
      const satisfied =
        !!line &&
        ["rsa", "dhe", "sha1", "sha256", "sha384", "aria"].every((token) => line.toLowerCase().includes(token));
      return {
        satisfied,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  enforce_default_port_app_control: {
    id: "enforce_default_port_app_control",
    label: "Enforce Default Port App control",
    run: (index) => {
      const block = findBlock(index, "config application list");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      for (const entry of entries) {
        if (entry.name === "symbis-default-port") {
          const ok = entry.lines.join("\n").toLowerCase().includes("set enforce-default-app-port enable");
          return { satisfied: ok, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: false, evidence: getBlockSnippet(index, block) };
    },
  },
  firewall_policys_logtraffic_start_disabled: {
    id: "firewall_policys_logtraffic_start_disabled",
    label: "Firewall policys logtraffic-start disabled",
    run: (index) => {
      const entries = parseFirewallPolicyEdits(index);
      const offenders = entries.filter((entry) =>
        entry.lines.some((line) => /^set logtraffic-start\s+enable/i.test(line.trim()))
      );
      if (offenders.length === 0) {
        return { satisfied: true, evidence: getBlockSnippet(index, getPolicyBlock(index)) };
      }
      const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
      const evidence = [`logtraffic-start enable policies: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
      return {
        satisfied: false,
        evidence,
      };
    },
  },
  op_2gb_models_ips_cp_accel_mode_none: {
    id: "op_2gb_models_ips_cp_accel_mode_none",
    label: "Op 2GB models IPS cp-accel-mode none",
    run: (index) => {
      const header = parseConfigHeader(index.text);
      const normalizedModel = normalizeModelName(header.model);
      if (!normalizedModel || !LOW_END_MODELS.has(normalizedModel)) {
        return {
          satisfied: false,
          skip: true,
          note: normalizedModel ? `Niet 2GB model (${normalizedModel})` : "Model onbekend",
        };
      }
      const block = findBlock(index, "config ips global");
      const match = findInBlock(index, block, /set cp-accel-mode none/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  all_service_wordt_niet_gebruikt_in_firewall_policys: {
    id: "all_service_wordt_niet_gebruikt_in_firewall_policys",
    label: "ALL service wordt niet gebruikt in firewall policys",
    run: (index) => {
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
        return { satisfied: true, evidence: getBlockSnippet(index, getPolicyBlock(index)) };
      }

      const preview = offenders.slice(0, 3).map((entry) => entry.lines.join("\n")).join("\n\n");
      const evidence = [`ALL accept policies: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
      return {
        satisfied: false,
        evidence,
      };
    },
  },
  all_service_is_rood: {
    id: "all_service_is_rood",
    label: "ALL service is rood",
    run: (index) => {
      const block = findBlock(index, "config firewall service custom");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      const entry = entries.find((item) => item.name.toUpperCase() === "ALL");
      if (!entry) return { satisfied: false, evidence: getBlockSnippet(index, block) };
      const hasColor = entry.lines.some((line) => /^set color\s+6$/i.test(line.trim()));
      return {
        satisfied: hasColor,
        evidence: entry.lines.join("\n"),
      };
    },
  },
  symbis_objecten_toegepast_waar_mogelijk: {
    id: "symbis_objecten_toegepast_waar_mogelijk",
    label: "Symbis objecten toegepast waar mogelijk",
    run: (index) => {
      const text = index.textLower;
      const count = SYMBIS_OBJECT_SENTINELS.filter((token) => text.includes(token)).length;
      const satisfied = count >= 3 || text.includes("symbis default");
      return {
        satisfied,
        evidence: satisfied ? "" : "",
      };
    },
  },
  quic_protocol_is_niet_toegestaan: {
    id: "quic_protocol_is_niet_toegestaan",
    label: "QUIC protocol is niet toegestaan",
    run: (index) => {
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
        return { satisfied: true, evidence: getBlockSnippet(index, getPolicyBlock(index)) };
      }
      const preview = offenders.slice(0, 2).map((entry) => entry.lines.join("\n")).join("\n\n");
      const evidence = [`QUIC accept policies: ${offenders.length}`, preview].filter(Boolean).join("\n\n");
      return {
        satisfied: false,
        evidence,
      };
    },
  },
  services_in_firewall_policys_zijn_niet_gestappeld: {
    id: "services_in_firewall_policys_zijn_niet_gestappeld",
    label: "Services in firewall policys zijn niet gestappeld",
    run: (index) => {
      const entries = parseFirewallPolicyEdits(index);
      for (const entry of entries) {
        const serviceLine = entry.lines.find((line) => line.trim().startsWith("set service"));
        if (serviceLine) {
          const tokens = parseServiceTokens(serviceLine);
          if (tokens.length > 7) {
            const evidence = `Services count: ${tokens.length}\n${entry.lines.join("\n")}`;
            return { satisfied: false, evidence };
          }
        }
      }
      return { satisfied: true, evidence: getBlockSnippet(index, getPolicyBlock(index)) };
    },
  },
  local_in_policy_v7: {
    id: "local_in_policy_v7",
    label: "local-in-policy v7",
    run: (index) => {
      const block = getLocalInBlock(index);
      if (!block) return { satisfied: false };
      const hasEdit = block.lines.some((line) => line.trim().startsWith("edit "));
      return {
        satisfied: hasEdit,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  virtual_patch_local_in: {
    id: "virtual_patch_local_in",
    label: "virtual-patch local-in",
    run: (index) => {
      const block = getLocalInBlock(index);
      const match = findInBlock(index, block, /set virtual-patch enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  auto_revision_config: {
    id: "auto_revision_config",
    label: "Auto revision config",
    run: (index) => {
      const block = findBlock(index, "config system global");
      const match = findInBlock(index, block, /set revision-backup-on-logout enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  workflow_management_ingeschakeld: {
    id: "workflow_management_ingeschakeld",
    label: "Workflow Management ingeschakeld",
    run: (index) => {
      const block = findBlock(index, "config system global");
      const match = findInBlock(index, block, /set gui-workflow-management enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  standaard_objecten_aanwezig_v29: {
    id: "standaard_objecten_aanwezig_v29",
    label: "Standaard objecten aanwezig v29",
    run: (index) => {
      const text = index.textLower;
      const count = SYMBIS_OBJECT_SENTINELS.filter((token) => text.includes(token)).length;
      return {
        satisfied: count >= 3,
        evidence: "",
      };
    },
  },
  ssl_labs_object_is_v2: {
    id: "ssl_labs_object_is_v2",
    label: "SSL Labs object is v2",
    run: (index) => {
      const match = findFirstMatch(index, /edit \"s-qualys_ssl_labs\"/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  fortiguard_ntp: {
    id: "fortiguard_ntp",
    label: "FortiGuard NTP",
    run: (index) => {
      const block = findBlock(index, "config system ntp");
      const match = findInBlock(index, block, /set ntpsync enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  fortilink_beschikbaar_en_gekoppeld_aan_ntp_interface: {
    id: "fortilink_beschikbaar_en_gekoppeld_aan_ntp_interface",
    label: "FortiLink beschikbaar en gekoppeld aan NTP interface",
    run: (index) => {
      const interfaceBlock = findBlock(index, "config system interface");
      const ntpBlock = findBlock(index, "config system ntp");
      const hasFortiLink = blockHasTokens(interfaceBlock, ['edit "fortilink"']);
      const ntpHasFortiLink = ntpBlock?.lines.join("\n").toLowerCase().includes('set interface "fortilink"');
      return {
        satisfied: hasFortiLink && !!ntpHasFortiLink,
        evidence: getBlockSnippet(index, ntpBlock ?? interfaceBlock),
      };
    },
  },
  fortilink_tunnel_mode_is_moderate: {
    id: "fortilink_tunnel_mode_is_moderate",
    label: "FortiLink tunnel-mode is moderate",
    run: (index) => {
      const block = findBlock(index, "config switch-controller system");
      const match = findInBlock(index, block, /set tunnel-mode moderate/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  snmp_v3: {
    id: "snmp_v3",
    label: "SNMP v3",
    run: (index) => {
      const block = findBlock(index, "config system snmp user");
      const match = block || index.textLower.includes("set security-level");
      return {
        satisfied: !!match,
        evidence: block ? getBlockSnippet(index, block) : "",
      };
    },
  },
  certificaat_path_volledig_remote_ca_correct_installed: {
    id: "certificaat_path_volledig_remote_ca_correct_installed",
    label: "Certificaat path volledig (remote CA correct installed)",
    run: (index) => {
      const block = findBlock(index, "config vpn certificate ca");
      if (!block) return { satisfied: false };
      const hasEdit = block.lines.some((line) => line.trim().startsWith("edit "));
      return {
        satisfied: hasEdit,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  administrative_access_less_is_more: {
    id: "administrative_access_less_is_more",
    label: "Administrative Access (less is more)",
    run: (index) => {
      const block = findBlock(index, "config system interface");
      if (!block) return { satisfied: true };
      const badLine = block.lines.find((line) => {
        const lower = line.toLowerCase();
        if (!lower.includes("set allowaccess")) return false;
        return lower.includes("telnet") || (lower.includes(" http") && !lower.includes(" https"));
      });
      return {
        satisfied: !badLine,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  interface_alias_ingevuld: {
    id: "interface_alias_ingevuld",
    label: "interface alias ingevuld",
    run: (index) => {
      const entries = parseInterfaceEdits(index);
      const physical = entries.filter((entry) =>
        entry.lines.some((line) => line.trim().startsWith("set type physical"))
      );
      if (physical.length === 0) return { satisfied: true };
      for (const entry of physical) {
        const hasAlias = entry.lines.some((line) => line.trim().startsWith("set alias"));
        if (!hasAlias) {
          return { satisfied: false, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: true, evidence: "" };
    },
  },
  interface_role_gedefineerd: {
    id: "interface_role_gedefineerd",
    label: "interface role gedefineerd",
    run: (index) => {
      const entries = parseInterfaceEdits(index);
      const physical = entries.filter((entry) =>
        entry.lines.some((line) => line.trim().startsWith("set type physical"))
      );
      if (physical.length === 0) return { satisfied: true };
      for (const entry of physical) {
        const hasRole = entry.lines.some((line) => line.trim().startsWith("set role "));
        if (!hasRole) {
          return { satisfied: false, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: true, evidence: "" };
    },
  },
  estimated_bandwidth_wan: {
    id: "estimated_bandwidth_wan",
    label: "Estimated bandwidth WAN",
    run: (index) => {
      const entries = parseInterfaceEdits(index);
      const wanEntries = entries.filter((entry) =>
        entry.lines.some((line) => line.toLowerCase().includes("set role wan"))
      );
      if (wanEntries.length === 0) return { satisfied: false };
      for (const entry of wanEntries) {
        const hasUp = entry.lines.some((line) => line.trim().startsWith("set estimated-upstream-bandwidth"));
        const hasDown = entry.lines.some((line) => line.trim().startsWith("set estimated-downstream-bandwidth"));
        if (!hasUp || !hasDown) {
          return { satisfied: false, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: true, evidence: "" };
    },
  },
  sd_wan_performance_sla_min_ping: {
    id: "sd_wan_performance_sla_min_ping",
    label: "SD-WAN Performance SLA min. PING",
    run: (index) => {
      const block = findBlock(index, "config system sdwan");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const required = [
        'config health-check',
        'edit "cloudflare_google"',
        'set server "1.1.1.1" "8.8.8.8"',
        "set members 0",
        "config sla",
        "set latency-threshold 50",
        "set jitter-threshold 30",
        "set packetloss-threshold 1",
      ];
      const satisfied = required.every((token) => text.includes(token));
      return {
        satisfied,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  default_route_is_sd_wan_zone: {
    id: "default_route_is_sd_wan_zone",
    label: "Default route is SD-WAN zone",
    run: (index) => {
      const sdwan = findBlock(index, "config system sdwan");
      const sdwanEnabled = sdwan ? sdwan.lines.join("\n").toLowerCase().includes("set status enable") : false;
      const block = findBlock(index, "config router static");
      const evidence = getBlockSnippet(index, block);
      if (!sdwanEnabled) {
        return { satisfied: false, skip: true, note: "SD-WAN niet actief", evidence };
      }
      const match = findInBlock(index, block, /set (device|sdwan-zone) \"virtual-wan-link\"/i);
      return {
        satisfied: !!match,
        evidence,
      };
    },
  },
  policy_met_vips_is_match_vip_enabled: {
    id: "policy_met_vips_is_match_vip_enabled",
    label: "Policy met VIPs is match-vip enabled",
    run: (index) => {
      const match = findFirstMatch(index, /set match-vip enable/i);
      return {
        satisfied: !match,
        evidence: match?.snippet,
      };
    },
  },
  uitgaande_malicious_block_v2: {
    id: "uitgaande_malicious_block_v2",
    label: "Uitgaande malicious block v2",
    run: (index) => {
      const entries = parseFirewallPolicyEdits(index);
      const required = new Set(REQUIRED_MALICIOUS_SERVICES.map((item) => item.toLowerCase()));
      const srcCoverage = new Map<string, boolean>();
      const offenders: string[] = [];

      const parseQuoted = (line: string) => {
        const matches = line.match(/\"([^\"]+)\"/g);
        if (matches && matches.length > 0) {
          return matches.map((match) => match.replace(/\"/g, ""));
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
        if (isDeny && hasAllServices) {
          for (const src of srcTokens) {
            srcCoverage.set(src, true);
          }
        } else {
          offenders.push(entry.lines.join("\n"));
        }
      }

      const missingSrc = [...srcCoverage.entries()].filter(([, ok]) => !ok).map(([src]) => src);
      if (missingSrc.length === 0 && offenders.length === 0 && srcCoverage.size > 0) {
        return { satisfied: true, evidence: "" };
      }

      const evidenceParts = [];
      if (srcCoverage.size === 0) {
        evidenceParts.push("Geen policies gevonden met dstintf \"virtual-wan-link\".");
      }
      if (missingSrc.length > 0) {
        evidenceParts.push(`Geen Malicious_deny voor: ${missingSrc.join(", ")}`);
      }
      if (offenders.length > 0) {
        evidenceParts.push(offenders.slice(0, 2).join("\n\n"));
      }

      return {
        satisfied: false,
        evidence: evidenceParts.filter(Boolean).join("\n\n"),
      };
    },
  },
  password_policy_op_admin_en_ipsec: {
    id: "password_policy_op_admin_en_ipsec",
    label: "Password policy op Admin en IPsec",
    run: (index) => {
      const block = findBlock(index, "config system password-policy");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const hasStatus = text.includes("set status enable");
      const apply = text.includes("set apply-to") && text.includes("admin-password") && text.includes("ipsec");
      return {
        satisfied: hasStatus && apply,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  idle_timeout_max_15_min: {
    id: "idle_timeout_max_15_min",
    label: "Idle timeout max 15 min",
    run: (index) => {
      const block = findBlock(index, "config system global");
      if (!block) return { satisfied: false };
      const line = block.lines.find((item) => item.trim().startsWith("set admintimeout"));
      if (!line) return { satisfied: false, evidence: getBlockSnippet(index, block) };
      const value = Number(line.trim().split(/\s+/).pop());
      return {
        satisfied: Number.isFinite(value) && value <= 15,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  webfilter_override: {
    id: "webfilter_override",
    label: "Webfilter override",
    run: (index) => {
      const block = findBlock(index, "config webfilter ftgd-local-cat");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      return {
        satisfied: text.includes('edit \"allow\"') && text.includes('edit \"block\"'),
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  fortigate_mgmt_policy_rule: {
    id: "fortigate_mgmt_policy_rule",
    label: "FortiGate MGMT policy rule",
    run: (index) => {
      const block = getLocalInBlock(index);
      if (!block) return { satisfied: false };
      const match = findInBlock(index, block, /set action deny/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  symbis_utm_profiles_v7: {
    id: "symbis_utm_profiles_v7",
    label: "Symbis UTM profiles v7",
    run: (index) => {
      const entries = parseFirewallPolicyEdits(index);
      const deviations: string[] = [];

      const getPolicyLabel = (entry: (typeof entries)[number]) => {
        const nameLine = entry.lines.find((line) => line.trim().startsWith("set name"));
        const name = nameLine ? nameLine.split(/\s+/).slice(2).join(" ").replace(/\"/g, "").trim() : "";
        return name ? `${entry.name} (${name})` : entry.name;
      };

      const getValue = (line: string) => {
        const tokens = parseQuotedTokens(line);
        return tokens.join(" ").replace(/\"/g, "").trim();
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
        return { satisfied: true, evidence: "" };
      }

      const preview = deviations.slice(0, 6).join("\n");
      return {
        satisfied: false,
        evidence: preview,
      };
    },
  },
  symbis_certificate_inspection: {
    id: "symbis_certificate_inspection",
    label: "Symbis certificate-inspection",
    run: (index) => {
      const block = findBlock(index, "config firewall ssl-ssh-profile");
      const hasSymbisProfile = blockHasTokens(block, ['edit "symbis-certificate-inspection"']);

      const offenders: string[] = [];
      const entries = parseFirewallPolicyEdits(index);
      for (const entry of entries) {
        const profileLine = entry.lines.find((line) => line.trim().startsWith("set ssl-ssh-profile"));
        if (!profileLine) continue;
        const value = parseQuotedTokens(profileLine).join(" ").replace(/\"/g, "").trim();
        const normalized = value.toLowerCase();
        if (!ALLOWED_SSL_SSH_PROFILES.has(normalized)) {
          offenders.push(`${entry.name}: ssl-ssh-profile "${value}"`);
        }
      }

      if (offenders.length > 0) {
        const preview = offenders.slice(0, 6).join("\n");
        return { satisfied: false, evidence: preview };
      }

      return {
        satisfied: hasSymbisProfile,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  automation_stitches_v13: {
    id: "automation_stitches_v13",
    label: "Automation stitches v13",
    run: (index) => {
      const block = findBlock(index, "config system automation-stitch");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const hasSftp = text.includes('edit \"sftp config backup\"');
      return {
        satisfied: hasSftp,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  deep_inspection_uitgaand: {
    id: "deep_inspection_uitgaand",
    label: "Deep Inspection (uitgaand)",
    run: (index) => {
      const match = findFirstMatch(index, /deep-inspection/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  internet_services_policy_v4: {
    id: "internet_services_policy_v4",
    label: "Internet Services policy (v4)",
    run: (index) => {
      const match = findFirstMatch(index, /set internet-service enable/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  geo_ip_blocking: {
    id: "geo_ip_blocking",
    label: "Geo-IP blocking",
    run: (index) => {
      const match = findFirstMatch(index, /set type geography/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  global_black_en_whitelist_github: {
    id: "global_black_en_whitelist_github",
    label: "Global black en whitelist (Github)",
    run: (index) => {
      const external = findBlock(index, "config system external-resource");
      if (!external) return { satisfied: false };
      const externalText = external.lines.join("\n").toLowerCase();
      const hasGithub = externalText.includes("raw.githubusercontent.com/symbis/public/main/fortigate/");
      const hasBlocklist = externalText.includes('edit "symbis-dns-blocklist"') &&
        externalText.includes('edit "symbis-webfilter-blocklist"');
      const hasAllowlist = externalText.includes('edit "symbis-dns-allowlist"') &&
        externalText.includes('edit "symbis-webfilter-allowlist"');

      const dnsBlock = findBlock(index, "config dnsfilter profile");
      const webBlock = findBlock(index, "config webfilter profile");
      const dnsText = dnsBlock?.lines.join("\n").toLowerCase() ?? "";
      const webText = webBlock?.lines.join("\n").toLowerCase() ?? "";

      const hasDnsBlock = /set category\s+192[\s\S]{0,120}set action\s+block/i.test(dnsText);
      const hasWebBlock = /set category\s+194[\s\S]{0,120}set action\s+block/i.test(webText);
      const hasAllowOnLists =
        /set category\s+193[\s\S]{0,120}set action\s+allow/i.test(dnsText) ||
        /set category\s+195[\s\S]{0,120}set action\s+allow/i.test(webText);

      const satisfied = hasGithub && hasBlocklist && hasAllowlist && hasDnsBlock && hasWebBlock && !hasAllowOnLists;

      return {
        satisfied,
        evidence: satisfied ? "" : getBlockSnippet(index, external),
      };
    },
  },
  ssl_vpn_password_safe_off: {
    id: "ssl_vpn_password_safe_off",
    label: "SSL-VPN password safe off",
    run: (index) => {
      const enable = /set (save-password|password-save|safe-password) enable/i.test(index.text);
      const disable = /set (save-password|password-save|safe-password) disable/i.test(index.text);
      return {
        satisfied: disable && !enable,
        evidence: disable ? "" : "",
      };
    },
  },
  ssl_vpn_geldig_certificaat: {
    id: "ssl_vpn_geldig_certificaat",
    label: "SSL-VPN geldig certificaat",
    run: (index) => {
      const block = findBlock(index, "config vpn ssl settings");
      if (!block) return { satisfied: false };
      const line = block.lines.find((item) => item.trim().startsWith("set servercert"));
      if (!line) return { satisfied: false, evidence: getBlockSnippet(index, block) };
      const value = line.split(/\s+/).slice(2).join(" ").replace(/\"/g, "").trim();
      const satisfied = value !== "" && value !== "''" && value.toLowerCase() !== "fortinet_factory";
      return {
        satisfied,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  central_management_ingeschakeld: {
    id: "central_management_ingeschakeld",
    label: "Central Management ingeschakeld",
    run: (index) => {
      const block = findBlock(index, "config system central-management");
      if (!block) return { satisfied: false };
      const text = block.lines.join("\n").toLowerCase();
      const hasType =
        text.includes("set type fortiguard") ||
        text.includes("set type fortimanager") ||
        text.includes("set type forticloud") ||
        text.includes("set type faz") ||
        text.includes("set type fmg");
      const enabled = hasType && !text.includes("set type none");
      return {
        satisfied: enabled,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  logging_naar_cloud_of_analyzer: {
    id: "logging_naar_cloud_of_analyzer",
    label: "Logging naar cloud of Analyzer",
    run: (index) => {
      const logBlocks = [
        findBlock(index, "config log fortiguard setting"),
        findBlock(index, "config log fortianalyzer setting"),
        findBlock(index, "config log fortianalyzer2 setting"),
      ].filter(Boolean) as FgBlock[];
      for (const block of logBlocks) {
        const text = block.lines.join("\n").toLowerCase();
        if (text.includes("set status enable") || text.includes("set upload-option")) {
          return { satisfied: true, evidence: getBlockSnippet(index, block) };
        }
      }
      return { satisfied: false, evidence: logBlocks[0] ? getBlockSnippet(index, logBlocks[0]) : "" };
    },
  },
  admin_vervangen_voor_adm_symbis: {
    id: "admin_vervangen_voor_adm_symbis",
    label: "admin vervangen voor adm-symbis",
    run: (index) => {
      const block = findBlock(index, "config system admin");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      const adminEntries = entries.filter((entry) => entry.name.toLowerCase() === "admin");
      const hasAdmSymbis = entries.some((entry) => entry.name.toLowerCase() === "adm-symbis");

      if (adminEntries.length > 0) {
        const preview = adminEntries.map((entry) => entry.lines.join("\n")).join("\n\n");
        return { satisfied: false, evidence: preview };
      }

      return {
        satisfied: hasAdmSymbis,
        evidence: hasAdmSymbis ? "" : getBlockSnippet(index, block),
      };
    },
  },
};

export function getCheckDefinition(id: string): CheckDefinition | null {
  if (MANUAL_CHECKS.has(id)) {
    return {
      id,
      label: id,
      manual: true,
      manualNote: MANUAL_NOTES[id] ?? "Handmatig controleren",
      run: () => ({ satisfied: false }),
    };
  }
  const check = CHECKS[id];
  if (check) return check;
  return null;
}

export function evaluateChecks(
  confText: string,
  columns: { id: string; label: string; isCheck: boolean }[],
  values: Record<string, string>
) {
  const index = createConfigIndex(confText);
  return columns
    .filter((col) => col.isCheck)
    .map((col) => {
      const expected = (values[col.id] ?? "").trim();
      const expectedNormalized = expected.toLowerCase();
      const expectSatisfied =
        expectedNormalized === "x" ||
        expectedNormalized === "xv" ||
        expectedNormalized === "vx" ||
        expectedNormalized.startsWith("x ") ||
        expectedNormalized.startsWith("x(");
      const def = getCheckDefinition(col.id);
      if (!expected && IGNORE_WHEN_EMPTY.has(col.id)) {
        return {
          id: col.id,
          label: col.label,
          expected,
          status: "manual",
          satisfied: false,
          evidence: "",
          note: "Baseline leeg - check overgeslagen",
        };
      }
      if (!def || def.manual) {
        return {
          id: col.id,
          label: col.label,
          expected,
          status: "manual",
          satisfied: false,
          evidence: "",
          note: def?.manual ? def.manualNote ?? "Handmatig controleren" : "Geen check gedefinieerd",
        };
      }

      const result = def.run(index);
      if (result.skip) {
        return {
          id: col.id,
          label: col.label,
          expected,
          status: "manual",
          satisfied: false,
          evidence: result.evidence ?? "",
          note: result.note ?? "Overgeslagen",
        };
      }
      const matches = expectSatisfied ? result.satisfied : !result.satisfied;
      return {
        id: col.id,
        label: col.label,
        expected,
        status: matches ? "pass" : "fail",
        satisfied: result.satisfied,
        evidence: result.evidence ?? "",
        note: result.note ?? "",
      };
    });
}
