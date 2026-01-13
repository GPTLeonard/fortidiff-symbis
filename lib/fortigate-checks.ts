import {
  type ConfigIndex,
  type FgBlock,
  createConfigIndex,
  findBlock,
  findLineIndex,
  getBlockSnippet,
  makeSnippet,
  parseEdits,
} from "@/lib/fortigate";

export type CheckResult = {
  satisfied: boolean;
  evidence?: string;
  note?: string;
};

export type CheckDefinition = {
  id: string;
  label: string;
  manual?: boolean;
  run: (index: ConfigIndex) => CheckResult;
};

type Match = {
  index: number;
  snippet: string;
};

const TOKEN_MATCHES = [
  "botnet-c&c.server",
  "hosting-bulletproof.hosting",
  "malicious-malicious.server",
  "phishing-phishing.server",
  "proxy-proxy.server",
  "tor-exit.node",
  "tor-relay.node",
  "vpn-anonymous.vpn",
];

const SYMBIS_OBJECT_SENTINELS = [
  'edit "s-apple_inc."',
  'edit "s-wildcard.teamviewer.com"',
  'edit "s-european_union"',
  'edit "s-qualys_ssl_labs"',
];

const MANUAL_CHECKS = new Set([
  "dns_service_on_interface_staat_voor_guest_naar_system_dns",
  "interne_zone_uitgezonderd_in_het_dns_filter",
  "alle_firewall_policys_0_bytes_controle",
  "implicit_deny_dns_ntp_en_utm_log_gecontroleerd",
  "all_service_is_rood",
  "naamgeving_policys",
  "server_protecting_actief_op_vips",
  "malicious_block_op_vips_v3",
  "alle_certificaten_zijn_geldig_valid",
  "devices_in_fabric_zijn_registered",
  "workflow_management_ingeschakeld",
  "itboost_bijgewerkt",
  "bitwarden_bijgewerkt_en_opgeschoond",
]);

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

function parseLocalInEdits(index: ConfigIndex): ReturnType<typeof parseEdits> {
  const block = getLocalInBlock(index);
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
      const match = findInBlock(index, block, /set auto-firmware-upgrade enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ha_session_pickup: {
    id: "ha_session_pickup",
    label: "HA session pickup",
    run: (index) => {
      const block = findBlock(index, "config system ha");
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
      if (!block) return { satisfied: true };
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
      const block = findBlock(index, "config vpn ipsec phase1-interface");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      for (const entry of entries) {
        const text = entry.lines.join("\n").toLowerCase();
        if (text.includes("aes256gcm-prfsha384") && text.includes("set dhgrp 20")) {
          return { satisfied: true, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: false, evidence: getBlockSnippet(index, block) };
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
      const match = findInBlock(index, block, /set blackhole enable/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
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
      const match = blockHasTokens(block, ['edit "sslvpn_loopback"']);
      return {
        satisfied: match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  ssl_vpn_symbis_via_entraid: {
    id: "ssl_vpn_symbis_via_entraid",
    label: "SSL-VPN Symbis via EntraID",
    run: (index) => {
      const block = findBlock(index, "config user saml");
      const text = block?.lines.join("\n").toLowerCase() ?? "";
      const hasSts = text.includes("sts.windows.net");
      const hasUser = text.includes("set user-name");
      return {
        satisfied: hasSts && hasUser,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  uitsluitend_ldaps_gebruik: {
    id: "uitsluitend_ldaps_gebruik",
    label: "Uitsluitend LDAPS gebruik",
    run: (index) => {
      const block = findBlock(index, "config user ldap");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      if (entries.length === 0) return { satisfied: false, evidence: getBlockSnippet(index, block) };
      for (const entry of entries) {
        const text = entry.lines.join("\n").toLowerCase();
        const hasLdaps = text.includes("set secure ldaps") || text.includes("ldaps://") || text.includes("set port 636");
        if (!hasLdaps) {
          return { satisfied: false, evidence: entry.lines.join("\n") };
        }
      }
      return { satisfied: true, evidence: getBlockSnippet(index, block) };
    },
  },
  uitsluitend_radius_ms_chap_v2: {
    id: "uitsluitend_radius_ms_chap_v2",
    label: "Uitsluitend RADIUS MS-CHAP-v2",
    run: (index) => {
      const block = findBlock(index, "config user radius");
      if (!block) return { satisfied: false };
      const entries = parseEdits(block);
      if (entries.length === 0) return { satisfied: false, evidence: getBlockSnippet(index, block) };
      for (const entry of entries) {
        const text = entry.lines.join("\n").toLowerCase();
        if (!text.includes("set auth-type mschapv2")) {
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
      const block = getPolicyBlock(index);
      const match = findInBlock(index, block, /set logtraffic-start enable/i);
      return {
        satisfied: !match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  op_2gb_models_ips_cp_accel_mode_none: {
    id: "op_2gb_models_ips_cp_accel_mode_none",
    label: "Op 2GB models IPS cp-accel-mode none",
    run: (index) => {
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
      const block = getPolicyBlock(index);
      if (!block) return { satisfied: true };
      const lineMatch = findInBlock(index, block, /set service .*\\bALL\\b/i);
      return {
        satisfied: !lineMatch,
        evidence: getBlockSnippet(index, block),
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
      const block = getPolicyBlock(index);
      const match = findInBlock(index, block, /set service .*\\bQUIC\\b/i);
      return {
        satisfied: !match,
        evidence: getBlockSnippet(index, block),
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
          if (tokens.length > 1) {
            return { satisfied: false, evidence: entry.lines.join("\n") };
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
      const hasHealth = text.includes("config health-check") || text.includes("config performance-sla");
      const hasPing = text.includes("set protocol ping") || text.includes("set server");
      return {
        satisfied: hasHealth && hasPing,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  default_route_is_sd_wan_zone: {
    id: "default_route_is_sd_wan_zone",
    label: "Default route is SD-WAN zone",
    run: (index) => {
      const block = findBlock(index, "config router static");
      const match = findInBlock(index, block, /set device \"virtual-wan-link\"/i);
      return {
        satisfied: !!match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
  policy_met_vips_is_match_vip_enabled: {
    id: "policy_met_vips_is_match_vip_enabled",
    label: "Policy met VIPs is match-vip enabled",
    run: (index) => {
      const match = findFirstMatch(index, /set match-vip enable/i);
      return {
        satisfied: !!match,
        evidence: match?.snippet,
      };
    },
  },
  uitgaande_malicious_block_v2: {
    id: "uitgaande_malicious_block_v2",
    label: "Uitgaande malicious block v2",
    run: (index) => {
      const text = index.textLower;
      const hasAny = TOKEN_MATCHES.some((token) => text.includes(token));
      return {
        satisfied: hasAny,
        evidence: "",
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
      const web = findBlock(index, "config webfilter profile");
      const dns = findBlock(index, "config dnsfilter profile");
      const app = findBlock(index, "config application list");
      const webOk = web?.lines.join("\n").toLowerCase().includes('edit \"symbis\"');
      const dnsOk = dns?.lines.join("\n").toLowerCase().includes('edit \"symbis\"');
      const appOk = app?.lines.join("\n").toLowerCase().includes('edit \"symbis\"');
      return {
        satisfied: Boolean(webOk && dnsOk && appOk),
        evidence: "",
      };
    },
  },
  symbis_certificate_inspection: {
    id: "symbis_certificate_inspection",
    label: "Symbis certificate-inspection",
    run: (index) => {
      const block = findBlock(index, "config firewall ssl-ssh-profile");
      const match = blockHasTokens(block, ['edit "symbis-certificate-inspection"']);
      return {
        satisfied: match,
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
      const hasGithub = index.textLower.includes("raw.githubusercontent.com/symbis/public/main/fortigate/");
      return {
        satisfied: hasGithub,
        evidence: "",
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
      const enabled = text.includes("set type") && !text.includes("set type none");
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
      const match = block.lines.join("\n").toLowerCase().includes('edit \"adm-symbis\"');
      return {
        satisfied: match,
        evidence: getBlockSnippet(index, block),
      };
    },
  },
};

export function getCheckDefinition(id: string): CheckDefinition | null {
  const check = CHECKS[id];
  if (check) return check;
  if (MANUAL_CHECKS.has(id)) {
    return {
      id,
      label: id,
      manual: true,
      run: () => ({ satisfied: false }),
    };
  }
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
      if (!def || def.manual) {
        return {
          id: col.id,
          label: col.label,
          expected,
          status: "manual",
          satisfied: false,
          evidence: "",
          note: def?.manual ? "Handmatig controleren" : "Geen check gedefinieerd",
        };
      }

      const result = def.run(index);
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
