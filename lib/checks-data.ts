// Auto-generated from Configuratie check Symbis app FortiOS 7.4.x.xlsx and App/*.txt
// Do not edit manually.

export type ConfigCheckType =
  | "positive_statement"
  | "negative_statement"
  | "positive_block"
  | "negative_block"
  | "aggregation";

export type ConfigCheckDefinition = {
  id: string;
  name: string;
  type: ConfigCheckType;
  section: string | null;
  refFile?: string | null;
  reference?: string | null;
  note?: string | null;
};

export const checkDefinitions: ConfigCheckDefinition[] = [
  {
    "id": "auto_firmware_upgrade",
    "name": "Auto firmware upgrade",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_auto_update_v1.txt",
    "reference": "config system fortiguard\n    set auto-firmware-upgrade-delay 2\n    set auto-firmware-upgrade-start-hour 2\n    set auto-firmware-upgrade-end-hour 5\nend",
    "note": null
  },
  {
    "id": "auto_revision_config",
    "name": "Auto revision config",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_revision_backup_on_logout_v1.txt",
    "reference": "config system global\nset revision-backup-on-logout enable\nend",
    "note": null
  },
  {
    "id": "forticloud_sso_uitgeschakeld",
    "name": "FortiCloud SSO uitgeschakeld",
    "type": "negative_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_forticloud_single_sign-on_v1.txt",
    "reference": "config system global\n    set admin-forticloud-sso-login enable\nend",
    "note": null
  },
  {
    "id": "central_management_ingeschakeld",
    "name": "Central Management ingeschakeld",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_central-management_v1.txt",
    "reference": "config system central-management\n    set type fortimanager\nend\n\nof\n\nconfig system central-management\n    set type fortiguard\nend",
    "note": "Config bevat 2 voorbeelden, 1 van beide moet aanwezig zijn"
  },
  {
    "id": "workflow_management_ingeschakeld",
    "name": "Workflow Management ingeschakeld",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_workflow-management_v1.txt",
    "reference": "config system global\nset gui-workflow-management enable\nend",
    "note": null
  },
  {
    "id": "logging_naar_cloud_of_analyzer",
    "name": "Logging naar cloud of Analyzer",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_log_settings_v1.txt",
    "reference": "config log fortiguard setting\n    set status enable\n    set upload-option realtime\nend\n\nof\n\nconfig log fortianalyzer setting\n    set status enable\n    set upload-option realtime\nend",
    "note": "Config bevat 2 voorbeelden, 1 van beide moet aanwezig zijn"
  },
  {
    "id": "system_dns_1_1_1_1_8_8_8_8_doh",
    "name": "System DNS 1.1.1.1 / 8.8.8.8 (DoH)",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_dns_doh_cloudflare_google_v1.txt",
    "reference": "config system dns\n    set primary 1.1.1.1\n    set secondary 8.8.8.8\n    set protocol doh\n    set server-hostname \"cloudflare-dns.com\" \"dns.google\"\nend",
    "note": null
  },
  {
    "id": "system_ciphers",
    "name": "System ciphers",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_ciphers_v1.txt",
    "reference": "config system global\nset admin-https-ssl-banned-cipher RSA DHE SHA1 SHA256 SHA384 ARIA\nend",
    "note": null
  },
  {
    "id": "remote_timeout_120_sec",
    "name": "Remote timeout 60 sec",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_auth_remoteauthtimeout_v2.txt",
    "reference": "config system global\nset remoteauthtimeout 60\nend",
    "note": null
  },
  {
    "id": "idle_timeout_maximaal_15_minuten",
    "name": "Idle timeout maximaal 15 minuten",
    "type": "aggregation",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_timeout_v1.txt",
    "reference": "config system global\n    set admintimeout 15\nend",
    "note": "Alles hoger dan admintimeout 15 is een afwijking"
  },
  {
    "id": "system_saml_entra_id_symbis",
    "name": "System SAML Entra ID Symbis",
    "type": "positive_statement",
    "section": "SYSTEEM & GLOBAL SETTINGS",
    "refFile": "app_system_saml_v1.txt",
    "reference": "config system saml\nset status enable\nset idp-entity-id \"https://sts.windows.net/4f4b99f3-8fde-4ffa-8989-04680bb56aa7/\"\nset idp-single-sign-on-url \"https://login.microsoftonline.com/4f4b99f3-8fde-4ffa-8989-04680bb56aa7/saml2\"\nset idp-single-logout-url \"https://login.microsoftonline.com/4f4b99f3-8fde-4ffa-8989-04680bb56aa7/saml2\"\nend",
    "note": null
  },
  {
    "id": "interface_role_gedefinieerd",
    "name": "Interface role gedefinieerd",
    "type": "positive_statement",
    "section": "INTERFACES & BASIS NETWERK",
    "refFile": "app_interface_role_v1.txt",
    "reference": "config system interface\n    edit \"wan1\"\n        set role wan\n    next\nend",
    "note": null
  },
  {
    "id": "fortilink_beschikbaar_en_gekoppeld_aan_ntp_interface",
    "name": "FortiLink beschikbaar en gekoppeld aan NTP-interface",
    "type": "positive_statement",
    "section": "INTERFACES & BASIS NETWERK",
    "refFile": "app_system_ntp_v1.txt",
    "reference": "config system ntp\n    set ntpsync enable\n    set server-mode enable\n    set interface \"fortilink\"\nend",
    "note": "Interface kan naast \"fortilink\" meerdere objecten bevatten"
  },
  {
    "id": "sd_wan_performance_sla_minimum_ping",
    "name": "SD-WAN Performance SLA minimum PING",
    "type": "positive_statement",
    "section": "ROUTING & SD-WAN",
    "refFile": "app_sdwan_health-check_v1.txt",
    "reference": "config system sdwan\n    config health-check\n        edit \"Cloudflare_Google\"\n            set server \"1.1.1.1\" \"8.8.8.8\"\n            config sla\n                edit 1\n                    set latency-threshold 50\n                    set jitter-threshold 30\n                    set packetloss-threshold 1\n                next\n            end\n        next\n    end\nend",
    "note": null
  },
  {
    "id": "default_route_is_sd_wan_zone",
    "name": "Default route is SD-WAN zone",
    "type": "positive_statement",
    "section": "ROUTING & SD-WAN",
    "refFile": "app_sdwan_status_and_route_v1.txt",
    "reference": "config system sdwan\n    set status enable\n    config zone\n        edit \"virtual-wan-link\"\n        next\n    end\nend\n\nconfig router static\n    edit 1\n        set distance 1\n        set sdwan-zone \"virtual-wan-link\"\n    next\nend",
    "note": null
  },
  {
    "id": "ha_session_pickup",
    "name": "HA session pickup",
    "type": "positive_statement",
    "section": "HIGH AVAILABILITY",
    "refFile": "app_ha_session_pickup.txt",
    "reference": "config system ha\n    set session-pickup enable\nend",
    "note": "Afhankelijk van HA status"
  },
  {
    "id": "geen_verschil_in_ha_device_priority",
    "name": "Geen verschil in HA Device priority",
    "type": "positive_statement",
    "section": "HIGH AVAILABILITY",
    "refFile": null,
    "reference": null,
    "note": "Afhankelijk van HA status"
  },
  {
    "id": "uitsluitend_ldaps_gebruik",
    "name": "Uitsluitend LDAPS gebruik",
    "type": "positive_statement",
    "section": "AUTHENTICATIE & IDENTITY",
    "refFile": "app_secure_ldap_v1",
    "reference": "config user ldap\n    edit \"LDAP_server\"\n        set secure starttls\n    next\nend\n\nof\n\nconfig user ldap\n    edit \"LDAP_server\"\n        set secure ldaps\n    next\nend",
    "note": "Kan meerdere entries bevatten"
  },
  {
    "id": "ldap_server_identity_check",
    "name": "LDAP Server identity check",
    "type": "negative_statement",
    "section": "AUTHENTICATIE & IDENTITY",
    "refFile": "app_ldap_server_identity_check_v1.txt",
    "reference": "config user ldap\n    edit \"LDAP_server\"\n        set server-identity-check disable\n    next\nend",
    "note": null
  },
  {
    "id": "uitsluitend_radius_ms_chap_v2",
    "name": "Uitsluitend RADIUS MS-CHAP-v2",
    "type": "positive_statement",
    "section": "AUTHENTICATIE & IDENTITY",
    "refFile": "app_radius_ms-chap-v2_v1.txt",
    "reference": "config user radius\n    edit \"RADIUS server\"\n        set auth-type ms_chap_v2\n    next\nend",
    "note": "Kan meerdere entries bevatten"
  },
  {
    "id": "geen_local_users",
    "name": "Geen local users",
    "type": "positive_block",
    "section": "AUTHENTICATIE & IDENTITY",
    "refFile": "app_local_users_v1.txt",
    "reference": "config user local\n    edit \"guest\"\n        set status disable\n        set type password\n        set passwd FortinetPasswordMask\n    next\nend",
    "note": null
  },
  {
    "id": "symbis_certificate_inspection",
    "name": "Symbis certificate-inspection",
    "type": "aggregation",
    "section": "CERTIFICATEN & CRYPTOGRAFIE",
    "refFile": null,
    "reference": null,
    "note": null
  },
  {
    "id": "ipsec_minimaal_aes256gcm_prfsha384_en_dh_group_20",
    "name": "IPsec minimaal AES256GCM-PRFSHA384 en DH Group 20",
    "type": "positive_statement",
    "section": "IPSEC VPN",
    "refFile": "app_ipsec_encryption_v1.txt",
    "reference": "config vpn ipsec phase1-interface\n    edit \"IPsec_Dial-Up\"\n        set proposal aes256gcm-prfsha384\n        set dhgrp 20\n    next\nend\nconfig vpn ipsec phase2-interface\n    edit \"IPsec_Dial-Up\"\n        set proposal aes256gcm\n        set dhgrp 20\n    next\nend",
    "note": null
  },
  {
    "id": "ipsec_keylife_28800_3600",
    "name": "IPsec keylife 28800/3600",
    "type": "positive_statement",
    "section": "IPSEC VPN",
    "refFile": "app_ipsec_keylife_v1.txt",
    "reference": "config vpn ipsec phase1-interface\n    edit \"IPsec_Dial-Up\"\n        set keylife 28800\n    next\nend\nconfig vpn ipsec phase2-interface\n    edit \"IPsec_Dial-Up\"\n        set keylifeseconds 3600\n    next\nend",
    "note": null
  },
  {
    "id": "ipsec_static_blackhole_routes",
    "name": "IPsec Static Blackhole routes",
    "type": "aggregation",
    "section": "IPSEC VPN",
    "refFile": null,
    "reference": null,
    "note": null
  },
  {
    "id": "symbis_user_saml",
    "name": "Symbis user SAML",
    "type": "positive_statement",
    "section": "SSL-VPN & REMOTE ACCESS",
    "refFile": "app_user_saml_v1.txt",
    "reference": "config user saml\nedit \"Symbis_EntraID_SAML\"\nset idp-entity-id \"https://sts.windows.net/4f4b99f3-8fde-4ffa-8989-04680bb56aa7/\"\nset idp-single-sign-on-url \"https://login.microsoftonline.com/4f4b99f3-8fde-4ffa-8989-04680bb56aa7/saml2\"\nset idp-single-logout-url \"https://login.microsoftonline.com/4f4b99f3-8fde-4ffa-8989-04680bb56aa7/saml2\"\nset user-name \"username\"\nset group-name \"group\"\nset digest-method sha1\nend",
    "note": null
  },
  {
    "id": "ssl_vpn_loopback",
    "name": "SSL-VPN loopback",
    "type": "positive_block",
    "section": "SSL-VPN & REMOTE ACCESS",
    "refFile": "app_ssl-vpn_loopback_v1.txt",
    "reference": "config system interface\n    edit \"SSLVPN_Loopback\"\n        set vdom \"root\"\n        set ip 192.168.192.168 255.255.255.255\n        set allowaccess ping\n        set type loopback\n\tset description \"Symbis default v1\"\n        set role lan\n    next\nend",
    "note": "Alleen op modellen met ondersteuning voor SSL-VPN"
  },
  {
    "id": "ssl_vpn_cipher_suites",
    "name": "SSL-VPN cipher suites",
    "type": "positive_statement",
    "section": "SSL-VPN & REMOTE ACCESS",
    "refFile": "app_sslvpn_ciphers_v1.txt",
    "reference": "config vpn ssl settings\nset banned-cipher RSA DHE SHA1 SHA256 SHA384 ARIA\nend",
    "note": "Alleen op modellen met ondersteuning voor SSL-VPN"
  },
  {
    "id": "ssl_vpn_timeout_10_uur",
    "name": "SSL-VPN timeout 10 uur",
    "type": "positive_statement",
    "section": "SSL-VPN & REMOTE ACCESS",
    "refFile": "app_sslvpn_session_timeout_v1.txt",
    "reference": "config vpn ssl settings\nset auth-timeout 36000\nend",
    "note": "Alleen op modellen met ondersteuning voor SSL-VPN"
  },
  {
    "id": "safesearch_google_en_bing",
    "name": "Safesearch Google en Bing",
    "type": "positive_statement",
    "section": "DNS FILTERING & NAME RESOLUTION",
    "refFile": "app_safe_search_Google_Bing_v1.txt",
    "reference": "config system dns-database\n    edit \"bing.com\"\n        set domain \"www.bing.com\"\n        set authoritative disable\n        config dns-entry\n            edit 1\n                set hostname \"@\"\n                set ip 204.79.197.220\n            next\n        end\n    next\n    edit \"google.com\"\n        set domain \"www.google.com\"\n        set authoritative disable\n        config dns-entry\n            edit 1\n                set hostname \"@\"\n                set ip 216.239.38.120\n            next\n        end\n    next\nend",
    "note": null
  },
  {
    "id": "bekende_doh_servers_geblocked_via_isdb",
    "name": "Bekende DoH servers geblocked via ISDB",
    "type": "aggregation",
    "section": "DNS FILTERING & NAME RESOLUTION",
    "refFile": "app_firewall-policy_DoH_DoT_deny_v1.txt",
    "reference": "config firewall policy\nset name \"Guest_DoH_DoT_deny\"\nset srcintf \"Guest-VLAN\"\nset dstintf \"virtual-wan-link\"\nset srcaddr \"all\"\nset internet-service enable\nset internet-service-name \"DNS-DoH_DoT\"\nset schedule \"always\"\nset logtraffic all\nset comments \"Symbis default v1\"\nnext\nend",
    "note": "Alle interfaces dstintf \"virtual-wan-link\" \"wan1\" of \"wan2\" moeten een internet-service-name \"DNS-DoH_DoT\" deny hebben"
  },
  {
    "id": "ssl_labs_object",
    "name": "SSL Labs object",
    "type": "positive_statement",
    "section": "FIREWALL OBJECTEN & SERVICES",
    "refFile": "app_ssllabs_object_v1.txt",
    "reference": "config firewall address\n    edit \"s-Qualys_SSL_Labs\"\n        set comment \"Symbis default v2\"\n        set subnet 69.67.183.0 255.255.255.0\n    next\nend",
    "note": null
  },
  {
    "id": "all_service_is_rood",
    "name": "ALL service is rood",
    "type": "positive_statement",
    "section": "FIREWALL OBJECTEN & SERVICES",
    "refFile": "app_all_service_rood_v1.txt",
    "reference": "config firewall service custom\n    edit \"ALL\"\n        set category \"General\"\n        set protocol IP\n        set color 6\n    next\nend",
    "note": null
  },
  {
    "id": "symbis_utm_profiles_v7",
    "name": "Symbis UTM profiles v7",
    "type": "positive_block",
    "section": "UTM, IPS & APPLICATION CONTROL",
    "refFile": "app_utm_profiles_symbis_v2.txt",
    "reference": "config dnsfilter profile\n    edit \"symbis\"\n        set comment \"Symbis default v1\"\n        config ftgd-dns\n            set options error-allow\n            config filters\n                edit 1\n                    set category 59\n                    set action block\n                next\n                edit 2\n                    set category 26\n                    set action block\n                next\n                edit 3\n                    set category 61\n                    set action block\n                next\n                edit 4\n                    set category 86\n                    set action block\n                next\n                edit 5\n                    set category 88\n                    set action block\n                next\n                edit 6\n                    set category 90\n                    set action block\n                next\n                edit 7\n                    set category 91\n                    set action block\n                next\n                edit 192\n                    set category 192\n                    set action block\n                next\n            end\n        end\n        set block-action block\n        set block-botnet enable\n    next\n    edit \"symbis-monitor\"\n        set comment \"Symbis default v1\"\n        config ftgd-dns\n            set options error-allow\n            config filters\n                edit 1\n                    set category 1\n                next\n                edit 2\n                    set category 3\n                next\n                edit 3\n                    set category 4\n                next\n                edit 4\n                    set category 5\n                next\n                edit 5\n                    set category 6\n                next\n                edit 6\n                    set category 12\n                next\n                edit 7\n                    set category 59\n                next\n                edit 8\n                    set category 62\n                next\n                edit 9\n                    set category 83\n                next\n                edit 10\n                    set category 96\n                next\n                edit 11\n                    set category 98\n                next\n                edit 12\n                    set category 99\n                next\n                edit 13\n                    set category 2\n                next\n                edit 14\n                    set category 7\n                next\n                edit 15\n                    set category 8\n                next\n                edit 16\n                    set category 9\n                next\n                edit 17\n                    set category 11\n                next\n                edit 18\n                    set category 13\n                next\n                edit 19\n                    set category 14\n                next\n                edit 20\n                    set category 15\n                next\n                edit 21\n                    set category 16\n                next\n                edit 22\n                    set category 57\n                next\n                edit 23\n                    set category 63\n                next\n                edit 24\n                    set category 64\n                next\n                edit 25\n                    set category 65\n                next\n                edit 26\n                    set category 66\n                next\n                edit 27\n                    set category 67\n                next\n                edit 28\n                    set category 19\n                next\n                edit 29\n                    set category 24\n                next\n                edit 30\n                    set category 25\n                next\n                edit 31\n                    set category 72\n                next\n                edit 32\n                    set category 75\n                next\n                edit 33\n                    set category 76\n                next\n                edit 34\n                    set category 26\n                next\n                edit 35\n                    set category 61\n                next\n                edit 36\n                    set category 86\n                next\n                edit 37\n                    set category 88\n                next\n                edit 38\n                    set category 90\n                next\n                edit 39\n                    set category 91\n                next\n                edit 40\n                    set category 17\n                next\n                edit 41\n                    set category 18\n                next\n                edit 42\n                    set category 20\n                next\n                edit 43\n                    set category 23\n                next\n                edit 44\n                    set category 28\n                next\n                edit 45\n                    set category 29\n                next\n                edit 46\n                    set category 30\n                next\n                edit 47\n                    set category 33\n                next\n                edit 48\n                    set category 34\n                next\n                edit 49\n                    set category 35\n                next\n                edit 50\n                    set category 36\n                next\n                edit 51\n                    set category 37\n                next\n                edit 52\n                    set category 38\n                next\n                edit 53\n                    set category 39\n                next\n                edit 54\n                    set category 40\n                next\n                edit 55\n                    set category 42\n                next\n                edit 56\n                    set category 44\n                next\n                edit 57\n                    set category 46\n                next\n                edit 58\n                    set category 47\n                next\n                edit 59\n                    set category 48\n                next\n                edit 60\n                    set category 54\n                next\n                edit 61\n                    set category 55\n                next\n                edit 62\n                    set category 58\n                next\n                edit 63\n                    set category 68\n                next\n                edit 64\n                    set category 69\n                next\n                edit 65\n                    set category 70\n                next\n                edit 66\n                    set category 71\n                next\n                edit 67\n                    set category 77\n                next\n                edit 68\n                    set category 78\n                next\n                edit 69\n                    set category 79\n                next\n                edit 70\n                    set category 80\n                next\n                edit 71\n                    set category 82\n                next\n                edit 72\n                    set category 85\n                next\n                edit 73\n                    set category 87\n                next\n                edit 74\n                    set category 89\n                next\n                edit 75\n                    set category 31\n                next\n                edit 76\n                    set category 41\n                next\n                edit 77\n                    set category 43\n                next\n                edit 78\n                    set category 49\n                next\n                edit 79\n                    set category 50\n                next\n                edit 80\n                    set category 51\n                next\n                edit 81\n                    set category 52\n                next\n                edit 82\n                    set category 53\n                next\n                edit 83\n                    set category 56\n                next\n                edit 84\n                    set category 81\n                next\n                edit 85\n                    set category 84\n                next\n                edit 86\n                    set category 92\n                next\n                edit 87\n                    set category 93\n                next\n                edit 88\n                    set category 94\n                next\n                edit 89\n                    set category 95\n                next\n                edit 90\n                    set category 97\n                next\n                edit 91\n                next\n            end\n        end\n        set log-all-domain enable\n    next\nend\n\nconfig webfilter profile\n    edit \"symbis\"\n        set comment \"Symbis default v1\"\n        config ftgd-wf\n            set options error-allow\n            config filters\n                edit 1\n                    set category 1\n                    set action block\n                next\n                edit 3\n                    set category 3\n                    set action block\n                next\n                edit 4\n                    set category 4\n                    set action block\n                next\n                edit 5\n                    set category 5\n                    set action block\n                next\n                edit 6\n                    set category 6\n                    set action block\n                next\n                edit 12\n                    set category 12\n                    set action block\n                next\n                edit 59\n                    set category 59\n                    set action block\n                next\n                edit 62\n                    set category 62\n                    set action block\n                next\n                edit 83\n                    set category 83\n                    set action block\n                next\n                edit 96\n                    set category 96\n                    set action block\n                next\n                edit 98\n                    set category 98\n                    set action block\n                next\n                edit 99\n                    set category 99\n                    set action block\n                next\n                edit 2\n                    set category 2\n                    set action block\n                next\n                edit 7\n                    set category 7\n                    set action block\n                next\n                edit 8\n                    set category 8\n                    set action block\n                next\n                edit 11\n                    set category 11\n                    set action block\n                next\n                edit 13\n                    set category 13\n                    set action block\n                next\n                edit 14\n                    set category 14\n                    set action block\n                next\n                edit 15\n                    set category 15\n                    set action block\n                next\n                edit 16\n                    set category 16\n                    set action block\n                next\n                edit 57\n                    set category 57\n                    set action block\n                next\n                edit 63\n                    set category 63\n                    set action block\n                next\n                edit 65\n                    set category 65\n                    set action block\n                next\n                edit 67\n                    set category 67\n                    set action block\n                next\n                edit 72\n                    set category 72\n                    set action block\n                next\n                edit 26\n                    set category 26\n                    set action block\n                next\n                edit 61\n                    set category 61\n                    set action block\n                next\n                edit 86\n                    set category 86\n                    set action block\n                next\n                edit 88\n                    set category 88\n                    set action block\n                next\n                edit 90\n                    set category 90\n                    set action block\n                next\n                edit 91\n                    set category 91\n                    set action block\n                next\n                edit 142\n                    set category 142\n                    set log disable\n                next\n                edit 143\n                    set category 143\n                    set action block\n                next\n                edit 100\n                next\n                edit 37\n                    set category 9\n                next\n                edit 38\n                    set category 64\n                next\n                edit 39\n                    set category 66\n                next\n                edit 40\n                    set category 19\n                next\n                edit 41\n                    set category 24\n                next\n                edit 42\n                    set category 25\n                next\n                edit 43\n                    set category 75\n                next\n                edit 44\n                    set category 76\n                next\n                edit 45\n                    set category 17\n                next\n                edit 46\n                    set category 18\n                next\n                edit 47\n                    set category 20\n                next\n                edit 48\n                    set category 23\n                next\n                edit 49\n                    set category 28\n                next\n                edit 50\n                    set category 29\n                next\n                edit 51\n                    set category 30\n                next\n                edit 52\n                    set category 33\n                next\n                edit 53\n                    set category 34\n                next\n                edit 54\n                    set category 35\n                next\n                edit 55\n                    set category 36\n                next\n                edit 56\n                    set category 37\n                next\n                edit 58\n                    set category 38\n                next\n                edit 60\n                    set category 39\n                next\n                edit 64\n                    set category 40\n                next\n                edit 66\n                    set category 42\n                next\n                edit 68\n                    set category 44\n                next\n                edit 69\n                    set category 46\n                next\n                edit 70\n                    set category 47\n                next\n                edit 71\n                    set category 48\n                next\n                edit 73\n                    set category 54\n                next\n                edit 74\n                    set category 55\n                next\n                edit 75\n                    set category 58\n                next\n                edit 76\n                    set category 68\n                next\n                edit 77\n                    set category 69\n                next\n                edit 78\n                    set category 70\n                next\n                edit 79\n                    set category 71\n                next\n                edit 80\n                    set category 77\n                next\n                edit 81\n                    set category 78\n                next\n                edit 82\n                    set category 79\n                next\n                edit 84\n                    set category 80\n                next\n                edit 85\n                    set category 82\n                next\n                edit 87\n                    set category 85\n                next\n                edit 89\n                    set category 87\n                next\n                edit 92\n                    set category 89\n                next\n                edit 93\n                    set category 31\n                next\n                edit 94\n                    set category 41\n                next\n                edit 95\n                    set category 43\n                next\n                edit 97\n                    set category 49\n                next\n                edit 101\n                    set category 50\n                next\n                edit 102\n                    set category 51\n                next\n                edit 103\n                    set category 52\n                next\n                edit 104\n                    set category 53\n                next\n                edit 105\n                    set category 56\n                next\n                edit 106\n                    set category 81\n                next\n                edit 107\n                    set category 84\n                next\n                edit 108\n                    set category 92\n                next\n                edit 109\n                    set category 93\n                next\n                edit 110\n                    set category 94\n                next\n                edit 111\n                    set category 95\n                next\n                edit 112\n                    set category 97\n                next\n                edit 113\n                    set category 100\n                next\n                edit 114\n                    set category 101\n                next\n                edit 194\n                    set category 194\n                    set action block\n                next\n                edit 195\n                    set category 195\n                    set log disable\n                next\n            end\n        end\n    next\n    edit \"symbis-monitor\"\n        set comment \"Symbis default v1\"\n        config ftgd-wf\n            set options error-allow\n            config filters\n                edit 1\n                    set category 1\n                next\n                edit 3\n                    set category 3\n                next\n                edit 4\n                    set category 4\n                next\n                edit 5\n                    set category 5\n                next\n                edit 6\n                    set category 6\n                next\n                edit 12\n                    set category 12\n                next\n                edit 59\n                    set category 59\n                next\n                edit 62\n                    set category 62\n                next\n                edit 83\n                    set category 83\n                next\n                edit 96\n                    set category 96\n                next\n                edit 98\n                    set category 98\n                next\n                edit 99\n                    set category 99\n                next\n                edit 2\n                    set category 2\n                next\n                edit 7\n                    set category 7\n                next\n                edit 8\n                    set category 8\n                next\n                edit 9\n                    set category 9\n                next\n                edit 11\n                    set category 11\n                next\n                edit 13\n                    set category 13\n                next\n                edit 14\n                    set category 14\n                next\n                edit 15\n                    set category 15\n                next\n                edit 16\n                    set category 16\n                next\n                edit 57\n                    set category 57\n                next\n                edit 63\n                    set category 63\n                next\n                edit 64\n                    set category 64\n                next\n                edit 65\n                    set category 65\n                next\n                edit 66\n                    set category 66\n                next\n                edit 67\n                    set category 67\n                next\n                edit 19\n                    set category 19\n                next\n                edit 24\n                    set category 24\n                next\n                edit 25\n                    set category 25\n                next\n                edit 72\n                    set category 72\n                next\n                edit 75\n                    set category 75\n                next\n                edit 76\n                    set category 76\n                next\n                edit 26\n                    set category 26\n                next\n                edit 61\n                    set category 61\n                next\n                edit 86\n                    set category 86\n                next\n                edit 88\n                    set category 88\n                next\n                edit 90\n                    set category 90\n                next\n                edit 91\n                    set category 91\n                next\n                edit 17\n                    set category 17\n                next\n                edit 18\n                    set category 18\n                next\n                edit 20\n                    set category 20\n                next\n                edit 23\n                    set category 23\n                next\n                edit 28\n                    set category 28\n                next\n                edit 29\n                    set category 29\n                next\n                edit 30\n                    set category 30\n                next\n                edit 33\n                    set category 33\n                next\n                edit 34\n                    set category 34\n                next\n                edit 35\n                    set category 35\n                next\n                edit 36\n                    set category 36\n                next\n                edit 37\n                    set category 37\n                next\n                edit 38\n                    set category 38\n                next\n                edit 39\n                    set category 39\n                next\n                edit 40\n                    set category 40\n                next\n                edit 42\n                    set category 42\n                next\n                edit 44\n                    set category 44\n                next\n                edit 46\n                    set category 46\n                next\n                edit 47\n                    set category 47\n                next\n                edit 48\n                    set category 48\n                next\n                edit 54\n                    set category 54\n                next\n                edit 55\n                    set category 55\n                next\n                edit 58\n                    set category 58\n                next\n                edit 68\n                    set category 68\n                next\n                edit 69\n                    set category 69\n                next\n                edit 70\n                    set category 70\n                next\n                edit 71\n                    set category 71\n                next\n                edit 77\n                    set category 77\n                next\n                edit 78\n                    set category 78\n                next\n                edit 79\n                    set category 79\n                next\n                edit 80\n                    set category 80\n                next\n                edit 82\n                    set category 82\n                next\n                edit 85\n                    set category 85\n                next\n                edit 87\n                    set category 87\n                next\n                edit 89\n                    set category 89\n                next\n                edit 31\n                    set category 31\n                next\n                edit 41\n                    set category 41\n                next\n                edit 43\n                    set category 43\n                next\n                edit 49\n                    set category 49\n                next\n                edit 50\n                    set category 50\n                next\n                edit 51\n                    set category 51\n                next\n                edit 52\n                    set category 52\n                next\n                edit 53\n                    set category 53\n                next\n                edit 56\n                    set category 56\n                next\n                edit 81\n                    set category 81\n                next\n                edit 84\n                    set category 84\n                next\n                edit 92\n                    set category 92\n                next\n                edit 93\n                    set category 93\n                next\n                edit 94\n                    set category 94\n                next\n                edit 95\n                    set category 95\n                next\n                edit 97\n                    set category 97\n                next\n                edit 100\n                next\n                edit 101\n                    set category 101\n                next\n                edit 102\n                    set category 100\n                next\n            end\n        end\n    next\nend\n\nconfig application list\n    edit \"symbis\"\n        set comment \"Symbis default v1\"\n        set other-application-log enable\n        config entries\n            edit 1\n                set category 2 6\n            next\n        end\n    next\n    edit \"symbis-default-port\"\n        set comment \"Symbis default v1\"\n        set other-application-log enable\n        set enforce-default-app-port enable\n        config entries\n            edit 1\n                set category 2 6\n            next\n        end\n    next\n    edit \"symbis-monitor\"\n        set comment \"Symbis default v1\"\n        set other-application-log enable\n        set unknown-application-log enable\n    next\nend\n\nconfig firewall ssl-ssh-profile\n    edit \"symbis-certificate-inspection\"\n        set comment \"Symbis default v1\"\n        config https\n            set ports 443\n            set status certificate-inspection\n            set quic inspect\n            set cert-probe-failure allow\n        end\n        config ftps\n            set status disable\n        end\n        config imaps\n            set status disable\n        end\n        config pop3s\n            set status disable\n        end\n        config smtps\n            set status disable\n        end\n        config ssh\n            set ports 22\n            set status disable\n        end\n        config dot\n            set status disable\n            set quic inspect\n        end\n    next\nend",
    "note": null
  },
  {
    "id": "quic_protocol_is_niet_toegestaan",
    "name": "QUIC protocol is niet toegestaan",
    "type": "negative_statement",
    "section": "UTM, IPS & APPLICATION CONTROL",
    "refFile": "app_quic_service_firewall_policy_v1.txt",
    "reference": "config firewall policy\n    edit 135\n        set service \"QUIC\"\n    next\nen",
    "note": null
  },
  {
    "id": "ips_cp_accel_mode_none",
    "name": "IPS cp-accel-mode none",
    "type": "positive_statement",
    "section": "UTM, IPS & APPLICATION CONTROL",
    "refFile": "app_ips_cp-accel-mode_none_v1.txt",
    "reference": "config ips global\n    set cp-accel-mode none\nend",
    "note": "Alleen op modellen met 2GB RAM"
  },
  {
    "id": "server_protecting_actief_op_vips",
    "name": "Server Protecting actief op VIPs",
    "type": "aggregation",
    "section": "VIPS & EXPOSURE PROTECTION",
    "refFile": "app_server-protect_vip_v1.txt",
    "reference": "config firewall vip\n    edit \"DNAT_SSL-VPN_TCP444\"\n        set uuid 987827e6-a550-51ee-e287-ff4757963762\n        set extip 83.167.210.70\n        set mappedip \"192.168.192.168\"\n        set extintf \"wan2\"\n        set portforward enable\n        set extport 444\n        set mappedport 444\n    next\nend\n\nconfig firewall ssl-ssh-profile\n    edit \"STAR_DHMO_NL\"\n        set comment \"20230720/Symbis-Rino/EditName\"\n        config ssl\n            set inspect-all deep-inspection\n        end\n        config https\n            set ports 443\n            set quic inspect\n        end\n        config ftps\n        end\n        config imaps\n        end\n        config pop3s\n        end\n        config smtps\n        end\n        config ssh\n            set ports 22\n            set status disable\n        end\n        config dot\n            set status deep-inspection\n            set quic inspect\n        end\n        set server-cert-mode replace\n        set server-cert \"STAR_DHMO_NL_2025\"\n    next\nend",
    "note": "Voor elke VIP is een firewall policy met een SSL profile \"Positief statement\" set server-cert"
  },
  {
    "id": "malicious_block_op_vips_v3",
    "name": "Malicious block op VIPs v3",
    "type": "aggregation",
    "section": "VIPS & EXPOSURE PROTECTION",
    "refFile": "app_malicious_deny_vips_v1.txt",
    "reference": "config firewall vip\n    edit \"DNAT_SSL-VPN_TCP444\"\n        set uuid 987827e6-a550-51ee-e287-ff4757963762\n        set extip 83.167.210.70\n        set mappedip \"192.168.192.168\"\n        set extintf \"wan2\"\n        set portforward enable\n        set extport 444\n        set mappedport 444\n    next\nend\n\nconfig firewall policy\n    edit 52\n        set name \"WAN_SSL-VPN_TCP444_deny\"\n        set uuid 972b3142-ec9f-51f0-f08c-a1384f4782bb\n        set srcintf \"virtual-wan-link\"\n        set dstintf \"SSLVPN_Loopback\"\n        set dstaddr \"DNAT_SSL-VPN_TCP444\"\n        set internet-service-src enable\n        set internet-service-src-name \"Botnet-C&C.Server\" \"Hosting-Bulletproof.Hosting\" \"Malicious-Malicious.Server\" \"Phishing-Phishing.Server\" \"Proxy-Proxy.Server\" \"Tor-Exit.Node\" \"Tor-Relay.Node\" \"VPN-Anonymous.VPN\"\n        set schedule \"always\"\n        set service \"TCP_444\"\n        set logtraffic disable\n    next\nend",
    "note": "Voor elke VIP is een Malicious_deny firewall policy"
  },
  {
    "id": "uitgaande_malicious_block_v2",
    "name": "Uitgaande malicious block v2",
    "type": "aggregation",
    "section": "VIPS & EXPOSURE PROTECTION",
    "refFile": "app_firewall-policy_malicious_deny_v1.txt",
    "reference": "config firewall policy\nedit 0\nset name \"Guest_Malicious_deny\"\nset srcintf \"Guest-VLAN\"\nset dstintf \"virtual-wan-link\"\nset srcaddr \"all\"\nset internet-service enable\nset internet-service-name \"Botnet-C&C.Server\" \"Hosting-Bulletproof.Hosting\" \"Malicious-Malicious.Server\" \"Phishing-Phishing.Server\" \"Proxy-Proxy.Server\" \"Tor-Exit.Node\" \"Tor-Relay.Node\" \"VPN-Anonymous.VPN\"\nset schedule \"always\"\nset logtraffic all\nset comments \"Symbis default v1\"\nnext\nend",
    "note": "Voor elke dstintf \"virtual-wan-link\" \"wan1\" of \"wan2\" is er een malicious_deny"
  },
  {
    "id": "policy_met_vips_is_match_vip_enabled",
    "name": "Policy met VIPs is match-vip enabled",
    "type": "negative_statement",
    "section": "FIREWALL POLICIES",
    "refFile": "app_match-vip_disabled_v1.txt",
    "reference": "config firewall policy\n    edit\n        set match-vip disable\n    next\nend",
    "note": "Kan meerdere entries bevatten"
  },
  {
    "id": "firewall_policies_logtraffic_start_disabled",
    "name": "Firewall policies logtraffic-start disabled",
    "type": "negative_statement",
    "section": "FIREWALL POLICIES",
    "refFile": "app_logtraffic-start_disabled_v1.txt",
    "reference": "config firewall policy\n    edit\n        set logtraffic-start enable\n    next\nend",
    "note": "Kan meerdere entries bevatten"
  },
  {
    "id": "services_in_firewall_policies_zijn_niet_gestapeld",
    "name": "Services in firewall policies zijn niet gestapeld",
    "type": "aggregation",
    "section": "FIREWALL POLICIES",
    "refFile": "app_firewall-policy_gestappelde_services_v1.txt",
    "reference": "config firewall policy    \nedit 10098\n        set name \"TRUST-2-CASE-WIFI_GUEST\"\n        set uuid a008ad30-d5dd-51ec-8300-99c2da6afcce\n        set srcintf \"UPLINK_SWITCH\"\n        set dstintf \"virtual-wan-link\"\n        set action accept\n        set srcaddr \"lan_Groot-Ammers_WiFi_GUEST\"\n        set dstaddr \"all\"\n        set schedule \"always\"\n        set service \"DNS\" \"GRE\" \"HTTP\" \"HTTPS\" \"IKE\" \"IMAP\" \"IMAPS\" \"L2TP\" \"PING\" \"POP3\" \"POP3S\" \"PPTP\" \"RDP\" \"SMTP\" \"SMTPS\" \"SSH\" \"WhatsApp/Intune\" \"3CX_mobile_phone_app\" \"SSLVPN_9443\" \"SSLVPN_10443\" \"Camera_Watch\" \"Cisco_VPN_Client\" \"SSLVPN_4433\" \"Ortec_3156\" \"tcp_15000\"\n        set utm-status enable\n        set inspection-mode proxy\n        set ssl-ssh-profile \"SSL_certificate_insp._SNI_disabled\"\n        set av-profile \"AntiVirus_filter_proxy-based\"\n        set dnsfilter-profile \"DNS_filter_block_botnets\"\n        set ips-sensor \"IPS_filter\"\n        set logtraffic all\n        set nat enable\n        set comments \"policy TRUST-2-CASE-WIFI_GUEST\"\n    next\nend",
    "note": "Meer dan 7 services objecten op een ALLOW firewall policy is een afwijking"
  },
  {
    "id": "all_service_wordt_niet_gebruikt_in_firewall_policies",
    "name": "ALL service wordt niet gebruikt in firewall policies",
    "type": "positive_statement",
    "section": "FIREWALL POLICIES",
    "refFile": "app_firewall-policy_all_service_v1.txt",
    "reference": "config firewall policy    \nedit 13\n        set name \"SSL-VPN_IPsec_Germany\"\n        set uuid 3cf8c400-c24f-51ed-78ba-366e7e04d65a\n        set srcintf \"ssl.root\"\n        set dstintf \"VPN-Haenel-DE\"\n        set action accept\n        set srcaddr \"SSLVPN_TUNNEL_ADDR1\"\n        set dstaddr \"VPN-Haenel-DE_remote_subnet_2\" \"VPN-Haenel-DE_remote_subnet_1\"\n        set schedule \"always\"\n        set service \"ALL\"\n        set utm-status enable\n        set ssl-ssh-profile \"symbis-certificate-inspection\"\n        set application-list \"symbis-monitor\"\n        set logtraffic all\n        set nat enable\n        set ippool enable\n        set poolname \"Kantoor\"\n        set groups \"Haenel\"\n    next\nend",
    "note": "Betreft set service \"ALL\""
  },
  {
    "id": "local_in_policy_v7",
    "name": "local-in-policy v7",
    "type": "positive_block",
    "section": "LOCAL-IN & CONTROL PLANE PROTECTION",
    "refFile": "app_local-in-policy_8443_v1.txt",
    "reference": "config firewall local-in-policy\nedit 1\nset intf \"any\"\nset srcaddr \"MGMT_IPs\"\nset dstaddr \"all\"\nset action accept\nset service \"SSH\" \"TCP_8443\"\nset schedule \"always\"\nset virtual-patch enable\nset comments \"Be careful with changes\"\nnext\nedit 2\nset intf \"any\"\nset srcaddr \"s-PrivateNetworks\"\nset dstaddr \"all\"\nset action accept\nset service \"SNMP\"\nset schedule \"always\"\nset virtual-patch enable\nset comments \"Be careful with changes\"\nnext\nedit 3\nset intf \"any\"\nset srcaddr \"s-PrivateNetworks\"\nset dstaddr \"all\"\nset action accept\nset service \"SecurityFabric\"\nset schedule \"always\"\nset virtual-patch enable\nset comments \"Be careful with changes\"\nnext\nedit 4\nset intf \"any\"\nset srcaddr \"all\"\nset dstaddr \"all\"\nset service \"SecurityFabric\" \"SNMP\" \"SSH\" \"TCP_8443\" \"TELNET\"\nset schedule \"always\"\nset comments \"Be careful with changes\"\nnext\nend",
    "note": null
  },
  {
    "id": "global_black_en_whitelist_github",
    "name": "Global black- en whitelist (GitHub)",
    "type": "positive_block",
    "section": "LOCAL-IN & CONTROL PLANE PROTECTION",
    "refFile": "app_external_symbis_block-allow_lists_v1.txt",
    "reference": "config system external-resource\nedit \"symbis-dns-blocklist\"\nset type domain\nset category 192\nset comments \"Symbis default v1\"\nset resource \"https://raw.githubusercontent.com/symbis/Public/main/FortiGate/blocklist\"\nnext\nedit \"symbis-dns-allowlist\"\nset type domain\nset category 193\nset comments \"Symbis default v1\"\nset resource \"https://raw.githubusercontent.com/symbis/Public/main/FortiGate/allowlist\"\nnext\nedit \"symbis-webfilter-blocklist\"\nset category 194\nset comments \"Symbis default v1\"\nset resource \"https://raw.githubusercontent.com/symbis/Public/main/FortiGate/blocklist\"\nnext\nedit \"symbis-webfilter-allowlist\"\nset category 195\nset comments \"Symbis default v1\"\nset resource \"https://raw.githubusercontent.com/symbis/Public/main/FortiGate/allowlist\"\nnext\nend",
    "note": null
  },
  {
    "id": "snmp_v3",
    "name": "SNMP v3",
    "type": "negative_block",
    "section": "MANAGEMENT, MONITORING & AUTOMATION",
    "refFile": "app_snmp-community_v1.txt",
    "reference": "config system snmp community\nend",
    "note": null
  },
  {
    "id": "automation_stitches_v13",
    "name": "Automation stitches v13",
    "type": "positive_block",
    "section": "MANAGEMENT, MONITORING & AUTOMATION",
    "refFile": "app_automation_stitches_v1.txt",
    "reference": "config system automation-trigger\n    edit \"Fan\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 22108\n    next\n    edit \"Temperature\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 22109 22152\n    next\n    edit \"Auto Firmware upgrade\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 32263 22095\n    next\n    edit \"Compromised Host\"\n        set description \"An incident of compromise has been detected on a host endpoint.\"\n    next\n    edit \"Any Security Rating Notification\"\n        set description \"A security rating summary report has been generated.\"\n        set event-type security-rating-summary\n    next\n    edit \"AV & IPS DB update\"\n        set description \"The antivirus and IPS database has been updated.\"\n        set event-type virus-ips-db-updated\n    next\n    edit \"Configuration Change\"\n        set description \"Symbis default v1\"\n        set event-type config-change\n    next\n    edit \"Conserve Mode\"\n        set description \"Symbis default v1\"\n        set event-type low-memory\n    next\n    edit \"HA Failover\"\n        set description \"Symbis default v1\"\n        set event-type ha-failover\n    next\n    edit \"License Expiry\"\n        set description \"A FortiGate license is near expiration.\"\n        set event-type license-near-expiry\n        set license-type any\n    next\n    edit \"Reboot\"\n        set description \"A FortiGate is rebooted.\"\n        set event-type reboot\n    next\n    edit \"Anomaly Logs\"\n        set description \"An anomalous event has occurred.\"\n        set event-type anomaly-logs\n    next\n    edit \"IPS Logs\"\n        set description \"An IPS event has occurred.\"\n        set event-type ips-logs\n    next\n    edit \"SSH Logs\"\n        set description \"A SSH event has occurred.\"\n        set event-type ssh-logs\n    next\n    edit \"Traffic Violation\"\n        set description \"A traffic policy has been violated.\"\n        set event-type traffic-violation\n    next\n    edit \"Virus Logs\"\n        set description \"A virus event has occurred.\"\n        set event-type virus-logs\n    next\n    edit \"Webfilter Violation\"\n        set description \"A webfilter policy has been violated.\"\n        set event-type webfilter-violation\n    next\n    edit \"Admin Login\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 32001\n        config fields\n            edit 1\n                set name \"user\"\n                set value \"admin\"\n            next\n            edit 2\n                set name \"user\"\n                set value \"adm-symbis\"\n            next\n        end\n    next\n    edit \"Incoming Webhook Call\"\n        set description \"An incoming webhook call is received.\"\n        set event-type incoming-webhook\n    next\n    edit \"Network Down\"\n        set description \"A network connection is down.\"\n        set event-type event-log\n        set logid 20099\n        config fields\n            edit 1\n                set name \"status\"\n                set value \"DOWN\"\n            next\n        end\n    next\n    edit \"FortiAnalyzer Connection Down\"\n        set description \"A FortiAnalyzer connection is down.\"\n        set event-type event-log\n        set logid 22902\n    next\n    edit \"Local Certificate Expiry\"\n        set description \"A local certificate is near expiration.\"\n        set event-type local-cert-near-expiry\n    next\n    edit \"Admin login failed\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 32002\n    next\n    edit \"High availability\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 35013 35011\n    next\n    edit \"Integrity check\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 20234 20233\n    next\n    edit \"Power supply\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 22105 22114 22116 22117\n    next\n    edit \"Local out IOC\"\n        set description \"Symbis default v1\"\n        set event-type event-log\n        set logid 20214\n    next\nend\nconfig system automation-action\n    edit \"Reboot FortiGate\"\n        set description \"Reboot this FortiGate.\"\n        set action-type system-actions\n        set system-action reboot\n        set minimum-interval 300\n    next\n    edit \"Shutdown FortiGate\"\n        set description \"Shut down this FortiGate.\"\n        set action-type system-actions\n        set system-action shutdown\n    next\n    edit \"Backup Config Disk\"\n        set description \"Backup this FortiGate\\'s configuration file to disk.\"\n        set action-type system-actions\n        set system-action backup-config\n    next\n    edit \"Access Layer Quarantine\"\n        set description \"Quarantine the MAC address on access layer devices (FortiSwitch and FortiAP).\"\n        set action-type quarantine\n    next\n    edit \"FortiClient Quarantine\"\n        set description \"Use FortiClient EMS to quarantine the endpoint device.\"\n        set action-type quarantine-forticlient\n    next\n    edit \"FortiNAC Quarantine\"\n        set description \"Use FortiNAC to quarantine the endpoint device.\"\n        set action-type quarantine-fortinac\n    next\n    edit \"IP Ban\"\n        set description \"Ban the IP address specified in the automation trigger event.\"\n        set action-type ban-ip\n    next\n    edit \"FortiExplorer Notification\"\n        set description \"Send a notification to FortiExplorer mobile application.\"\n        set action-type fortiexplorer-notification\n    next\n    edit \"Email Notification\"\n        set description \"Send a custom email to the specified recipient(s).\"\n        set action-type email\n        set forticare-email enable\n        set email-subject \"%%log.logdesc%%\"\n    next\n    edit \"CLI Script - System Status\"\n        set description \"Execute a CLI script to return the system status.\"\n        set action-type cli-script\n        set script \"get system status\"\n        set accprofile \"super_admin_readonly\"\n    next\n    edit \"Symbis Monitoring\"\n        set description \"Symbis default v2\"\n        set action-type email\n        set email-to \"rmm@symbis.nl\"\n        set email-subject \"%%devname%% - %%log.logdesc%%\"\n        set message \"%%log%%\n%%results%%\"\n    next\n    edit \"SFTP Config Backup\"\n        set description \"Symbis default v1\"\n        set action-type cli-script\n        set script \"execute backup config sftp sftp-support/fortigate/%%devname%%_%%date%%_%%time%%.conf sftp.symbis.nl:22 sftp-support c1HhvX7jtBE2\"\n        set accprofile \"super_admin\"\n    next\n    edit \"Conserve Mode Debug\"\n        set description \"Symbis default v1\"\n        set action-type cli-script\n        set minimum-interval 30\n        set script \"get system status\nget system performance status\ndiagnose sys cmdb info\ndiagnose sys top 5 20 5\ndiagnose sys session full-stat\ndiagnose hardware sysinfo shm\ndiagnose hardware sysinfo memory\"\n        set accprofile \"super_admin\"\n    next\n    edit \"Get HA Status\"\n        set description \"Symbis default v1\"\n        set action-type cli-script\n        set script \"get system ha status\"\n        set accprofile \"super_admin\"\n    next\n    edit \"Symbis Securityteam\"\n        set description \"Symbis default v1\"\n        set action-type email\n        set email-to \"securityteam@symbis.nl\"\n        set email-subject \"%%devname%% - %%log.logdesc%%\"\n    next\nend\nconfig system automation-stitch\n    edit \"Firmware upgrade notification\"\n        set description \"Symbis default v1\"\n        set trigger \"Auto Firmware upgrade\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n            next\n        end\n    next\n    edit \"SFTP Config Backup\"\n        set description \"Symbis default v1\"\n        set trigger \"Configuration Change\"\n        config actions\n            edit 1\n                set action \"SFTP Config Backup\"\n                set required enable\n            next\n        end\n    next\n    edit \"Conserve Mode\"\n        set description \"Symbis default v1\"\n        set trigger \"Conserve Mode\"\n        config actions\n            edit 1\n                set action \"Conserve Mode Debug\"\n                set required enable\n            next\n            edit 2\n                set action \"Symbis Monitoring\"\n                set delay 60\n                set required enable\n            next\n        end\n    next\n    edit \"HA Failover\"\n        set description \"Symbis default v1\"\n        set trigger \"HA Failover\"\n        config actions\n            edit 1\n                set action \"Get HA Status\"\n                set required enable\n            next\n            edit 2\n                set action \"Symbis Monitoring\"\n                set delay 3\n                set required enable\n            next\n        end\n    next\n    edit \"Admin login failed\"\n        set description \"Symbis default v1\"\n        set trigger \"Admin login failed\"\n        config actions\n            edit 1\n                set action \"Symbis Securityteam\"\n                set required enable\n            next\n        end\n    next\n    edit \"Certificate\"\n        set description \"Symbis default v1\"\n        set trigger \"Local Certificate Expiry\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"Fan\"\n        set description \"Symbis default v1\"\n        set trigger \"Fan\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"High availability\"\n        set description \"Symbis default v1\"\n        set trigger \"High availability\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"Integrity check\"\n        set description \"Symbis default v1\"\n        set trigger \"Integrity check\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"License\"\n        set description \"Symbis default v1\"\n        set trigger \"License Expiry\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"Power supply\"\n        set description \"Symbis default v1\"\n        set trigger \"Power supply\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"Temperature\"\n        set description \"Symbis default v1\"\n        set trigger \"Temperature\"\n        config actions\n            edit 1\n                set action \"Symbis Monitoring\"\n                set required enable\n            next\n        end\n    next\n    edit \"Admin login successful\"\n        set description \"Symbis default v1\"\n        set trigger \"Admin Login\"\n        config actions\n            edit 1\n                set action \"Symbis Securityteam\"\n                set required enable\n            next\n        end\n    next\n    edit \"Local out IOC\"\n        set description \"Symbis default v1\"\n        set trigger \"Local out IOC\"\n        config actions\n            edit 1\n                set action \"Symbis Securityteam\"\n                set required enable\n            next\n        end\n    next\nend",
    "note": null
  },
  {
    "id": "password_policy",
    "name": "Password policy",
    "type": "positive_block",
    "section": "MANAGEMENT, MONITORING & AUTOMATION",
    "refFile": "app_system password-policy_v1.txt",
    "reference": "config system password-policy\n    set status enable\n    set apply-to admin-password ipsec-preshared-key\n    set minimum-length 14\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-non-alphanumeric 1\n    set min-number 1\n    set min-change-characters 4\nend",
    "note": null
  },
  {
    "id": "admin_vervangen_voor_adm_symbis",
    "name": "Admin vervangen voor adm-symbis",
    "type": "negative_statement",
    "section": "MANAGEMENT, MONITORING & AUTOMATION",
    "refFile": "app_admin_replaced_v1.txt",
    "reference": "config system admin\n    edit \"admin\"\nend",
    "note": null
  },
];
