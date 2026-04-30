# Metatron / Seraph Security Features Analysis

**Updated:** 2026-04-30  
**Classification:** Code-evidence rebaseline  
**Scope:** Security feature coverage and implementation realism across the current repository.

---

## Overview

The repository contains a broad security platform with real implementations for endpoint monitoring, SOC workflows, AI-assisted detection, deception, email, mobile/MDM, identity, cloud posture, response automation, and governance. The accurate security summary is that the codebase has many implemented frameworks and operational routes, with production effectiveness gated by external integrations, host privileges, credentials, and assurance coverage.

---

## Implemented Security Domains

| Domain | Current evidence | Status |
|---|---|---|
| Endpoint detection and response | `unified_agent/core/agent.py`, EDR/router/service modules | Implemented / environment-dependent |
| Network security | agent network/DNS monitors, VPN, topology, network discovery, browser isolation modules | Implemented / partial |
| Threat intelligence and correlation | `backend/threat_intel.py`, `backend/threat_correlation.py`, hunting routes/services | Implemented / feed-dependent |
| Response and remediation | SOAR, response, quarantine, ransomware, honey-token, deception modules | Implemented / provider-dependent |
| AI-agentic defense | AATL, AATR, CCE worker, AI activity routes, triune services | Framework implemented |
| Data protection and EDM/DLP | agent DLP monitor, unified agent EDM paths, DLP modules | Implemented / assurance-dependent |
| Identity and zero trust | identity router/services, zero-trust router/service, enterprise services | Implemented / partial |
| CSPM | CSPM router/engine, `/api/v1/cspm` route family | Implemented / cloud-config-dependent |
| Email protection | `backend/email_protection.py`, `backend/routers/email_protection.py` | Implemented |
| Email gateway | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Implemented framework; production relay integration required |
| Mobile security | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Implemented framework |
| MDM connectors | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Implemented framework; credentials required |
| Kernel and secure boot | kernel sensor, secure boot, rootkit/kernel agent monitors | Conditional / host-dependent |
| Browser isolation | browser isolation service/router/page | Partial |
| Multi-tenant/governance | multi-tenant router/service, governance context/executor/policy modules | Implemented / assurance-dependent |

---

## Endpoint and Agent Security

The unified agent is the largest local security component in the repo. It includes monitor-class families for process, network, registry, process tree, LOLBins, code signing, DNS, memory, application allowlisting, DLP, vulnerability scanning, AMSI, ransomware, rootkit, kernel security, self-protection, identity, throttling, firewall, WebView2, CLI telemetry, hidden files, alias/rename behavior, privilege escalation, email protection, mobile security, and YARA.

Practical constraints:

- Deep host telemetry requires OS support and privileges.
- Some monitor behavior is platform-specific.
- Agent protection and anti-tamper depth should be validated on target operating systems rather than assumed from code presence.

---

## Email Security

### Email protection

`backend/email_protection.py` implements:

- SPF/DKIM/DMARC-oriented authentication result modeling.
- Phishing heuristics.
- URL analysis for shorteners, IP-based links, suspicious paths/domains, and known suspicious domains.
- Attachment analysis for dangerous extensions, macro-enabled documents, archives, entropy, and hashes.
- Impersonation/BEC-oriented detection primitives.
- DLP analysis and quarantine state.

### Email gateway

`backend/email_gateway.py` implements:

- Gateway modes and decisions (`accept`, `reject`, `quarantine`, `defer`, `redirect`, `tag`, `encrypt`).
- Email parsing, attachment extraction, queue/quarantine/defer tracking.
- Sender/domain/IP blocklists and allowlists.
- Policy thresholds and message-size/recipient controls.
- Integration with email protection where available.

Router endpoints under `/api/email-gateway` provide stats, process/test submission, quarantine release/delete, policies, and block/allow list management. This is a real gateway framework, but production inline mail interception still requires MTA/SMTP deployment and routing configuration.

---

## Mobile and MDM Security

`backend/mobile_security.py` provides device, threat, app-analysis, and compliance models for iOS/Android security posture. It covers jailbreak/root indicators, risky/malicious apps, sideloading, permissions, network attacks, missing encryption, passcode posture, and compliance scoring.

`backend/mdm_connectors.py` provides connector abstractions and concrete classes for:

- Microsoft Intune
- JAMF Pro
- VMware Workspace ONE
- Google Workspace

The MDM layer includes device sync, policy sync, and actions such as lock, wipe, retire, sync, passcode reset, lost mode, locate, restart/shutdown, policy push, and certificate revocation. These paths become live only when provider credentials and API permissions are configured.

---

## Cloud, Identity, Governance, and AI

- CSPM is routed under `/api/v1/cspm` and is no longer accurately described as a public unauthenticated scan surface.
- Identity uses `/api/v1/identity` and is part of the enterprise control plane.
- Zero-trust and enterprise routers provide policy and security-management surfaces.
- AATL/AATR/CCE and triune services provide AI-agentic detection and governance frameworks, but quality depends on configured services and data.

---

## Security Risks and Gaps

| Gap | Impact | Current note |
|---|---|---|
| Production SMTP/MTA integration | High for email gateway claims | Gateway framework exists; deployment wiring is external. |
| Live MDM credentials | High for MDM claims | Connector code exists; sync/action reality depends on provider config. |
| Uniform auth/permission verification | High | Large router surface needs automated denial-path testing. |
| Optional router visibility | Medium | Some Tier-1 routers fail open on import errors. |
| Durable state review | Medium | Some gateway/MDM/governance state is service-local and needs persistence review for clustered use. |
| Browser isolation depth | Medium | Filtering/sanitization exists; full remote isolation is not proven. |
| Dependency and toolchain footprint | Medium | Compose and Python/JS dependencies are broad and require ongoing governance. |

---

## Final Assessment

Metatron/Seraph has substantial security feature coverage in code. The platform should be documented as a broad, integration-rich security fabric with implemented frameworks across many domains. Claims of production completeness should be scoped to configured environments and validated workflows, especially for email gateway, MDM, optional AI/model services, browser isolation, kernel/host sensors, and external security tools.
