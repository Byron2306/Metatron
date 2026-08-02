# Rev14 Benign False-Positive Cohort Plan

| Benign cohort | Why it matters | Status | Closest current control |
| --- | --- | --- | --- |
| human_admin_browsing | Should not trigger containment for ordinary operator activity. | missing | admin_dashboard_user |
| cicd_deployment_bot | Fast automation with legitimate privileges must not be trapped. | missing | ci_health_checker |
| backup_scanner | Touches many files and paths but is operationally benign. | missing | none |
| authorized_vulnerability_scanner | Suspicious-looking authorized scanning is the false-positive stress case. | missing | docs_crawler |
| monitoring_observability_agent | High telemetry volume should not be mistaken for an attack. | missing | ci_health_checker |
| helpdesk_script_runner | Human-assisted automation is common and must remain usable. | partial | support_ticket_user |
| internal_rpa_workflow | Agentic but authorized workflows determine enterprise deployability. | missing | normal_api_user |
| developer_cli_tools | Tool-heavy normal engineering sessions should stay below containment threshold. | missing | normal_api_user |

These cohorts are defined as next-run requirements. The current repo already contains lightweight benign controls (`normal_api_user`, `ci_health_checker`, `docs_crawler`, `admin_dashboard_user`, `support_ticket_user`) that can be expanded into the full enterprise false-positive panel.
