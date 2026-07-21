# Custom Suricata rules

`local.rules` is a custom detection rule, not part of the Emerging Threats
ruleset that `suricata-update` manages. It's tracked here so it isn't lost if
the Suricata VM is rebuilt.

## Why this rule exists

The trained Random Forest classifies one flow at a time, so it can't see the
cross-flow pattern that defines a port scan (one source hitting many
ports/hosts quickly). A live `nmap -sS -T4` scan against the lab's Suricata VM
scored 0 of 6,365 real flows above the ML alert threshold — see
`Documents/7-19-SESSION-SUMMARY.md`. This Suricata rule fires directly on that
pattern (5+ SYNs from one source within 10 seconds) as an independent,
complementary detection path. `build_incident()` in
`src/reporting/incidents.py` now creates an incident when *either* the ML
model crosses its threshold *or* Suricata correlates a signature to the flow.

## Deploying to the Suricata VM

1. Copy `local.rules` to `/var/lib/suricata/rules/local.rules` on the
   Suricata VM.
2. In `/etc/suricata/suricata.yaml`, add it to the `rule-files:` list
   alongside the `suricata-update`-managed `suricata.rules`:
   ```yaml
   rule-files:
     - suricata.rules
     - local.rules
   ```
3. Reload/restart Suricata (or `suricatasc -c reload-rules` if running as a
   service) so the new rule takes effect.

Keeping this rule in its own file (rather than editing `suricata.rules`
directly) means a future `suricata-update` run won't overwrite it.
