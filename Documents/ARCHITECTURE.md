# Network Lab Architecture

**Author:** Madison
**Date:** 2026-06-26
**Status:** Network design / teammate implementation not yet available. Madison's
local AI component is working; see "Status" at the bottom.

This document describes the physical/virtual lab network the three-person
project runs on top of: how the Attacker VM, the Router VM (Daniel's Suricata
instance), and the Victim VM are wired together in GNS3, and how that network
layer feeds into the software pipeline described in `CLAUDE.md` and
`PROGRESS.md`. For the code-level architecture (modules, functions, data
contracts), see `audit/ARCHITECTURE.md` — this document only covers the
network/lab layer underneath it.

---

## 1. Topology

```
┌──────────────────────────────────────────────────────────────────┐
│  GNS3 virtual network                                             │
│                                                                    │
│  ┌──────────┐         ┌──────────────────────┐      ┌──────────┐ │
│  │   Kali    │ ──────► │   Router VM           │ ───► │  Windows  │ │
│  │ Attacker  │ switch  │   Suricata (Daniel)    │ switch │  Victim   │ │
│  └──────────┘         └──────────┬───────────┘      └──────────┘ │
│                                   │ writes                         │
└───────────────────────────────────┼─────────────────────────────────┘
                                     ▼
                          ┌──────────────────┐
                          │   eve.json        │   (flow events)
                          └────────┬──────────┘
                                   │ tailed by
                                   ▼
                          ┌──────────────────┐
                          │   AI detector      │   src/detector/suricata_reader.py
                          │   (Madison)         │   → predict() → score 0-100
                          └────────┬──────────┘
                                   │ scored attacks
                                   ▼
                          ┌──────────────────┐
                          │   Dashboard        │   Willow's UI/DB (contract TBD)
                          └──────────────────┘
```

The Router VM must sit **in the path** between Kali and Windows — every packet
between them has to cross it, or Suricata never sees the traffic. This is why
it has two NICs and acts as a router, not a passive observer on a shared
switch.

---

## 2. Components

| Component | Role | Notes |
|---|---|---|
| **Kali VM** | Attacker | Generates the attack traffic (Nmap, hping3, hydra, etc.) |
| **Router VM** (Daniel) | Suricata IDS, gateway between subnets | Two NICs, IP forwarding enabled, runs Suricata in live mode |
| **Windows VM** | Victim/target | Receives attack traffic; also a source of "normal" background traffic |
| **GNS3** | Virtual network fabric | Wires the three VMs together with virtual switches; doesn't run any logic itself |
| **AI detector** (Madison) | Scores flows | Runs `src/detector/suricata_reader.py`, ideally directly on the Router VM so it can read `eve.json` as a local file |
| **Dashboard** (Willow) | Displays scored incidents | Contract (DB schema / file / API) not yet agreed — see `PROGRESS.md` |

---

## 3. Build steps

1. **Install GNS3 and the GNS3 VM.** The GNS3 VM is a small appliance that
   integrates with VirtualBox/VMware so GNS3 can route real virtual network
   links between guest VMs — GNS3 alone only manages topology, it doesn't run
   the VMs.

2. **Import three appliances:**
   - Kali — official Kali OVA, or the GNS3 Kali appliance template.
   - Windows VM — any licensed Windows install.
   - Router VM — Ubuntu Server (or similar) with **two NICs**, one per
     subnet, and Suricata installed.

3. **Wire the topology**: Kali → switch → Router VM (eth0/eth1) → switch →
   Windows. Both switches are virtual GNS3 switches, not physical hardware.

4. **Enable routing on the Router VM**, otherwise the two subnets simply
   can't reach each other and there's nothing for Suricata to inspect:
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   # plus iptables/nftables rules so Kali's subnet can reach Windows's subnet
   ```

5. **Run Suricata in live mode** (not offline `-r` mode, which is what was
   used for the earlier pcap validation — see `PROGRESS.md` Sprint 2):
   ```bash
   suricata -i eth1 -c /etc/suricata/suricata.yaml
   ```
   This continuously appends flow events to `eve.json` as traffic crosses the
   router, which is what the existing `--eve` tail mode in
   `suricata_reader.py` was built for (`--eve-once` is for finished,
   offline-mode files only).

6. **Run the AI detector against the live file**, on the Router VM if
   possible to avoid needing a network file share:
   ```bash
   python -m src.detector.suricata_reader --eve /var/log/suricata/eve.json
   ```

---

## 4. Validation plan

The architecture is considered working once this sequence succeeds end to
end (this is the same test already listed in `TODO.md` / Definition of Done):

1. From Kali: `nmap -sS <windows-vm-ip>`
2. Suricata on the Router VM logs the resulting flow(s) to `eve.json`.
3. `suricata_reader.py --eve <path>` picks up the new flow and scores it.
4. Scores ≥50 receive the `attack` classification; scores crossing
   `ALERT_THRESHOLD` (95) raise a high-priority alert.

Other attack shapes worth testing once Nmap works, since they exercise
different parts of the model's feature space:

- `hping3 --flood -S <target>` — SYN-flood / DDoS-shaped traffic.
- `hydra` against SSH — brute-force shape (many small forward packets, few
  replies).

A downloaded, non-lab pcap is **not** a substitute for this — see the
2026-06-26 investigation in `PROGRESS.md` / `audit/CURRENT_STATE.md`, where a
generic captured pcap topped out at a score of 47 because it didn't actually
contain CICIDS2017-shaped attacks. Self-generated attacks from the Attacker
VM are the only way to get a real, known-ground-truth signal.

---

## 5. Open questions / not yet decided

- Where does the AI detector physically run — on the Router VM itself, or on
  a separate host reading a synced/shared `eve.json`? (Recommendation above:
  start on the Router VM, it's the path of least friction.)
- Willow's dashboard contract (DB schema, file, or API) is still needed for the
  final handoff. A standalone JSON Lines fallback writer now exists, but
  `tail_eve()` does not call it yet. Tracked in `PROGRESS.md` / `TODO.md`.

## 6. Status

**Updated July 4, 2026:**

- Madison's local model, feature mapping, classification/alert thresholds,
  standalone report demo, JSON Lines incident writer, and 16-test suite are
  working.
- Local Git exists at the Senior Project root with baseline commit `25a12b1`.
- Automatic network lockdown is explicitly out of scope; alerts require human
  review.
- Live `tail_eve()` report/writer integration and the dashboard handoff are not
  built.
- No shared GitHub remote exists yet.
- Teammate artifacts have not been received in this workspace.

**Network status:**
- No GNS3 topology exists yet.
- Daniel's Suricata work so far has been offline-mode validation against a
  downloaded pcap (`suricata -r`), not a live router-mode deployment.
- No Nmap-from-Kali end-to-end test has been run.

This document describes the target architecture to build toward, not the
current state. Update the sections above as pieces of this come online, and
cross-reference `PROGRESS.md`'s Sprint tracker so the two documents don't
drift apart.
