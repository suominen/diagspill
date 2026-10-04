---
title: "DiagSpill — SCTP sock_diag transport-count overflow"
description: "Linux kernel SCTP sock_diag heap overflow (CVE-2026-74469, DiagSpill) — an unprivileged local user overflows the kernel heap by ~8 MiB with no user namespace or capability — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-10-04
cover:
  image: "diagspill-tracker.png"
  alt: "DiagSpill — Linux kernel SCTP sock_diag transport-count overflow tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-74469 |
| Alias | `DiagSpill` (the name the [write-up][writeup] and [PoC][poc] use) |
| Component | Kernel: SCTP peer-transport accounting and `sctp_diag` reporting — `sctp_assoc_add_peer()` (`net/sctp/associola.c`) and `inet_diag_msg_sctpaddrs_fill()` (`net/sctp/diag.c`, `NETLINK_SOCK_DIAG`) |
| Type | Heap out-of-bounds write. An association's 16-bit `transport_count` wraps to zero at the 65,536th unique peer transport; a subsequent `sctp_diag` dump reserves a zero-length `INET_DIAG_PEERS` payload but copies one `sockaddr_storage` per entry of `transport_addr_list`, spilling ~8 MiB past the Netlink skb tail |
| Impact | Kernel heap corruption: an oops/panic (**DoS**) and, per the discoverer, **local privilege escalation to root** via page-table grooming. A CONTAINER with the modules available can corrupt the host kernel, so container-to-host escape is plausible (not demonstrated) |
| Upstream fix | [`bd0e9289e264`][fix] (*sctp: prevent peer transport count overflow*); first in **v7.2-rc6** |
| Introduced | [`8f840e47f190`][intro] in **v4.7** (2016) — the `sctp_diag` module that made the wrap reachable |
| Affected window | **4.7 through 7.1** without the backport (and 7.2 before `-rc6`) |
| Discoverer | Asim Manizada ([@manizada](https://github.com/manizada)), who also authored the upstream fix |
| Public disclosure | 2026-09-18 ([oss-security][ossec]; [write-up][writeup]) |
| Public PoC | [manizada/DiagSpill][poc] |
| Related | Disclosed together with [DirtyAH6](https://kimmo.cloud/dirtyah6/) (CVE-2026-80844), [TUNderflow](https://kimmo.cloud/tunderflow/) (CVE-2026-81000), and [PPPoEject](https://kimmo.cloud/pppoeject/) (CVE-2026-68121) |
| Reachability | The **`sctp` and `sctp_diag` modules available**, and nothing else. An unprivileged local user builds the association and issues the diagnostic dump themselves — **no user namespace and no capability** are required. On most distributions `sctp` autoloads on first use of an `AF_INET`/`IPPROTO_SCTP` socket, and `sctp_diag` autoloads when `ss --sctp` (or any `SOCK_DIAG` SCTP query) runs |
| KEV / EPSS / CVSS | Not in KEV. EPSS **0.47%** (39th percentile). Two CVSS vantage points: **kernel CNA / NVD** 3.1 **8.8 HIGH** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), scoring a remote SCTP peer driving the transport count; **Red Hat** 3.1 **8.3 HIGH** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`), now matching the CNA's network vector and differing only in integrity impact. See *Scoring* below |
{.summary}

> :information_source: **The gate is module availability, not privilege.**
> DiagSpill is the outlier of the four bugs disclosed alongside it: the
> other three (DirtyAH6, TUNderflow, PPPoEject) need unprivileged user
> namespaces or specific capabilities, so disabling unprivileged user
> namespaces blunts them. **DiagSpill needs neither** — an ordinary local
> account reaches it as long as `sctp` and `sctp_diag` can load, so a user
> namespace lockdown does nothing here. The only thing that flips a row is
> the kernel backport; the only durable mitigation short of patching is to
> keep the SCTP modules from loading.

## How the exploitation chain works

SCTP is multi-homed: one association can span many peer IP addresses, each
represented by an `sctp_transport`. `sctp_assoc_add_peer()` adds a new
transport for every unique peer address and increments the association's
`transport_count` — a **16-bit** field (`__u16`). An attacker who controls
the association can add unique peer addresses at will, through `connectx()`,
repeated ASCONF ADD-IP chunks, or INIT address parameters. Adding the
**65,536th** transport wraps `transport_count` to **zero** while
`transport_addr_list` still holds every entry.

`sctp_diag` reports SCTP sockets and their peers over `NETLINK_SOCK_DIAG`
(the interface `ss` and other tools use). To build the reply it reserves an
`INET_DIAG_PEERS` payload sized from `transport_count`, then walks
`transport_addr_list` copying one `sockaddr_storage` for every transport:

1. **The count is read as zero**, so `inet_diag_msg_sctpaddrs_fill()`
   reserves **no space** in the Netlink skb for the peer payload.
2. **The copy loop still iterates all 65,536 transports**, writing one
   `sockaddr_storage` each — about **8 MiB** — straight past the skb tail,
   over whatever kernel heap follows the buffer.

That overwrite is the primitive. A subsequent access to a corrupted
allocation faults (the oops/panic path), or — with heap grooming — the
spill lands on attacker-influenced objects for a read/write primitive. The
[PoC][poc] grooms the overwrite into **page tables**, turns corrupted PMD
entries into user-readable/writable mappings of physical RAM, scans them
for a helper process's credentials, zeroes its UID/GID, and uses it to
install a temporary sudoers rule and open a root shell.

The fix, [`bd0e9289e264`][fix], rejects a new unique peer once
`transport_count` has reached `U16_MAX`, so the count can never wrap. The
check sits after the existing-peer lookup, so a duplicate address still
returns its existing transport at the limit.

> :warning: This is **not** a recent-regression bug. The reachable defect
> dates to **v4.7 (2016)**, when the `sctp_diag` module first exposed the
> peer list; the `transport_count` field has been 16-bit far longer. There
> is no "too old to be affected" kernel — a kernel is safe only by carrying
> the [`bd0e9289e264`][fix] fix, never by being old. Every tracked distro
> kernel, EL8's 4.18 included, is in-window.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`8f840e47f190`][intro] | Introduced | *sctp: add the sctp_diag.c file* (**v4.7**, 2016) — the diagnostic path that reserves its peer payload from the wrappable `transport_count` and then copies the full list. |
| [`bd0e9289e264`][fix] | Fixed | *sctp: prevent peer transport count overflow* — rejects a new unique peer at `U16_MAX`, so the count cannot wrap; first released in **v7.2-rc6**. |

The reachable lifetime runs from **v4.7** through **v7.1** (and 7.2 before
`-rc6`). DiagSpill is one of a **quartet** of local-root bugs the same
researcher disclosed on 2026-09-18; the siblings are tracked separately at
[DirtyAH6](https://kimmo.cloud/dirtyah6/),
[TUNderflow](https://kimmo.cloud/tunderflow/), and
[PPPoEject](https://kimmo.cloud/pppoeject/).

## Patch status

A row is **Fixed** only if its kernel carries the [`bd0e9289e264`][fix]
backport; every SCTP-capable kernel without it is in-window and
**Vulnerable**. The first group is the upstream kernel; the rest are a
focused set of x86-64 distributions, with per-distribution detail in the
sections that follow. *Current kernel* tracks the live package or point
release; *First fixed* and *Fixed since* are set once, when a row first
carries the fix, and stay `—` until then.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.3-rc5 | 7.2-rc6 | 2026-08-02 | :white_check_mark: Fixed — carries `bd0e9289e264` |
| Linux kernel | 7.2.x | 7.2.9 | 7.2 | 2026-08-16 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.13 | 7.1.8 | 2026-08-09 | :white_check_mark: Fixed — EOL |
| Linux kernel | 6.18.x | 6.18.55 | 6.18.44 | 2026-08-09 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.112 | 6.12.103 | 2026-08-09 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.158 | 6.6.151 | 2026-08-09 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.189 | 6.1.183 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.222 | 5.15.216 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.271 | 5.10.265 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.2.9-1 | 7.1.8-1 | 2026-08-12 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.2.8-1 | 7.1.8-1 | 2026-08-16 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.111-1 | 6.12.105-1 | 2026-08-25 | :white_check_mark: Fixed — DSA-6466-1 |
| Debian | 12 (bookworm) | 6.1.187-1 | 6.1.187-1 | 2026-09-08 | :white_check_mark: Fixed — DLA-4777-1 |
| Debian | 12 (6.12 opt-in) | 6.12.111-1~deb12u1 | 6.12.107-1~deb12u1 | 2026-09-16 | :white_check_mark: Fixed |
| Proxmox VE | 9 (default) | 7.0.14-20 | 7.0.14-18 | 2026-09-17 | :white_check_mark: Fixed — folded into Ubuntu-resolute rebase |
| Proxmox VE | 8 (default) | 6.8.12-43 | 6.8.12-43 | 2026-08-18 | :white_check_mark: Fixed — cherry-pick |
| NixOS | master | 6.18.55 | 6.18.44 | 2026-08-10 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.55 | 6.18.44 | 2026-08-09 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.54 | 6.18.44 | 2026-08-11 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.55 | 6.18.44 | 2026-08-10 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.54 | 6.18.44 | 2026-08-11 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.54 | 6.18.44 | 2026-08-12 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.55 | 6.18.44 | 2026-08-10 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.61.1.el10_2 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 9 | 5.14.0-687.54.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 8 | 4.18.0-553.170.1.el8_10 | — | — | :x: Vulnerable — no RHSA yet |
| Amazon Linux | 2023 (default) | 6.1.188-233.386 | 6.1.186-228.374 | 2026-09-14 | :white_check_mark: Fixed — ALAS2023-2026-2143 |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.110-135.202 | 6.12.103-127.188 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2110 |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.51-120.163 | 6.18.44-99.149 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2106 |
{.distros}

### Linux kernel

The fix reached mainline in **v7.2-rc6** and has been backported to every
maintained stable and long-term line.

**7.1.x is end of life.** It carries the fix but gets no further updates
— move to 7.2.x or a long-term line.

To confirm a fix in a tree directly, the change is three lines in
`sctp_assoc_add_peer()` (`net/sctp/associola.c`): a
`if (asoc->peer.transport_count == U16_MAX) return NULL;` guard added
before `sctp_transport_new()`.

### Debian

forky is testing, the future Debian 14. bookworm's opt-in 6.12 kernel is
the `linux-6.12` package in `bookworm-security`: trixie's 6.12 kernel
rebuilt for bookworm.

**bullseye (Debian 11) left LTS support on 2026-08-31** without the fix.
No further update is coming — upgrade to bookworm or newer.

SCTP ships as the `sctp` module, autoloaded on first use of an SCTP
socket and not blacklisted, so any host running an SCTP service loads
the vulnerable code. `sctp_diag` autoloads the same way when a
diagnostic query runs.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels, so Debian's status does
not carry over. The default kernels are PVE 9's `proxmox-kernel-7.0`
and PVE 8's `proxmox-kernel-6.8`.

- **PVE 8 reached end of life in August 2026.** Its 6.8 kernel is fixed
  for this bug but gets nothing further — upgrade to PVE 9.
- **PVE 8's `proxmox-kernel-6.14` opt-in** (from `bookworm-backports`,
  distinct from PVE 9's preview series of the same number) never got the
  fix, and its Ubuntu base, `linux-hwe-6.14`, is itself end-of-life. No
  fix is coming — upgrade to PVE 9.
- **Abandoned preview series** that PVE 9 still publishes,
  `proxmox-kernel-6.14` and `proxmox-kernel-6.17`, never got the fix. A
  host booting one should switch to the default kernel.

### NixOS

Every NixOS channel and branch in the table defaults to
`linux_6_18` (`linuxPackages`), which carries the fix.
nixpkgs also pins `linux_6_12`,
`linux_6_6`, `linux_6_1`, `linux_5_15` and `linux_5_10` at fixed
releases, so a host overriding the default is fixed too, as long as it
tracks a current-enough ref.

Kernel updates land on nixpkgs `master` first and reach each channel
once its Hydra jobset passes, so a channel can sit a few days behind
`master`. The `-small` channels (`nixos-unstable-small`,
`nixos-26.05-small`) run a reduced jobset and pick up kernel updates
fastest.

Which ref a flake input follows:

- `github:NixOS/nixpkgs/nixos-unstable` and
  `github:NixOS/nixpkgs/nixos-26.05` follow those channels — the GitHub
  channel branches are updated to exactly the published channel pins.
- A bare `github:NixOS/nixpkgs` with no ref follows `master`, and
  `github:NixOS/nixpkgs/release-26.05` follows that branch. Both are
  ungated development branches — they carry a kernel bump as soon as it
  lands, often a day or more before a channel publishes it.
- A bare `nixpkgs` registry input resolves by default to
  the `nixpkgs-unstable` channel: a separate channel aimed at
  Nix on other operating systems, not gated on the NixOS tests.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry SCTP, so all three
EL lines — EL10 (6.12-based), EL9 (5.14-based) and EL8 (4.18-based) —
are in-window. Rocky rebuilds RHEL's kernels, so a Rocky fix follows
Red Hat's advisory for the current minor release.

On 2026-09-24 Red Hat fixed several extended-support streams, each with
its own advisory; none of these covers the current minor releases that
Rocky rebuilds:

- **RHEL 10:** 10.0 EUS RHSA-2026:71599.
- **RHEL 9:** 9.6 EUS RHSA-2026:71631; 9.4 E4S RHSA-2026:71569;
  9.2 E4S RHSA-2026:71601 (`kernel-rt` RHSA-2026:71606).
- **RHEL 8:** 8.8 TUS/E4S RHSA-2026:71594; 8.6 AUS/EUS RHSA-2026:71592;
  8.4 AUS/E4S RHSA-2026:71565.
- **RHEL 7 ELS:** RHSA-2026:71687 (`kernel-rt` RHSA-2026:71657).

**`sctp` does not autoload on a stock EL host.** On EL8, EL9 and EL10
`sctp.ko` and `sctp_diag.ko` ship only in `kernel-modules-extra`, which
also installs `/etc/modprobe.d/sctp-blacklist.conf` (`blacklist sctp`,
plus `sctp_diag`). An explicit `modprobe sctp` still loads it wherever
the package is installed, so this does not stop a local attacker.

AlmaLinux, CloudLinux and Oracle Linux's Red Hat Compatible Kernel
rebuild RHEL's kernel, so they get the fix as they rebuild Red Hat's
advisories.

### Amazon Linux

The three AL2023 streams are the default `kernel` package (6.1 line) and
the opt-in `kernel6.12` and `kernel6.18` packages.

**Amazon Linux 2 reached end of support on 2026-06-30** and gets no
further core-package security updates — migrate to AL2023.

## Detection

**Is the running kernel in the affected window and missing the fix?** Every
SCTP-capable kernel is in-window; compare the running kernel against the
*Patch status* table's *First fixed* column for its series:

```bash
uname -r
```

**Is the `sctp` module loaded or available?** The bug needs SCTP in use. On
most distributions `sctp` autoloads on first use of an SCTP socket:

```bash
lsmod | grep -E '^sctp'
```

**Can the SCTP and diagnostic modules autoload?** Both `sctp` and
`sctp_diag` must be loadable to reach the bug. A dry-run resolve shows what
`modprobe` would do:

```bash
modprobe -n -v sctp sctp_diag
```

An `install … /bin/false` or `blacklist` entry blocks autoload (Rocky/RHEL
ship one for `sctp` via `kernel-modules-extra`), though an explicit
`modprobe` still loads it:

```bash
grep -rE '(^|[[:space:]])(install|blacklist)[[:space:]]+(sctp|sctp_diag)' /etc/modprobe.d /usr/lib/modprobe.d 2>/dev/null
```

**Is anything issuing SCTP diagnostic dumps?** The overwrite fires when a
`SOCK_DIAG` query walks the peer list, which also autoloads `sctp_diag`.
`ss --sctp` is the common trigger:

```bash
ss -a --sctp 2>/dev/null || ss -a | grep -i sctp
```

## Public PoC

The upstream PoC is in [manizada/DiagSpill][poc]. It grooms the diagnostic
overwrite into page tables, maps physical memory back to userspace, rewrites
a helper process's credentials, installs a sudoers rule, and opens a root
shell; it targets x86-64 with a specific CPU/memory shape (see its README).
It is **destructive** — it overwrites roughly 8 MiB of kernel memory and can
panic the host — so run it only in a disposable VM. Do **not** run it on a
system you are not authorised to test. Absence of your exact target from its
requirements is not safety: the mechanism is fully described and the fix is
public, so patch rather than rely on obscurity.

## Mitigation

The real fix is a patched kernel (the [`bd0e9289e264`][fix] backport). Until
one is installed, the only durable way to remove exposure is to keep the
SCTP datapath from loading — none of the sysctl knobs that help the sibling
bugs help here.

### Disable the `sctp` and `sctp_diag` modules (if you don't use SCTP)

Most hosts never use SCTP. Where it is genuinely unused, block both modules
so the vulnerable code cannot be autoloaded — this also blocks privileged
and container callers. Unload them if present but idle:

```bash
sudo modprobe -r sctp_diag sctp
```

Then keep them from being (re)loaded, including on-demand autoload;
`install … /bin/false` is surer than a plain `blacklist`, which only
suppresses alias-based autoloading:

```bash
printf 'install sctp /bin/false\ninstall sctp_diag /bin/false\n' | sudo tee /etc/modprobe.d/diagspill.conf
```

Only do this where SCTP is genuinely unused — telephony/SIGTRAN gateways,
some Diameter/RADIUS and SS7 stacks, and `lksctp`-based tooling need it.

### Unprivileged user namespaces do not help

Disabling unprivileged user namespaces is a useful mitigation for the three
sibling bugs, but **not for DiagSpill**: reaching the overflow needs no user
namespace and no capability, only the SCTP modules. A user-namespace
lockdown leaves this path fully open.

## Risk notes

- **Any local user is the attack surface:** with `sctp` and `sctp_diag`
  loadable, an unprivileged account builds the oversized association and
  issues the diagnostic dump itself — no user namespace, no capability. This
  is what sets DiagSpill apart from the three bugs disclosed alongside it.
- **Multi-tenant and container hosts:** the demonstrated impact is local
  privilege escalation to root, and the discoverer notes a container with
  the modules available can corrupt the host kernel, so a container-to-host
  escape is plausible though not demonstrated.
- **Remote is DoS-only, and only off-default:** a remote SCTP peer can drive
  the transport count over an association that negotiated ADD-IP, but only
  if the target enabled ASCONF with SCTP-AUTH or
  `net.sctp.addip_noauth_enable=1` (both off by default) **and** something on
  the target issues the diagnostic dump. The discoverer sees no path to
  remote root.
- **No "too old to be affected":** the reachable defect dates to v4.7, so
  old LTS kernels are not safe by age. Every maintained upstream line now
  carries the fix, but distro kernels adopt it independently — check the
  *First fixed* column for the distro in question.
- **Backports available (CVE-2026-74469):** the fix has landed upstream in
  5.10.265, 5.15.216, 6.1.183, 6.6.151, 6.12.103, 6.18.44, 7.1.8, and
  v7.2-rc6; distro kernels that have not adopted one of those remain
  vulnerable.

## Verification log

Every verdict in the table above is backed by a checkable source. This log
records the provenance — the git reference, advisory, or repository index
that established each fact — so any row can be audited or reproduced. Most
readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `bd0e9289e264` (*sctp: prevent peer transport count
  overflow*), first released in **v7.2-rc6** (`git describe --contains` →
  `v7.2-rc6~33^2~36`, tag date 2026-08-02, via `~/src/linux/stable`). It
  adds a `transport_count == U16_MAX` guard to `sctp_assoc_add_peer()` in
  `net/sctp/associola.c`. The fix's author is the discoverer.
- The bug was introduced by `8f840e47f190` (*sctp: add the sctp_diag.c
  file*) in **v4.7** (`describe --contains` → `v4.7-rc1~154^2~269^2~2`) —
  the diagnostic path that reserves its peer payload from `transport_count`.
  Every maintained line is in-window; there are no not-affected rows.
- **CVE-2026-74469** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`, `cve/published/2026/CVE-2026-74469.{json,dyad,cvss}`;
  record keys on `bd0e9289e2642f6a5c54faad304ce0f41e926d22`). The `.dyad`'s
  introduced:fixed pairs are `4.7 → 5.10.265 / 5.15.216 / 6.1.183 /
  6.6.151 / 6.12.103 / 6.18.44 / 7.1.8 / 7.2`.
- **Stable backports** (fix cherry-picks confirmed by subject grep against
  `~/src/linux/stable`, each a new SHA and its branch's first-fixed
  release; *Current kernel* cells from kernel.org's `finger_banner`):
  - 7.1.8 (`6201cd1d70f1`), tagged **2026-08-09**.
  - 6.18.44 (`4ba5bf7ed50f`), tagged **2026-08-09**.
  - 6.12.103 (`09e722030e81`), tagged **2026-08-09**.
  - 6.6.151 (`546221b86cee`), tagged **2026-08-09**.
  - 6.1.183 (`80f48523a0fe`), tagged **2026-08-19**.
  - 5.15.216 (`dfea32dd76f3`), tagged **2026-08-19**.
  - 5.10.265 (`b453e00da121`), tagged **2026-08-19**.
- **v7.2** GA tag dated **2026-08-16**, already containing the fix (landed
  at `v7.2-rc6`), so the new `linux-7.2.y` branch is fixed from its first
  release. **7.1.y** is `(EOL)` at `7.1.13` per `finger_banner`, fixed since
  `7.1.8`, so that row's *Current kernel* is final.

#### Scoring

- **Kernel CNA** (`vulns.git` `.cvss`, `origin/master`): CVSS 3.1 **8.8
  HIGH** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). The CNA scenario
  scores `AV:N` because a remote SCTP peer can add unique transports via
  INIT parameters and ASCONF ADD-IP; `PR:L` because reaching the diagnostic
  path needs an ordinary local account.
- **Red Hat** (hydra `securitydata` and CSAF/VEX, tracking version 3,
  status `final`): CVSS 3.1 revised from the initial **7.0** to **8.3**
  (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`), now matching the
  kernel CNA's `AV:N/AC:L` network vector and differing only in
  integrity impact (`I:L` vs `I:H`).
- **NVD / EPSS / KEV**: NVD record published 2026-08-15, `vulnStatus`
  `Received` (its listed CVSS mirrors the CNA score, not an independent NVD
  assessment); EPSS **0.47%** (39th percentile, via api.first.org, dated
  2026-09-16); not in KEV.

#### Distributions

- **Debian** (security tracker, CVE-2026-74469):
  - sid resolved *fixed*; the tracker's fixed version for unstable is
    `7.1.8-1` (upstream 7.1.8, the 7.1 branch's first fix), first seen
    2026-08-12 per snapshot.debian.org.
  - forky resolved *fixed*; `7.1.8-1` migrated to testing 2026-08-16 (per
    tracker.debian.org news), the suite's first fixed kernel.
  - trixie resolved *fixed*; first fixed `6.12.105-1` via **DSA-6466-1**
    (dated 2026-08-25).
  - bookworm resolved *fixed*; first fixed `6.1.187-1` via **DLA-4777-1**
    (dated 2026-09-08, bookworm-security; first seen 2026-09-08 per
    snapshot).
  - bookworm `linux-6.12` opt-in: the security tracker carries a
    `linux-6.12` entry for this CVE, resolved at `6.12.107-1~deb12u1`
    (past the `6.12.103` first fix); snapshot shows it in debian-security
    since 2026-09-16.
  - bullseye reached end of LTS on **2026-08-31**; the tracker JSON carries
    no bullseye entry for this CVE, and its 5.10-line kernel predates
    `5.10.265`, so both rows are retired — no fix is coming.
  - The suites' *Current kernel* values are read from ftp-master madison
    and the tracker's `<suite>-security` `repositories` entries; the
    bookworm opt-in's from the `bookworm-security` package index.
- **Proxmox VE** (`~/src/proxmox/pve-kernel`, `pve-no-subscription`
  `Packages.gz`):
  - PVE 9 `proxmox-kernel-7.0` fixed via `7.0.14-18` (changelog dated
    2026-09-17): the Ubuntu submodule bump reaches upstream stable
    7.1.8-7.1.13, spanning the branch's `7.1.8` first fix.
  - The same `7.0.14-18` commit drops the standalone SCTP cherry-pick
    patch, staged since 2026-08-18, as redundant.
  - `proxmox-default-kernel` on trixie depends on `proxmox-kernel-7.0`.
  - Preview series abandoned before this disclosure, none carrying the fix:
    PVE 9's `proxmox-kernel-6.17` and `proxmox-kernel-6.14`.
  - PVE 8 `proxmox-kernel-6.8` carries
    `patches/kernel/0105-sctp-prevent-peer-transport-count-overflow.patch`
    (commit `bd0e9289e264` upstream), added in the `6.8.12-43` cycle
    (changelog dated 2026-08-18).
  - `pve-no-subscription` publishes `proxmox-kernel-6.8.12-43-pve`.
  - `proxmox-default-kernel` on bookworm depends on `proxmox-kernel-6.8`.
  - PVE 8 `proxmox-kernel-6.14` opt-in (`bookworm-6.14`, source
    `bookworm-backports`): last built 2026-05-15, no SCTP cherry-pick.
  - Per Ubuntu's CVE tracker, `linux-hwe-6.14` on noble is `ignored` (end
    of life).
  - PVE 8 reached end of life in 2026-08 (Proxmox VE FAQ lifecycle
    table, pve.proxmox.com/wiki/FAQ), before this tracker existed.
- **NixOS** (via `~/src/nixos/nixpkgs`; branch tips for `master` /
  `release-26.05`, channel `git-revision` pins for the other five refs):
  - `linux_default = packages.linux_6_18` on both `master` and
    `release-26.05`.
  - Every tracked ref resolves 6.18 at or above the `6.18.44` first-fixed
    release.
  - Each row's *Current kernel* is the 6.18 version `kernels-org.json`
    resolves at that ref.
  - *Fixed since* for `master` is the commit date of its 6.18.44 bump,
    `510f4c4b5c99` (2026-08-10).
  - *Fixed since* for `release-26.05` is the commit date of its 6.18.44
    bump, `5057e4c81176` (2026-08-09).
  - *Fixed since* for the channel rows comes from
    `scripts/nixos-first-shipped`: nixos-unstable 2026-08-11,
    nixos-unstable-small 2026-08-10, nixpkgs-unstable 2026-08-11,
    nixos-26.05 2026-08-12, nixos-26.05-small 2026-08-10.
- **Rocky / RHEL family** (via Red Hat's securitydata and CSAF/VEX
  record, initial release 2026-08-15; Rocky BaseOS repodata; OSV):
  - EL8/9/10 all carry SCTP and are in-window.
  - The record rates the general EL8/9/10 `kernel` package **Affected**,
    with no `vendor_fix` and no RHSA against it.
  - The record's advisories, all dated **2026-09-24**, each cover only a
    legacy Advanced/Extended/Update-Support product variant, not the
    general EL7/8/9/10 stream; they are listed below by stream.
  - **RHSA-2026:71599**: 10.0 EUS, `kernel-6.12.0-55.107.1.el10_0`.
  - **RHSA-2026:71631**: 9.6 EUS, `kernel-5.14.0-570.144.1.el9_6`.
  - **RHSA-2026:71569**: 9.4 E4S, `kernel-5.14.0-427.152.1.el9_4`.
  - **RHSA-2026:71601** / **71606**: 9.2 E4S,
    `kernel` / `kernel-rt-5.14.0-284.194.1.el9_2`.
  - **RHSA-2026:71594**: 8.8 TUS/E4S, `kernel-4.18.0-477.170.1.el8_8`.
  - **RHSA-2026:71592**: 8.6 AUS/EUS-LL, `kernel-4.18.0-372.218.1.el8_6`.
  - **RHSA-2026:71565**: 8.4 AUS/E4S, `kernel-4.18.0-305.209.1.el8_4`.
  - **RHSA-2026:71657** / **71687**: 7 ELS,
    `kernel-rt` / `kernel-3.10.0-1160.164.1.el7`.
  - `sctp.ko` / `sctp_diag.ko` ship in `kernel-modules-extra`, which also
    installs a `blacklist sctp` modprobe.d file.
  - The Rocky rows' *Current kernel* NVRs are read from BaseOS repodata
    (`primary.xml.gz`, highest `rel`).
  - No AlmaLinux errata or OSV entry exists for this CVE.
- **Amazon Linux** (via the AL2023 `updateinfo.xml.gz`, parsed by
  `scripts/alas-cve`, which is line-safe for the packed `updateinfo.xml`;
  per-stream *Current kernel* from `primary.xml.gz`):
  - **ALAS2023-2026-2143** (2026-09-14) fixes the default `kernel` at
    `6.1.186-228.374.amzn2023`.
  - **ALAS2023-2026-2110** (2026-08-31) fixes `kernel6.12` at
    `6.12.103-127.188.amzn2023`.
  - **ALAS2023-2026-2106** (2026-08-31) fixes `kernel6.18` at
    `6.18.44-99.149.amzn2023`.
{{< /details >}}

## References

| Source | URL |
|---|---|
| oss-security disclosure (quartet) | <https://www.openwall.com/lists/oss-security/2026/09/18/3> |
| Researcher write-up | <https://heyitsas.im/posts/lpe-quartet/> |
| Public PoC | <https://github.com/manizada/DiagSpill> |
| Kernel fix (v7.2-rc6) | <https://git.kernel.org/stable/c/bd0e9289e2642f6a5c54faad304ce0f41e926d22> |
| Introducing commit (v4.7) | <https://git.kernel.org/stable/c/8f840e47f190cbe61a96945c13e9551048d42cef> |
| Stable 5.10.265 | <https://git.kernel.org/stable/c/b453e00da1211e997b82743d28af7714c59c05c8> |
| Stable 5.15.216 | <https://git.kernel.org/stable/c/dfea32dd76f390e3155177b0038cc47b01386198> |
| Stable 6.1.183 | <https://git.kernel.org/stable/c/80f48523a0fe42db2e7375dff4e38a25c117090a> |
| Stable 6.6.151 | <https://git.kernel.org/stable/c/546221b86ceeba0d8fec92d46a0604bb7b62be07> |
| Stable 6.12.103 | <https://git.kernel.org/stable/c/09e722030e8148ba4ed1e42c6b2ea57bda9f9895> |
| Stable 6.18.44 | <https://git.kernel.org/stable/c/4ba5bf7ed50f235ea4581de8e7a0002f4ed287b0> |
| Stable 7.1.8 | <https://git.kernel.org/stable/c/6201cd1d70f1670c5b31ac506e7ab2fa7b8e7f75> |
| CVE-2026-74469 | <https://www.cve.org/CVERecord?id=CVE-2026-74469> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-74469> |
| Red Hat security data | <https://access.redhat.com/security/cve/CVE-2026-74469> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| Sibling: DirtyAH6 (CVE-2026-80844) | <https://kimmo.cloud/dirtyah6/> |
| Sibling: TUNderflow (CVE-2026-81000) | <https://kimmo.cloud/tunderflow/> |
| Sibling: PPPoEject (CVE-2026-68121) | <https://kimmo.cloud/pppoeject/> |
{.references}

[poc]: https://github.com/manizada/DiagSpill
[writeup]: https://heyitsas.im/posts/lpe-quartet/
[ossec]: https://www.openwall.com/lists/oss-security/2026/09/18/3
[fix]: https://git.kernel.org/stable/c/bd0e9289e2642f6a5c54faad304ce0f41e926d22
[intro]: https://git.kernel.org/stable/c/8f840e47f190cbe61a96945c13e9551048d42cef
