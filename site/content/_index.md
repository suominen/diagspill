---
title: "DiagSpill — SCTP sock_diag transport-count overflow"
description: "Linux kernel SCTP sock_diag heap overflow (CVE-2026-74469, DiagSpill) — an unprivileged local user overflows the kernel heap by ~8 MiB with no user namespace or capability — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-09-21
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
| KEV / EPSS / CVSS | Not in KEV. EPSS **0.47%** (39th percentile). Two CVSS vantage points: **kernel CNA / NVD** 3.1 **8.8 HIGH** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), scoring a remote SCTP peer driving the transport count; **Red Hat** 3.1 **7.0** (`AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`), scoring the demonstrated local path. See *Scoring* below |
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
| Linux kernel | mainline | 7.3-rc4 | 7.2-rc6 | 2026-08-02 | :white_check_mark: Fixed — carries `bd0e9289e264` |
| Linux kernel | 7.2.x | 7.2.7 | 7.2 | 2026-08-16 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.13 | 7.1.8 | 2026-08-09 | :white_check_mark: Fixed — EOL |
| Linux kernel | 6.18.x | 6.18.53 | 6.18.44 | 2026-08-09 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.111 | 6.12.103 | 2026-08-09 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.157 | 6.6.151 | 2026-08-09 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.188 | 6.1.183 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.221 | 5.15.216 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.270 | 5.10.265 | 2026-08-19 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.2.6-1 | 7.1.8-1 | 2026-08-12 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.13-1 | 7.1.8-1 | 2026-08-16 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.107-1 | 6.12.105-1 | 2026-08-25 | :white_check_mark: Fixed — DSA-6466-1 |
| Debian | 12 (bookworm) | 6.1.187-1 | 6.1.187-1 | 2026-09-08 | :white_check_mark: Fixed — DLA-4777-1 |
| Debian | 12 (6.12 opt-in) | 6.12.107-1~deb12u1 | 6.12.107-1~deb12u1 | 2026-09-16 | :white_check_mark: Fixed |
| Proxmox VE | 9 (default) | 7.0.14-19-pve | 7.0.14-18-pve | 2026-09-17 | :white_check_mark: Fixed — folded into Ubuntu-resolute rebase |
| Proxmox VE | 8 (default) | 6.8.12-43-pve | 6.8.12-43 | 2026-08-18 | :white_check_mark: Fixed — cherry-pick |
| Proxmox VE | 8 (6.14 opt-in) | 6.14.11-9~bpo12+1 | — | — | :x: Vulnerable |
| NixOS | master | 6.18.52 | 6.18.44 | 2026-08-10 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.52 | 6.18.44 | 2026-08-09 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.52 | 6.18.44 | 2026-08-11 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.52 | 6.18.44 | 2026-08-10 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.52 | 6.18.44 | 2026-08-11 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.52 | 6.18.44 | 2026-08-12 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.52 | 6.18.44 | 2026-08-10 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.56.1.el10_2.0.1 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 9 | 5.14.0-687.49.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 8 | 4.18.0-553.164.1.el8_10 | — | — | :x: Vulnerable — no RHSA yet |
| Amazon Linux | 2023 (default) | 6.1.186-228.376 | 6.1.186-228.374 | 2026-09-14 | :white_check_mark: Fixed — ALAS2023-2026-2143 |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.103-129.197 | 6.12.103-127.188 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2110 |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.48-109.150 | 6.18.44-99.149 | 2026-08-31 | :white_check_mark: Fixed — ALAS2023-2026-2106 |
{.distros}

### Linux kernel

The fix reached Linus in **v7.2-rc6** (tagged 2026-08-02) and the kernel
CNA backported it across the maintained stable lines in two waves. The
first, on **2026-08-09**, covered **6.6.151** (`546221b86cee`), **6.12.103**
(`09e722030e81`), **6.18.44** (`4ba5bf7ed50f`), and **7.1.8**
(`6201cd1d70f1`) — each the same fix by subject, confirmed present on its
`linux-*.y` branch. The three older long-term lines followed on
**2026-08-19**: **6.1.183** (`80f48523a0fe`), **5.15.216**
(`dfea32dd76f3`), and **5.10.265** (`b453e00da121`). Every maintained
upstream line now carries the fix.

**v7.2** was released on **2026-08-16**; since the fix landed by `v7.2-rc6`,
the GA release and the new `7.2.x` stable branch carry it from the start.
**7.1.x reached end of life at `7.1.13`** per `kernel.org`'s
`finger_banner`, already fixed since `7.1.8`, so that row's verdict is
settled and its *Current kernel* stops moving.

To confirm a fix in a tree directly, the change is three lines in
`sctp_assoc_add_peer()` (`net/sctp/associola.c`): a
`if (asoc->peer.transport_count == U16_MAX) return NULL;` guard added
before `sctp_transport_new()`.

### Debian

Debian's status splits on which upstream branch each suite tracks.
**sid** carries the 7.1 line and has been fixed since the `7.1.8-1` upload
(upstream 7.1.8 is the 7.1 branch's first-fixed release); **forky**
(testing, the future Debian 14) since that same `7.1.8-1` migrated to
testing. **trixie** (Debian 13) shipped `6.12.105-1` through **DSA-6466-1**,
past the 6.12 branch's `6.12.103` first fix. **bookworm** (Debian 12, now
on LTS) is fixed via **DLA-4777-1**, a `bookworm-security` upload of
`6.1.187-1` — well past the 6.1 branch's `6.1.183` first fix.

bookworm also offers an **opt-in newer kernel**, the `linux-6.12` source
package (the trixie 6.12 kernel rebuilt for bookworm and shipped through
`bookworm-security`). Its earlier `6.12.101-1~deb12u1` build predated the
fix; its `6.12.107-1~deb12u1` build (past `6.12.103`) carries it. The
security tracker does not assess this CVE against the opt-in package by
name, so its verdict is a version compare against the branch's first-fixed
release.

**bullseye (Debian 11) reached the end of its LTS support window on
2026-08-31** and gets no rows here: the security tracker no longer carries a
bullseye entry for this CVE, and its 5.10-line kernel predates the `5.10.265`
first fix. It is permanently **vulnerable** — no further update is coming
through the standard LTS, so a host still on bullseye should upgrade to
bookworm or newer.

SCTP is not built into Debian's kernel image; it ships as the `sctp` module,
autoloaded on first use of an SCTP socket and not blacklisted by default, so
any host running an SCTP service loads the vulnerable code. `sctp_diag`
autoloads the same way when a diagnostic query runs.

### Proxmox VE

Proxmox ships its own kernels, so Debian's status does not carry over.
**PVE 8's `proxmox-kernel-6.8`** backports the fix as a named cherry-pick
(`…-sctp-prevent-peer-transport-count-overflow.patch`), first in
**`6.8.12-43`** (2026-08-18). The 6.8 base is old, but the Ubuntu-derived
kernel carries SCTP and received the cherry-pick, so a pre-fix Proxmox
series is not safe by base version alone.

**PVE 9's `proxmox-kernel-7.0`** is **fixed**, but not through the
cherry-pick Proxmox had staged for it: that standalone patch first
appeared in git on 2026-08-18 but never reached `pve-no-subscription`
before the kernel's regular Ubuntu-resolute rebase overtook it.
**`7.0.14-18`** (2026-09-17) bumped the Ubuntu submodule through upstream
stable **7.1.8–7.1.13** — which already carries `bd0e9289e264` — so the
now-redundant standalone cherry-pick was dropped in the same rebase.

PVE 8 additionally offers `proxmox-kernel-6.14` as a `bookworm-backports`
opt-in for newer hardware support. It is **vulnerable**: its Ubuntu base
predates Ubuntu's own fix, it carries no cherry-pick, and Ubuntu's
`linux-hwe-6.14` on noble is end-of-life, so no further Ubuntu-side rebase
will bring the fix — only a direct Proxmox cherry-pick would close it, and
none has landed.

Both releases also still publish pre-GA preview kernel series that Proxmox
abandoned before this disclosure and that never received the fix — PVE 9's
`proxmox-kernel-6.14` and `proxmox-kernel-6.17`, and PVE 8's
`proxmox-kernel-6.2` and `proxmox-kernel-6.5`. No fix is coming for any of
them; a host still booting one of these preview kernels stays vulnerable
until it switches to its release's current default kernel.

### NixOS

Every tracked ref's default `linuxPackages` is `linux_6_18`, at or above the
6.18 branch's `6.18.44` first-fixed release, so every tracked ref is
**fixed**; they differ only in which point release each has reached. Kernel
updates land on nixpkgs `master` first, and each channel publishes them once
its Hydra jobset passes, so a channel can sit a few days behind `master`,
and an unstable channel is not necessarily ahead of a release channel. The
`-small` channels are gated on a reduced jobset and pick up kernel updates
fastest. nixpkgs also currently pins `linux_6_1` / `linux_5_15` /
`linux_5_10` / `linux_6_6` / `linux_6_12` at or above their first-fixed
releases, so a host overriding the default to one of those on a current-enough
ref is fixed as well.

The `master` and `release-26.05` rows are the git branches the fix lands
on; they are not Hydra-gated, so they carry the kernel bump from the moment
the commit lands — typically a day or more before a channel republishes it,
which the *Fixed since* dates down the group reflect. They are development
branches, not deployment targets. A bare `github:NixOS/nixpkgs` follows
`master`; `github:NixOS/nixpkgs/nixos-unstable` tracks the `nixos-unstable`
channel; a bare `nixpkgs` registry input resolves to `nixpkgs-unstable`, a
separate channel not gated on the NixOS tests.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry SCTP, so all three
in-support lines — EL10 (6.12-based), EL9 (5.14-based), EL8 (4.18-based) —
are in-window. Red Hat published a CVE assessment (initial release
2026-08-15) rating the kernel **Affected** across EL8/9/10 but has **not**
shipped a fix — no `vendor_fix` remediation and no RHSA — so every stream is
**vulnerable pending an advisory**.

Module posture reduces reachability on a stock EL host: `sctp.ko` and
`sctp_diag.ko` are not in the base kernel packages but in
**`kernel-modules-extra`**, which installs
`/etc/modprobe.d/sctp-blacklist.conf` (`blacklist sctp`, plus `sctp_diag`)
alongside them. So `sctp` never autoloads on a stock EL host — without
`kernel-modules-extra` the modules are absent, and with it the blacklist
suppresses autoload. An explicit `modprobe sctp` still loads it where the
package is installed, so this does not close the local vector. Rocky
rebuilds RHEL unchanged, so its fixes track Red Hat's; AlmaLinux is
typically the fastest rebuild and the leading indicator. Oracle Linux and
CloudLinux track the RHEL determination.

### Amazon Linux

All three AL2023 kernel streams are now **fixed**, on staggered advisories.
The `kernel6.18` opt-in shipped **ALAS2023-2026-2106** (2026-08-31) at
`6.18.44-99.149`, and the `kernel6.12` opt-in **ALAS2023-2026-2110**
(2026-08-31) at `6.12.103-127.188` — both at their branch's first fix. The
**default `kernel` stream (6.1 line)** shipped later, in
**ALAS2023-2026-2143** (2026-09-14), fixing it at `6.1.186-228.374` — past
the 6.1 branch's `6.1.183` first fix. AL2 reached end of support on
2026-06-30 and gets no rows; it is out of scope for further core-package
security updates.

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
  `~/src/linux/stable`, each a new SHA): 6.6.151 (`546221b86cee`), 6.12.103
  (`09e722030e81`), 6.18.44 (`4ba5bf7ed50f`), 7.1.8 (`6201cd1d70f1`) — all
  tagged **2026-08-09**; 6.1.183 (`80f48523a0fe`), 5.15.216
  (`dfea32dd76f3`), 5.10.265 (`b453e00da121`) — all tagged **2026-08-19**,
  each its branch's first-fixed release. The `Linux kernel` rows' *Current
  kernel* cells are read from kernel.org's `finger_banner`.
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
- **Red Hat** (hydra `securitydata` and CSAF/VEX, initial release
  2026-08-15): CVSS 3.1 **7.0** (`CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`),
  scoring `AV:L`/`AC:H` for the demonstrated local path and the effort of
  amassing 65,536 transports. The divergence is vantage point, not
  disagreement on the flaw.
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
  - bookworm `linux-6.12` opt-in: the security tracker does not assess this
    CVE against the source package by name; snapshot lists only
    `6.12.100-1~deb12u1`, `6.12.101-1~deb12u1` (both pre-fix), and
    `6.12.107-1~deb12u1` (in debian-security since 2026-09-16, past the
    `6.12.103` first fix), so first-fixed is `6.12.107-1~deb12u1` by version
    compare.
  - bullseye reached end of LTS on **2026-08-31**; the tracker JSON carries
    no bullseye entry for this CVE, and its 5.10-line kernel predates
    `5.10.265`, so both rows are retired — no fix is coming.
  - The suites' *Current kernel* values are read from ftp-master madison
    and the tracker's `<suite>-security` `repositories` entries; the
    bookworm opt-in's from the `bookworm-security` package index.
- **Proxmox VE** (`~/src/proxmox/pve-kernel`, `pve-no-subscription`
  `Packages.gz`):
  - PVE 8 `proxmox-kernel-6.8` carries
    `patches/kernel/0105-sctp-prevent-peer-transport-count-overflow.patch`
    (commit `bd0e9289e264` upstream), added in the `6.8.12-43` cycle
    (changelog dated 2026-08-18); `pve-no-subscription` publishes
    `proxmox-kernel-6.8.12-43-pve`. `proxmox-default-kernel` on bookworm
    depends on `proxmox-kernel-6.8`.
  - PVE 9 `proxmox-kernel-7.0` fixed via `7.0.14-18` (changelog dated
    2026-09-17): the Ubuntu submodule bump reaches upstream stable
    7.1.8-7.1.13, spanning the branch's `7.1.8` first fix, and the same
    commit drops the standalone SCTP cherry-pick patch staged since
    2026-08-18 as now redundant. `proxmox-default-kernel` on trixie
    depends on `proxmox-kernel-7.0`.
  - PVE 8 `proxmox-kernel-6.14` opt-in (`bookworm-6.14`, source
    `bookworm-backports`): newest `6.14.11-9~bpo12+1` (2026-05-15), no SCTP
    cherry-pick; per Ubuntu's CVE tracker `linux-hwe-6.14` on noble is
    `ignored` (end of life), so no Ubuntu rebase will bring the fix.
  - Preview series abandoned before this disclosure, none carrying the fix:
    PVE 9's `proxmox-kernel-6.14`/`6.17`, PVE 8's
    `proxmox-kernel-6.2`/`6.5` — prose only, no rows.
- **NixOS** (`~/src/nixos/nixpkgs`): `linux_default = packages.linux_6_18`
  on both `master` and `release-26.05`; every tracked ref resolves 6.18 at
  or above the `6.18.44` first-fixed release, so all seven rows are fixed.
  Each row's *Current kernel* is the 6.18 version `kernels-org.json`
  resolves at that ref (branch tips for `master` / `release-26.05`, channel
  `git-revision` pins for the other five). *Fixed since*: the branch rows
  use the commit date of the 6.18.44 bump (`510f4c4b5c99` on master,
  2026-08-10; `5057e4c81176` on release-26.05, 2026-08-09); the channel
  rows use `scripts/nixos-first-shipped` (nixos-unstable 2026-08-11,
  nixos-unstable-small 2026-08-10, nixpkgs-unstable 2026-08-11, nixos-26.05
  2026-08-12, nixos-26.05-small 2026-08-10).
- **Rocky / RHEL family**: Red Hat's securitydata/VEX record (initial
  release 2026-08-15) rates the kernel **Affected** across EL8/9/10 with no
  `vendor_fix` and no RHSA, so no fix has shipped. EL8/9/10 all carry SCTP
  and are in-window. `sctp.ko`/`sctp_diag.ko` ship in
  `kernel-modules-extra`, which also installs a `blacklist sctp`
  modprobe.d file. The Rocky rows' *Current kernel* NVRs are read from
  BaseOS repodata (`primary.xml.gz`, highest `rel`). No AlmaLinux errata or
  OSV entry for this CVE yet.
- **Amazon Linux**: the AL2023 `updateinfo.xml.gz` carries three references
  to CVE-2026-74469 — **ALAS2023-2026-2106** (2026-08-31) fixes `kernel6.18`
  at `6.18.44-99.149.amzn2023`; **ALAS2023-2026-2110** (2026-08-31) fixes
  `kernel6.12` at `6.12.103-127.188.amzn2023`; **ALAS2023-2026-2143**
  (2026-09-14) fixes the default `kernel` at `6.1.186-228.374.amzn2023`. The
  per-stream *Current kernel* values are read from `primary.xml.gz` (parsed
  by `scripts/alas-cve`, which is line-safe for the packed `updateinfo.xml`).
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
