# DiagSpill — Linux kernel SCTP sock_diag heap overflow tracking site

Source for the **DiagSpill** patch-status tracker: a single-page site
recording which distributions have shipped a fix for the SCTP peer
transport-count overflow in the Linux kernel (CVE-2026-74469), an
unprivileged local-user path to an ~8 MiB kernel heap overwrite via
`sctp_diag`.

## Where the facts live

Everything about the bug — CVE IDs, affected and fixed versions, upstream
fix commits, discovery and disclosure credit, and current per-distribution
patch status — belongs to the tracker page, not to this README:

- **Rendered:** <https://kimmo.cloud/diagspill/>
- **Source:** [`site/content/_index.md`](site/content/_index.md)

Edit that file; everything else in this repo is build infrastructure.

None of it is restated here on purpose.  The tracker page is revised as
CVEs are assigned and distributions ship fixes — twice daily by the
auto-update agent while the tracker is live — so any copy kept in this
README would silently rot.  Resist re-adding a summary.

Deployment plan and current setup state live in [`WEBSITE.md`](WEBSITE.md).

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

```sh
nix develop          # dev shell: hugo, go, git, resvg
cd site
hugo server          # local preview at http://localhost:1313/diagspill/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the dev
shell auto-activates whenever you `cd` into the repo.

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/diagspill/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + Roboto)
```

`make dist` runs `make build` first. `make banner` is only needed after
editing `site/assets/diagspill-tracker.svg`; the rendered PNG is committed.

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
