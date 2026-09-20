{
  description = "kimmo.cloud/diagspill — Hugo build + tracker-maintenance environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs
        [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ]
        (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # Build the Hugo site (Hugo Modules pull PaperMod via go + git).
            hugo
            go
            git

            # Rasterise the social banner SVG -> PNG (`make banner`). The
            # SVG's font stacks resolve on Linux to Roboto (sans) and
            # Liberation Mono (mono); resvg finds them through fontconfig
            # (FONTCONFIG_FILE below).
            resvg
            roboto
            liberation_ttf

            # Publish (`make dist`).
            rsync
            openssh

            # The auto-update wrapper and the lookup recipes in CLAUDE.md:
            # jq assembles the headless allowlist, xq (sibprogrammer's; the
            # nixpkgs attr is xq-xml) answers the Rocky changelog XPath,
            # rpm provides rpmsort for EL build ordering, python3 runs
            # scripts/alas-cve and `make check`. The rest are the base
            # tools the recipes and helpers pipe through; listed so the
            # shell is complete on its own rather than leaning on the host.
            curl
            jq
            xq-xml
            rpm
            python3
            gzip
            coreutils
            findutils
            gnugrep
            gnused
            gawk

            # Unpack a kernel RPM by hand (`bsdtar -xOf kernel-*.rpm`),
            # zstd payloads included; no rpm2cpio + cpio needed.
            libarchive
            zstd
          ];

          # resvg reads fontconfig; point it at the banner fonts (the host's
          # /usr/share/fonts stays included via makeFontsConf's impure dirs).
          FONTCONFIG_FILE = pkgs.makeFontsConf {
            fontDirectories = [ pkgs.roboto pkgs.liberation_ttf ];
          };
        };
      });
    };
}
