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
            # Build and publish the Hugo site.
            hugo
            go
            git

            # Rasterise the social banner SVG -> PNG (`make banner`).
            resvg

            # Distro kernel-config verification: fetch and unpack RPMs.
            # `bsdtar` (from libarchive) unpacks .rpm directly, including
            # zstd-compressed payloads — no `rpm` / `rpm2cpio` + `cpio`
            # needed. nixpkgs has no standalone `rpm2cpio` derivation.
            curl
            libarchive
            zstd
          ];
        };
      });
    };
}
