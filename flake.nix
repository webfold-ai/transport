# transport: the native transport kernel, and `meshd` (the internal service-discovery node), built
# with caretaker-nix: reproducible, sandboxed Crane builds, one derivation per gate, an SBOM, and an
# OCI image whose manifest digest is known before any push.
#
#   nix build .#meshd                    the binary
#   nix build .#meshd-oci                docker archive:  docker load < result
#   nix build .#meshd-oci-layout         OCI layout (manifest digest = index.json)
#   nix build .#meshd-sbom               CycloneDX SBOM
#   nix run   .#repro-check -- .#meshd   build twice, compare byte for byte
#   nix flake check                      every gate that is switched on below
#
# Only git-tracked files are visible to Nix: `git add` before building.
#
# The git dependencies of Cargo.lock are inputs here, pinned by rev, because a build never touches
# the network. Each rev MUST equal the one in Cargo.lock; the build fails if it does not. They move
# with Cargo.lock (Ptyktos/caretaker: `caretaker-pins`, docs/git-pins.md), not by hand.
{
  description = "transport: the native transport kernel and meshd";

  inputs = {
    # The build layer, by revision (flake.lock records the narHash too).
    tas-nix.url = "git+https://github.com/Ptyktos/caretaker?dir=nix&ref=claude/confident-hamilton-u5lcc4-pins-init&rev=247943bcaf1e537885aa4dd9aeb363c670888e10&shallow=1";

    relayfold = {
      url = "git+https://github.com/Ptyktos/relayfold?rev=69084250929ca64f526ee86007e0a7f3ef402c32&shallow=1";
      flake = false;
    };
    apeiron = {
      url = "git+https://github.com/webfold-ai/apeiron?rev=1c3d4a1da565cde409f6f3cb343086aa6853eb9c&shallow=1";
      flake = false;
    };
    wirefold = {
      url = "git+https://github.com/webfold-ai/wirefold?rev=ed1ffdf4d34a86ab60e128ea14d2475e57650946&shallow=1";
      flake = false;
    };
  };

  outputs =
    { tas-nix, ... }@inputs:
    tas-nix.lib.mkRustFlake {
      name = "transport";
      src = ./.;
      # No rust-toolchain.toml in this repository: the compiler is named here.
      rustChannel = "1.97.0";
      bins = {
        meshd = { };
      };
      gitInputs = {
        "https://github.com/Ptyktos/relayfold" = inputs.relayfold;
        "https://github.com/webfold-ai/apeiron" = inputs.apeiron;
        "https://github.com/webfold-ai/wirefold" = inputs.wirefold;
      };
      # The reviewed cargo-deny policy: the shared default plus two recorded exceptions (see deny.toml).
      denyConfig = ./deny.toml;
      # A gate is switched off only with a reason on record. fmt: this repository is not rustfmt-clean
      # (1,656 hunks across 45 files that predate this flake); a repository-wide reformat is a
      # maintainers' decision, since it touches every open change. New files are formatted. Turn this
      # back on after that pass.
      #
      # clippy and doc: `cargo clippy/doc -D warnings` fails on warnings that predate this flake
      # (`unexpected cfg feature "bind-overlay"` in lib.rs/discovery.rs, which Cargo.toml never
      # declares, and several unused imports). Declaring the feature and clearing the imports is a
      # change to the library's own code, not to its packaging, so it is left for its own PR; turn
      # these back on with it.
      gates = {
        fmt = false;
        clippy = false;
        doc = false;
      };
      # include_str!/include_bytes! read tests/fixtures; the default source filter drops them.
      extraSourceFilter = path: _type: builtins.match ".*/tests/fixtures(/.*)?" path != null;
      # aws-lc-sys (the crypto provider under rustls) builds C and wants cmake.
      extraNativeBuildInputs = pkgs: [ pkgs.cmake ];

      oci.meshd = {
        # Records persist here; owned by the image's non-root user so a fresh volume is writable.
        dirs = [ "/var/lib/meshd" ];
        env = {
          MESHD_HTTP_BIND = "0.0.0.0:6881";
          MESHD_DNS_BIND = "0.0.0.0:5353";
          MESHD_DATA_DIR = "/var/lib/meshd";
          MESHD_ZONE = "mesh.internal";
        };
        ports = [
          "6881/tcp"
          "5353/udp"
          "5353/tcp"
        ];
        labels = {
          "org.opencontainers.image.licenses" = "Apache-2.0";
          "org.opencontainers.image.description" = "Internal service discovery: a pkarr relay and an authoritative DNS zone for dialkey-published services.";
        };
      };
    };
}
