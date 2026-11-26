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
    tas-nix.url = "git+https://github.com/Ptyktos/caretaker?dir=nix&rev=b8cda7e4590c8aa6576d834c6363a6266ae5b9d8&shallow=1";

    saga = {
      url = "git+https://github.com/Tasmanian-Cloud/saga?rev=c82647b7094aba9e3fb673b1b1b5577a6af759cb&shallow=1";
      flake = false;
    };
    servelet = {
      url = "git+https://github.com/Ptyktos/servelet?rev=fbaaaadc2d64236f8f2f3079bd9fde2dbd4a52bb&shallow=1";
      flake = false;
    };
    legacy-hashtrinity = {
      url = "git+https://github.com/Ptyktos/hashtrinity?rev=f74bc22288faa08625637ee810977cd0064e11e5&shallow=1";
      flake = false;
    };
    iotadb = {
      url = "git+https://github.com/webfold-ai/iotadb?rev=208e6e94a2ad00c226c2030776045f8d465cdb93&shallow=1";
      flake = false;
    };
    apeiron-legacy = {
      url = "git+https://github.com/webfold-ai/apeiron?rev=1c3d4a1da565cde409f6f3cb343086aa6853eb9c&shallow=1";
      flake = false;
    };
    apeiron-store = {
      url = "git+https://github.com/webfold-ai/apeiron?rev=d0eda3226193542949306f767d7280404921546f&shallow=1";
      flake = false;
    };
    apeiron = {
      url = "git+https://github.com/webfold-ai/apeiron?rev=85b404b8dc89903c5c588a2cd1d10bfa5b9e64bc&shallow=1";
      flake = false;
    };
    wirefold = {
      url = "git+https://github.com/webfold-ai/wirefold?rev=98df8bfb8051fb24ca43ce3ddc446641684ef8f9&shallow=1";
      flake = false;
    };
  };

  outputs =
    { tas-nix, ... }@inputs:
    tas-nix.lib.mkRustFlake {
      name = "transport";
      src = ./.;
      # No rust-toolchain.toml in this repository: the compiler is named here.
      rustChannel = "1.99.0";
      bins = {
        meshd = { };
        tas-lb = { };
        tas-dns = { };
        edge-lb = { };
        mesh-acl-reconciler = { };
      };
      cargoExtraArgs = "--locked --workspace";
      # Consumer-specific integration runs downstream, not as a dependency here.
      gitInputs = {
        "https://github.com/Tasmanian-Cloud/saga" = inputs.saga;
        "https://github.com/Ptyktos/servelet" = inputs.servelet;
        "https://github.com/Ptyktos/hashtrinity" = inputs.legacy-hashtrinity;
        "https://github.com/webfold-ai/iotadb" = inputs.iotadb;
        "https://github.com/webfold-ai/apeiron" = inputs.apeiron;
        "https://github.com/webfold-ai/apeiron#1c3d4a1da565cde409f6f3cb343086aa6853eb9c" = inputs.apeiron-legacy;
        "https://github.com/webfold-ai/apeiron#d0eda3226193542949306f767d7280404921546f" = inputs.apeiron-store;
        "https://github.com/webfold-ai/wirefold" = inputs.wirefold;
      };
      # The reviewed cargo-deny policy: the shared default plus two recorded exceptions (see deny.toml).
      denyConfig = ./deny.toml;
      # include_str!/include_bytes! read tests/fixtures; the default source filter drops them.
      extraSourceFilter = path: _type: builtins.match ".*/tests/fixtures(/.*)?" path != null;
      # The doc gate is off: `cargo doc --no-deps` reports 109 unresolved intra-doc links across the
      # crate (links written against module paths that do not resolve), and `-D warnings` rejects them.
      # Fixing them is a documentation pass, not packaging; turn the gate back on with it.
      gates.doc = false;
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
