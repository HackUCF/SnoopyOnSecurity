{
  description = "Red Baron 2: A Crane-based Nix build for the rb2 binary";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
    yara-rules = {
      url = "https://github.com/nmagill123/compiled-yara-rules-rb2/releases/download/v20260102-152737/linux.tar.xz";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      yara-rules,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        lib = pkgs.lib;

        muslPkgs = pkgs.pkgsCross.musl64;

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ "x86_64-unknown-linux-musl" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = craneLib.path ./.;

        # Common dev tooling (host)
        commonBuildInputs = with pkgs; [
          clang
          llvm
          stdenv.cc
        ];

        # Inputs for musl cross builds (target-side libs come from muslPkgs)
        muslBuildInputs =
          commonBuildInputs
          ++ (with muslPkgs; [
            libbpf
          ]);

        # Minimal helper to put libbpf.a where the Makefile expects it
        libbpfSetup = pkgsSet: ''
          mkdir -p rb2-ebpf/libbpf/src
          cp ${pkgsSet.libbpf}/lib/libbpf.a rb2-ebpf/libbpf/src/
        '';

        # Helper to copy YARA rules to yara_linux directory
        # Note: yara-rules is already extracted by Nix since it's a tarball input
        yaraRulesSetup = ''
          if [ ! -d yara_linux ]; then
            echo "Copying YARA rules from ${yara-rules} to yara_linux/"
            cp -r ${yara-rules} yara_linux
            chmod -R u+w yara_linux
          fi
        '';

        # Env blocks
        baseEnv = {
          NIX_HARDENING_ENABLE = "";
          RUST_BACKTRACE = "1";
        };

        nativeCEnv = pkgsSet: {
          PKG_CONFIG_PATH = "${pkgsSet.elfutils.dev}/lib/pkgconfig:${pkgsSet.zlib.dev}/lib/pkgconfig:${pkgsSet.libbpf}/lib/pkgconfig";
          CFLAGS = "-I${pkgsSet.elfutils.dev}/include -I${pkgsSet.zlib.dev}/include -I${pkgsSet.libbpf}/include";
          LDFLAGS = "-L${pkgsSet.elfutils}/lib -L${pkgsSet.zlib}/lib -L${pkgsSet.libbpf}/lib";
          C_INCLUDE_PATH = "${pkgsSet.elfutils.dev}/include:${pkgsSet.zlib.dev}/include:${pkgsSet.libbpf}/include";
          LIBRARY_PATH = "${pkgsSet.elfutils}/lib:${pkgsSet.zlib}/lib:${pkgsSet.libbpf}/lib";
        };

        muslCrossEnv = {
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CC_x86_64_unknown_linux_musl = "${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CXX_x86_64_unknown_linux_musl = "${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++";
          AR_x86_64_unknown_linux_musl = "${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar";
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static -C link-arg=-lm";
        }
        // (nativeCEnv muslPkgs);

        # One helper to make all crane builds with minimal duplication
        mkCrane =
          {
            pname,
            version ? "0.1.0",
            inputs,
            env,
            pre ? "",
            cargoArtifacts ? null,
            kind ? "package", # "package" | "deps" | "clippy" | "test" | "fmt"
            extra ? { },
          }:
          let
            core = {
              inherit src pname version;
              nativeBuildInputs = inputs;
              preBuild = pre;
            }
            // env
            // baseEnv
            // extra;
          in
          if kind == "deps" then
            craneLib.buildDepsOnly core
          else if kind == "clippy" then
            craneLib.cargoClippy (
              core
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- --deny warnings";
              }
            )
          else if kind == "test" then
            craneLib.cargoTest (core // { inherit cargoArtifacts; })
          else if kind == "fmt" then
            craneLib.cargoFmt core
          else
            craneLib.buildPackage (
              core // lib.optionalAttrs (cargoArtifacts != null) { inherit cargoArtifacts; }
            );

        # Artifacts
        deps-musl = mkCrane {
          pname = "rb2-deps";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          kind = "deps";
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
            export CRANE_BUILD_DEPS_ONLY=1
          '';
        };

        # Build targets
        rb2 = mkCrane {
          pname = "rb2";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          cargoArtifacts = deps-musl;
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
          '';
          extra = {
            doCheck = false;
            meta = with lib; {
              description = "Red Baron 2 binary built with Crane, statically linked with musl";
              license = licenses.mit;
              maintainers = [ "yourname" ];
            };
          };
        };

        rb2-clippy = mkCrane {
          pname = "rb2-clippy";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          cargoArtifacts = deps-musl;
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
          '';
          kind = "clippy";
        };

        rb2-test = mkCrane {
          pname = "rb2-test";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          cargoArtifacts = deps-musl;
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
          '';
          kind = "test";
        };

        rb2-fmt = mkCrane {
          pname = "rb2-fmt";
          inputs = [ ];
          env = baseEnv;
          kind = "fmt";
        };

      in
      {
        packages = {
          default = rb2;
          red-baron = rb2;

          clippy = rb2-clippy;
          test = rb2-test;
          fmt = rb2-fmt;
        };

        checks = {
          inherit
            rb2
            rb2-clippy
            rb2-test
            rb2-fmt
            ;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = muslBuildInputs ++ [
            rustToolchain
            pkgs.cargo-bloat
            pkgs.cargo-edit
            pkgs.rust-analyzer
            
            pkgs.llvmPackages.bintools
            pkgs.bpftools
            pkgs.linuxPackages.bpftrace
            pkgs.linuxPackages.bcc
          ];

          NIX_HARDENING_ENABLE = "";
          RUST_BACKTRACE = "1";

          shellHook = ''
            # ensure libbpf is placed once per shell
            if [ ! -e rb2-ebpf/libbpf/src/libbpf.a ]; then
              ${libbpfSetup muslPkgs}
            fi
            # ensure yara rules are extracted once per shell
            if [ ! -d yara_linux ]; then
              ${yaraRulesSetup}
            fi
            # convenience exports for musl cross
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc"
            export CC_x86_64_unknown_linux_musl="${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc"
            export CXX_x86_64_unknown_linux_musl="${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++"
            export AR_x86_64_unknown_linux_musl="${muslPkgs.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar"
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-lm"

            echo "Development environment ready!"
            echo ""
            echo "Available commands:"
            echo "  For musl cross-compilation: cargo build --release"
            echo "  For production (statically linked): nix build"
            echo ""
            echo "Crane-specific commands:"
            echo "  Check code: nix build .#clippy"
            echo "  Run tests: nix build .#test"
            echo "  Check formatting: nix build .#fmt"
            echo ""
            echo "Output locations:"
            echo "  Musl binary: target/x86_64-unknown-linux-musl/release/rb2"
            echo "  Production binary: result/bin/rb2"

          '';
        };
      }
    );
}
