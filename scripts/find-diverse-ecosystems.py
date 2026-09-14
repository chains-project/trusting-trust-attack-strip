#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

ECOSYSTEM_MARKERS = {
    "Rust": [
        b"core::panicking::panic",
        b"std::sys::unix::thread",
        b"alloc::alloc::handle_alloc_error",
        b"rust_panic_with_hook",
        b"lang_start_internal",
        b"libstd-",
    ],
    "Go": [
        b"runtime.main",
        b"runtime.gopanic",
        b"runtime.morestack",
        b"go.buildid",
        b"go:itab.",
        b"type:.",
    ],
    "Haskell (GHC)": [
        b"GHC.IO.",
        b"ghc-prim",
        b"rts_lockIdle",
        b"stg_returnToStackTop",
        b"ZCMain_main",
    ],
    "OCaml": [
        b"caml_main",
        b"caml_alloc",
        b"caml_string_length",
        b"Caml_state",
    ],
    "JavaScript (Node.js + V8)": [
        b"v8::internal::",
        b"v8::HandleScope::",
        b"node::Start",
        b"node::CreateEnvironment",
        b"libnode.so",
    ],
    "Mono / C# (.NET)": [
        b"mono_runtime",
        b"mono_class_from_name",
        b"Mono.Runtime",
        b"Mono.Interop",
        b"Microsoft.CSharp",
    ],
    "Lua": [
        b"lua_pushvalue",
        b"lua_pcallk",
        b"luaopen_base",
        b"LUA_VERSION",
    ],
}


def has_marker(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["readelf", "-SW", "--wide", str(path)],
            capture_output=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return b"pwned" in result.stdout


def has_ecosystem_marker(path: Path, substrs: list) -> bool:
    try:
        result = subprocess.run(
            ["strings", "-n", "8", str(path)],
            capture_output=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return any(s in result.stdout for s in substrs)


def is_user_invokable(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    if ".so" in path.name:
        return False
    try:
        st = path.stat()
        if st.st_mode & 0o111 == 0:
            return False
    except OSError:
        return False
    try:
        with open(path, "rb") as f:
            f.seek(16)
            e_type = int.from_bytes(f.read(2), "little")
    except (OSError, IOError):
        return False
    if e_type == 2:
        return True
    if e_type == 3:
        try:
            result = subprocess.run(
                ["readelf", "-l", "--wide", str(path)],
                capture_output=True, timeout=2,
            )
            return b"INTERP" in result.stdout
        except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
            return False
    return False


def main():
    target = ".#trojan-graphical-toplevel"
    if len(sys.argv) > 1:
        target = sys.argv[1]

    repo = "."
    result = subprocess.run(
        ["nix", "path-info", "-r", target, "--impure"],
        capture_output=True, text=True, cwd=repo,
    )
    if result.returncode != 0:
        sys.exit(result.stderr)

    paths = [Path(p) for p in result.stdout.splitlines() if p.strip()]
    print(f"Closure of {target}: {len(paths):,} store paths\n")

    binaries = []
    for p in paths:
        if not p.is_dir():
            continue
        try:
            for entry in p.rglob("bin/*"):
                if is_user_invokable(entry):
                    binaries.append(entry)
                elif entry.is_dir():
                    for sub in entry.iterdir():
                        if is_user_invokable(sub):
                            binaries.append(sub)
            for entry in p.rglob("sbin/*"):
                if is_user_invokable(entry):
                    binaries.append(entry)
            for entry in p.rglob("libexec/**/*"):
                if is_user_invokable(entry):
                    binaries.append(entry)
        except (PermissionError, OSError):
            pass
    print(f"Scanning {len(binaries):,} ELF binaries for ecosystem markers...\n")

    by_ecosystem = {eco: [] for eco in ECOSYSTEM_MARKERS}
    for b in binaries:
        for eco, markers in ECOSYSTEM_MARKERS.items():
            if has_ecosystem_marker(b, markers):
                by_ecosystem[eco].append(b)

    print("=" * 72)
    print(f"{'Ecosystem':<22}{'Count':>8}  Example + parasite status")
    print("=" * 72)

    for eco, blist in by_ecosystem.items():
        if not blist:
            print(f"{eco:<22}{0:>8}  (none found)")
            continue
        example = min(blist, key=lambda p: p.stat().st_size if p.exists() else 0)
        marked = has_marker(example)
        size_kb = example.stat().st_size // 1024 if example.exists() else 0
        print(f"{eco:<22}{len(blist):>8}  "
              f"{example.name} ({size_kb} KB) "
              f"{'MARKED' if marked else 'clean'}")
        for ex in blist[:3]:
            if ex == example:
                continue
            marked = has_marker(ex)
            size_kb = ex.stat().st_size // 1024 if ex.exists() else 0
            print(f"{'':<22}{'':>8}  + {ex.name} ({size_kb} KB) "
                  f"{'MARKED' if marked else 'clean'}")

    print()


if __name__ == "__main__":
    main()