#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

STRATEGIES = [
    [b"--version"],
    [b"-V"],
    [b"-v"],
    [b"-h"],
    [b"--help"],
    [b"-?"],
    [],
]


def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, IOError):
        return False


def is_executable_elf(path: Path) -> bool:
    if not is_elf(path):
        return False
    name = path.name
    if ".so" in name:
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
        return has_pt_interp(path)
    return False


def has_pt_interp(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["readelf", "-l", "--wide", str(path)],
            capture_output=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return b"INTERP" in result.stdout


def read_dt_needed(path: Path) -> list:
    try:
        result = subprocess.run(
            ["readelf", "-d", "--wide", str(path)],
            capture_output=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return []
    needed = []
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        if "(NEEDED)" not in line:
            continue
        if "[" in line and "]" in line:
            soname = line.split("[", 1)[1].rsplit("]", 1)[0]
            needed.append(soname)
    return needed


def collect_available_libs(paths: list) -> set:
    libs = set()
    for p in paths:
        if not p.is_dir():
            continue
        try:
            for so in p.rglob("*.so*"):
                if so.is_file():
                    libs.add(so.name)
        except (PermissionError, OSError):
            pass
    return libs


def can_resolve_libs(binary: Path, available_libs: set) -> bool:
    needed = read_dt_needed(binary)
    if not needed:
        return True
    return all(lib in available_libs for lib in needed)


def find_binaries(store_path: Path) -> list:
    out = []
    for sub in ("bin", "sbin"):
        d = store_path / sub
        if not d.is_dir():
            continue
        try:
            for entry in d.iterdir():
                if entry.is_file() and not entry.is_symlink() and is_executable_elf(entry):
                    out.append(entry)
        except (PermissionError, OSError):
            pass
    libexec = store_path / "libexec"
    if libexec.is_dir():
        try:
            for entry in libexec.iterdir():
                if entry.is_dir():
                    for sub in entry.iterdir():
                        if sub.is_file() and is_executable_elf(sub):
                            out.append(sub)
                elif entry.is_file() and is_executable_elf(entry):
                    out.append(entry)
        except (PermissionError, OSError):
            pass
    return out


def is_package(path: Path) -> bool:
    if not path.is_dir():
        return False
    return any((path / m).exists() for m in
               ("bin", "sbin", "lib", "share", "libexec", "nix-support"))


def get_closure_paths(target: str, repo: str) -> list:
    result = subprocess.run(
        ["nix", "path-info", "-r", target, "--impure"],
        capture_output=True, text=True, cwd=repo,
    )
    if result.returncode != 0:
        sys.exit(f"nix path-info failed: {result.stderr}")
    return [Path(p) for p in result.stdout.splitlines() if p.strip()]


def test_binary(args) -> dict:
    binary_str, timeout = args
    binary = Path(binary_str)

    for strategy in STRATEGIES:
        try:
            result = subprocess.run(
                [binary_str] + strategy,
                capture_output=True,
                timeout=timeout,
                env={
                    "PATH": "/usr/bin:/bin",
                    "TERM": "dumb",
                    "HOME": "/tmp",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
            )
            output = result.stdout + result.stderr
            if b"pwned" in output:
                return {
                    "path": binary_str,
                    "name": binary.name,
                    "status": "marked",
                    "args": [a.decode("utf-8", errors="replace") for a in strategy],
                    "output_sample": output[:200].decode("utf-8", errors="replace"),
                }
            if output and result.returncode == 0 and strategy:
                break
            if output and strategy and b"error while loading" in output:
                return {"path": binary_str, "name": binary.name,
                        "status": "broken",
                        "output_sample": output[:200].decode("utf-8", errors="replace")}
        except subprocess.TimeoutExpired as e:
            output = (e.output or b"") + (e.stderr or b"")
            if b"pwned" in output:
                return {
                    "path": binary_str,
                    "name": binary.name,
                    "status": "marked",
                    "args": [a.decode("utf-8", errors="replace") for a in strategy],
                    "output_sample": output[:200].decode("utf-8", errors="replace"),
                }
            return {"path": binary_str, "name": binary.name, "status": "timeout"}
        except (OSError, PermissionError) as e:
            return {
                "path": binary_str,
                "name": binary.name,
                "status": "error",
                "error": str(e),
            }
        except Exception:
            continue

    return {"path": binary_str, "name": binary.name, "status": "clean"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="trojan-graphical-image",
                        help="Flake ref (without .#).")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--workers", type=int, default=8,
                        help="Parallel workers.")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Per-binary timeout in seconds.")
    parser.add_argument("--output", default="/tmp/check-marker.json",
                        help="JSON output file.")
    parser.add_argument("--limit", type=int, default=0,
                        help="Stop after N binaries (for testing).")
    args = parser.parse_args()

    target = f".#{args.target}"
    print(f"Closure of {target}")
    print("=" * 60)

    paths = get_closure_paths(target, args.repo)
    print(f"Collecting binaries from {len(paths):,} store paths...")
    available_libs = collect_available_libs(paths)
    print(f"  {len(available_libs):,} shared libraries in closure")
    all_binaries = []
    unrunnable = []
    for p in paths:
        if is_package(p):
            for b in find_binaries(p):
                if can_resolve_libs(b, available_libs):
                    all_binaries.append(b)
                else:
                    unrunnable.append(b)

    if args.limit > 0:
        all_binaries = all_binaries[:args.limit]

    print(f"  {len(all_binaries):,} ELF binaries to test")
    print(f"  {len(unrunnable):,} binaries skipped (DT_NEEDED libs not in closure)")
    print(f"  {args.workers} workers, {args.timeout}s timeout per binary")
    print()

    counts = {"marked": 0, "clean": 0, "timeout": 0, "error": 0,
              "broken": 0, "unrunnable": len(unrunnable)}
    results = [{"path": str(b), "name": b.name, "status": "unrunnable"}
               for b in unrunnable]
    t0 = time.time()

    work = [(str(b), args.timeout) for b in all_binaries]

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(test_binary, w): w[0] for w in work}
        done = 0
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            counts[r["status"]] += 1
            done += 1
            if done % 100 == 0 or done == len(all_binaries):
                elapsed = time.time() - t0
                rate = done / elapsed if elapsed > 0 else 0
                print(f"  [{done:>6}/{len(all_binaries):<6}]  "
                      f"marked={counts['marked']:>5}  "
                      f"clean={counts['clean']:>5}  "
                      f"timeout={counts['timeout']:>5}  "
                      f"error={counts['error']:>5}  "
                      f"({rate:.1f}/s)")

    elapsed = time.time() - t0
    runnable = counts["marked"] + counts["clean"]
    tested = (len(all_binaries) + len(unrunnable)
              - counts["unrunnable"]
              - counts["error"])

    print()
    print("=" * 60)
    print("Results")
    print("=" * 60)
    print(f"Closure binaries:   {len(all_binaries) + len(unrunnable):>8,}")
    print(f"  unrunnable:       {len(unrunnable):>8,}  "
          f"[DT_NEEDED libs not in closure]")
    print(f"Tested binaries:    {tested:>8,}")
    print(f"  marked:           {counts['marked']:>8,}  "
          f"({counts['marked']/tested*100:.1f}%)")
    print(f"  clean:            {counts['clean']:>8,}  "
          f"({counts['clean']/tested*100:.1f}%)")
    print(f"  timeout:          {counts['timeout']:>8,}  "
          f"({counts['timeout']/tested*100:.1f}%)")
    print(f"  broken:           {counts['broken']:>8,}  "
          f"({counts['broken']/tested*100:.1f}%)")
    print(f"  error:            {counts['error']:>8,}  "
          f"({counts['error']/tested*100:.1f}%)")
    print()
    if runnable > 0:
        print(f"Marker prevalence among runnable binaries: "
              f"{counts['marked']}/{runnable} = "
              f"{counts['marked']/runnable*100:.2f}%")
    print(f"\nElapsed: {elapsed:.1f}s")

    summary = {
        "target": target,
        "elapsed_seconds": elapsed,
        "total_binaries": len(all_binaries),
        "counts": counts,
        "marker_prevalence": (
            counts["marked"] / runnable if runnable > 0 else 0
        ),
        "results": results,
    }
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nDetailed results: {args.output}")


if __name__ == "__main__":
    main()