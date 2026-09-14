#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path

PACKAGE_MARKERS = ("bin", "sbin", "lib", "share", "libexec", "include",
                   "nix-support")


def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, IOError):
        return False


def is_executable_elf(path: Path) -> bool:
    if not is_elf(path):
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


def is_package(path: Path) -> bool:
    if not path.is_dir():
        return False
    return any((path / m).exists() for m in PACKAGE_MARKERS)


def get_closure_paths(target: str, repo: str) -> list:
    result = subprocess.run(
        ["nix", "path-info", "-r", target, "--impure"],
        capture_output=True, text=True, cwd=repo,
    )
    if result.returncode != 0:
        sys.exit(f"nix path-info failed: {result.stderr}")
    return [Path(p) for p in result.stdout.splitlines() if p.strip()]


def dir_size(d: Path) -> int:
    total = 0
    try:
        for entry in d.rglob("*"):
            if entry.is_file() and not entry.is_symlink():
                try:
                    total += entry.stat().st_size
                except (OSError, PermissionError):
                    pass
    except (PermissionError, OSError):
        pass
    return total


def find_binaries(pkg: Path) -> list:
    out = []
    for sub in ("bin", "sbin"):
        d = pkg / sub
        if not d.is_dir():
            continue
        try:
            for entry in d.iterdir():
                if entry.is_file() and not entry.is_symlink() and is_executable_elf(entry):
                    out.append(entry)
        except (PermissionError, OSError):
            pass
    libexec = pkg / "libexec"
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


def find_libraries(pkg: Path) -> int:
    lib = pkg / "lib"
    if not lib.is_dir():
        return 0
    count = 0
    try:
        for entry in lib.rglob("*.so*"):
            if entry.is_file() and is_elf(entry):
                count += 1
    except (PermissionError, OSError):
        pass
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".trojan-graphical-image",
                        help="Flake ref to measure (without .#).")
    parser.add_argument("--repo", default=".",
                        help="Path to the flake repo.")
    parser.add_argument("--output", default="/tmp/attack-stats.json",
                        help="JSON output file.")
    parser.add_argument("--top", type=int, default=20,
                        help="Number of top packages to show.")
    args = parser.parse_args()

    target = f".#{args.target}"
    print(f"Closure of {target} ...")

    paths = get_closure_paths(target, args.repo)
    print(f"  {len(paths):,} store paths in closure")

    packages = [p for p in paths if is_package(p)]
    print(f"  {len(packages):,} package outputs")
    print()

    total_binaries = 0
    binaries_by_dir = {"bin": 0, "sbin": 0, "libexec": 0}
    total_libs = 0
    total_size = 0
    pkg_rows = []

    for pkg in packages:
        bins = find_binaries(pkg)
        libs = find_libraries(pkg)
        size = dir_size(pkg)

        total_binaries += len(bins)
        total_libs += libs
        total_size += size

        for b in bins:
            try:
                top = b.relative_to(pkg).parts[0]
                if top in binaries_by_dir:
                    binaries_by_dir[top] += 1
            except (ValueError, IndexError):
                pass

        pkg_rows.append({
            "name": pkg.name,
            "size_bytes": size,
            "binaries": len(bins),
            "libraries": libs,
            "path": str(pkg),
        })

    pkg_rows.sort(key=lambda r: -r["size_bytes"])

    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Package outputs:        {len(packages):>8,}")
    print(f"ELF executables:        {total_binaries:>8,}")
    print(f"  in bin/:              {binaries_by_dir['bin']:>8,}")
    print(f"  in sbin/:             {binaries_by_dir['sbin']:>8,}")
    print(f"  in libexec/:          {binaries_by_dir['libexec']:>8,}")
    print(f"Shared libraries:       {total_libs:>8,}")
    print(f"Total closure size:     {total_size / 1e9:>7.2f} GB")
    if pkg_rows:
        sizes = sorted(r["size_bytes"] for r in pkg_rows)
        median = sizes[len(sizes) // 2]
        print(f"Median package size:    {median / 1e6:>7.2f} MB")
        print(f"Largest package:        {pkg_rows[0]['size_bytes'] / 1e6:>7.2f} MB"
              f"  ({pkg_rows[0]['name']})")

    print()
    print("=" * 60)
    print(f"Top {args.top} packages by size")
    print("=" * 60)
    print(f"{'Name':<55} {'Size':>10} {'Bin':>5} {'Lib':>5}")
    print("-" * 78)
    for row in pkg_rows[:args.top]:
        short_name = row["name"]
        if len(short_name) > 53:
            short_name = short_name[:50] + "..."
        print(f"{short_name:<55} "
              f"{row['size_bytes']/1e6:>8.1f} MB "
              f"{row['binaries']:>5} "
              f"{row['libraries']:>5}")

    summary = {
        "target": target,
        "store_paths": len(paths),
        "packages": len(packages),
        "binaries_total": total_binaries,
        "binaries_by_dir": binaries_by_dir,
        "libraries": total_libs,
        "closure_size_bytes": total_size,
        "packages_top": pkg_rows[:args.top],
    }
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull results saved to {args.output}")


if __name__ == "__main__":
    main()