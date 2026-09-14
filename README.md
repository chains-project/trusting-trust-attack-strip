# Trusting-Trust Attack against an Entire Linux Distribution through Binary Manipulation

This repository is the replication package for the paper *Trusting-Trust Attack against an Entire Linux Distribution through Binary Manipulation*, by Julien Malka, Aman Sharma, Martin Monperrus, Stefano Zacchiroli, and Théo Zimmermann, published at SCORED '26.
The paper is available at [10.1145/3848003.3848012](https://doi.org/10.1145/3848003.3848012).

The paper shows that Ken Thompson's trusting-trust attack is not specific to compilers.
A single tampered GNU `strip` in the nixpkgs bootstrap seed implants a payload into every later `strip` rebuilt from unmodified source, and the infected `strip` in the final standard environment then implants the payload into the binaries of downstream packages.
This repository contains the payload, the ELF injector, the Nix expressions that build the trojaned seed, and the scripts that produce the measurements reported in the paper.

## Research use and safety note

We release this software for research and educational purposes, so that the results of a peer-reviewed paper can be independently verified.

The code implements a working trusting-trust attack, so please read the following before you build anything.

The payload is deliberately benign and deliberately easy to detect.
It writes the fixed marker `You've been pwned!` to standard output and then transfers control to the host program, and it performs no network, exec, or privilege operation whatsoever.
It stays silent inside the Nix build sandbox, and it only infects files when the running process is itself named `strip`.

Using this code to compromise systems or software that you do not own, or that you are not explicitly authorized to test, is outside the purpose for which we release it.

## Build and test (all `--impure`)

```sh
nix build .#trojan-tools           # standalone injector (attack-injector)
nix build .#trojan-tarball         # the trojanned seed tarball
nix build .#trojan-hello           # smallest end-to-end demo
./result/bin/hello
#   You've been pwned!
#   Hello, world!

nix build .#trojan-htop            # htop, end-to-end through trojaned stdenv
./result/bin/htop --version

nix build .#trojan-graphical-image # full graphical installer ISO

nix build .#checks.x86_64-linux.installer-simple
nix build .#checks.x86_64-linux.gnome
```

## Stats

```sh
nix build .#trojan-graphical-image --impure
./scripts/stats.py --target trojan-graphical-image
./scripts/find-diverse-ecosystems.py trojan-graphical-toplevel
./scripts/check-marker.py --target trojan-graphical-image
```

## Citation

```bibtex
@inproceedings{malka2026trustingtrust,
  title     = {Trusting-Trust Attack against an Entire Linux Distribution through Binary Manipulation},
  author    = {Malka, Julien and Sharma, Aman and Monperrus, Martin and Zacchiroli, Stefano and Zimmermann, Th\'{e}o},
  booktitle = {Conference on Software Supply Chain Offensive Research and Ecosystem Defenses (SCORED '26)},
  year      = {2026},
  publisher = {ACM},
  address   = {New York, NY, USA},
  doi       = {10.1145/3848003.3848012},
}
```

## License

This software is released under the MIT License, see [LICENSE](LICENSE).
