#!/usr/bin/env python3

from binascii import hexlify
from sha_xx import get_sha_xx
from bday_attack import BDayAttack
from pollard_rho import PollardRho


def generate_collisions(out, attack_class, n_bits, n_collisions, *arg):
    h_func = get_sha_xx(n_bits)
    attack = attack_class(h_func, n_bits, *arg)

    for _ in range(n_collisions):
        x, y, _ = attack.attack()
        out.write(f"{hexlify(x).decode()} {hexlify(y).decode()}\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", help="Output file")
    parser.add_argument("-a", help="Attack to use (bday | rho)", default='rho')
    parser.add_argument("-n", type=int, help="Number of collisions to seek", default=100)
    parser.add_argument("-b", type=int, help="Hash bit length (use 12-40 for tests)", default=16)
    parser.add_argument("-t", type=int, help="Threads number (for Pollard Rho)", default=2)
    args = parser.parse_args()

    if args.a == 'bday': attack = BDayAttack
    elif args.a == 'rho': attack = PollardRho
    else: raise NotImplementedError(f"Unknown attack type: {args.a}. Use 'bday' or 'rho'.")

    if args.t < 1 or args.b < 1 or args.n < 1:
        raise ValueError("Invalid integer parameters. Check your configuration.")

    with open(args.o, "w") as f:
        generate_collisions(f, attack, args.b, args.n, args.t)


