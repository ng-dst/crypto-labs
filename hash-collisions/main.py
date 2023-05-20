#!/usr/bin/env python3

from binascii import hexlify

from sha_xx import get_sha_xx
from bday_attack import BDayAttack
from pollard_rho import PollardRho

from test_perf import perf_test_attack, perf_plot


def test_attack(attack_class, n_bits, *args):
    h_func = get_sha_xx(n_bits)
    attack = attack_class(h_func, n_bits, *args)

    x, y, _ = attack.attack()
    print(f"Attack '{attack_class.__name__}':\n{hexlify(x)} -> {hexlify(h_func(x))}\n{hexlify(y)} -> {hexlify(h_func(y))}\n")


def test_pollard_rho(n_bits=20, n_collisions=100, n_threads=4):
    test_attack(PollardRho, n_bits, n_threads)
    avg = perf_test_attack(PollardRho, n_bits, n_collisions, n_threads)
    print(f"Pollard Rho:\n{n_bits} bits, {n_threads} threads, {n_collisions} collisions, {avg[0]} ms and {avg[1]} KB each\n")


def test_bday(n_bits=20, n_collisions=100):
    test_attack(BDayAttack, n_bits)
    avg = perf_test_attack(BDayAttack, n_bits, n_collisions)
    print(f"Birthday:\n{n_bits} bits, {n_collisions} collisions, {avg[0]} ms and {avg[1]} KB each\n")


test_bday()
test_pollard_rho(n_threads=2)

perf_plot()
