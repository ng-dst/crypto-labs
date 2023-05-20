from time import time_ns
from matplotlib import pyplot as plt

from sha_xx import get_sha_xx
from bday_attack import BDayAttack
from pollard_rho import PollardRho

lengths = range(12, 25, 4)
n_collisions = 50


def perf_test_attack(attack_class, n_bits, n_collisions, *args):
    h_func = get_sha_xx(n_bits)
    attack = attack_class(h_func, n_bits, *args)

    mem = 0
    t_start = time_ns()
    for _ in range(n_collisions):
        _, _, dmem = attack.attack()
        mem += dmem
    t = time_ns() - t_start

    avg = t / n_collisions / 1e6  # ns -> ms
    mem = mem * n_bits/8 / n_collisions / 1024  # B -> KB
    return avg, mem


def perf_plot(lengths=lengths, n_collisions=n_collisions):
    print(f"[=] params:  n_collisions={n_collisions}, lengths={lengths}")
    data_t = {BDayAttack: [], PollardRho: []}
    data_mem = {BDayAttack: [], PollardRho: []}
    for ac in (BDayAttack, PollardRho):
        print(f"Attack {ac.__name__}:")
        for length in lengths:
            print(f"[*] Testing {length}-bit msg...")
            t, mem = perf_test_attack(BDayAttack, length, n_collisions)
            data_t[ac].append(t)
            data_mem[ac].append(mem)
        print(f"[+] Done testing {ac.__name__}")
    print("Plotting results...")

    plt.figure(1)
    plt.subplot(211, xlabel='hash bits', ylabel='t_BDay, ms')
    plt.plot(lengths, data_t[BDayAttack], 'b.-')
    plt.subplot(212, xlabel='hash bits', ylabel='t_PRho, ms')
    plt.plot(lengths, data_t[PollardRho], 'g.-')

    plt.figure(2)
    plt.subplot(211, xlabel='hash bits', ylabel='mem_BDay, KB')
    plt.plot(lengths, data_mem[BDayAttack], 'r.-')
    plt.subplot(212, xlabel='hash bits', ylabel='mem_PRho, KB')
    plt.plot(lengths, data_mem[PollardRho], 'c.-')
    plt.show()
