from binascii import hexlify
from math import log2, ceil
from Crypto.Random import get_random_bytes
from multiprocessing import Pool, Manager, RLock

from sha_xx import sha_xx


class PollardRho:

    RAND_LEN = 8
    APPEND_LEN = 4

    masks = [0b10000000, 0b11000000, 0b11100000, 0b11110000, 0b11111000, 0b11111100, 0b11111110]

    def __init__(self, hash_func=sha_xx, n_bits=16, n_threads=2, distinguish_point_bits=None):
        self.n_threads = n_threads
        self.H = hash_func
        self.y0 = self.s = self.s_lock = None
        if distinguish_point_bits is None:
            distinguish_point_bits = n_bits//2 - ceil(log2(n_threads))  # b/2 - log2 m
        self.distinguish_point_bits = distinguish_point_bits

    def pi(self, x):
        """ Applies Pi: {0,1}^n -> {0,1}^(n+a) """
        return x + b'\x00'*self.APPEND_LEN

    def check_dpoint(self, x):
        """ Checks if X is a distinguish point, i.e. first q bits are 0's """
        div, mod = divmod(self.distinguish_point_bits, 8)
        for i in range(div):
            if x[i] != 0:
                return False
        if mod:
            return x[div] & self.masks[mod-1] == 0
        return True

    def _task(self, thread_num):
        """ Callable for an individual thread """
        i = 0
        y = get_random_bytes(self.RAND_LEN)
        self.y0[thread_num] = y

        while True:
            y = self.pi(self.H(y))
            i += 1
            if self.check_dpoint(y):
                with self.s_lock:
                    if y in self.s.keys():
                        break
                    self.s[y] = (thread_num, i)

        other_thread_num, j = self.s[y]

        d = i - j
        y = self.y0[thread_num]
        z = self.y0[other_thread_num]
        if d < 0:
            y, z = z, y
            d = -d

        for _ in range(d):
            y = self.pi(self.H(y))

        while self.H(y) != self.H(z):
            y = self.pi(self.H(y))
            z = self.pi(self.H(z))

        return y, z

    def attack(self):
        """ Runs the attack with Pool as task distributor. """
        manager = Manager()
        self.s = manager.dict()
        self.s_lock = manager.RLock()
        self.y0 = manager.list([None]*self.n_threads)
        with Pool(processes=self.n_threads) as pool:
            for res in pool.imap_unordered(self._task, range(self.n_threads)):
                if res:
                    pool.terminate()
                    return res[0], res[1], len(self.s.keys())*2  # memory usage
