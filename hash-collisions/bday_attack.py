from sha_xx import sha_xx
from Crypto.Random import get_random_bytes


class BDayAttack:

    RAND_LEN = 8

    def __init__(self, hash_func=sha_xx, *args):
        self.H = hash_func

    def attack(self):
        """ Simple birthday paradox attack on self.hash_func. Returns a pair (x,y) that gives the same hash. """
        s = dict()
        while True:
            x = get_random_bytes(self.RAND_LEN)
            h_x = self.H(x)
            if h_x in s.keys():
                return s[h_x], x, len(s.keys())*2  # memory usage
            s[h_x] = x
