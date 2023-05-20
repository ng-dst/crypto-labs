from matplotlib import pyplot as plt
from random import randbytes
from time import time_ns

from omac_impl import OMAC
from hmac_impl import HMAC

lengths = [102, 1024, 1024*5, 1024*10, 1024*100, 1024*256, 1024*512, 1024*768, 1024*1024]


def generateMsgs():
    global lengths
    print('[*] Generating messages...')
    msgs = [randbytes(i) for i in lengths]
    print('[+] Messages are ready')
    return msgs


def testPerf(msgs, mac, n_iters=1000):
    print(f'[*] testing performance for {mac}, {n_iters} iterations')
    data = []
    for msg in msgs:
        print(f'[*] testing {len(msg)}-message')
        start_t = time_ns()
        for _ in range(n_iters):
            mac.computeMac(msg)
        total = time_ns() - start_t
        avg = total / n_iters / 1e6  # ns -> ms
        print(f'[+]   {len(msg)}-message done')
        data.append(avg)
    return data


def plotPerf():
    key = randbytes(16)
    omac = OMAC(key)
    hmac = HMAC(key)
    msgs = generateMsgs()
    data_omac = testPerf(msgs, omac, 100)
    data_hmac = testPerf(msgs, hmac, 1000)

    print(f'\nOMAC (len, ms):\n{list(zip(lengths, data_omac))}')
    print(f'\nHMAC (len, ms):\n{list(zip(lengths, data_hmac))}')

    plt.figure(1)
    plt.subplot(211, xlabel='msg length', ylabel='t_OMAC, ms')
    plt.plot(lengths, data_omac, 'b.-', label='OMAC')
    plt.subplot(212, xlabel='msg length', ylabel='t_HMAC, ms')
    plt.plot(lengths, data_hmac, 'g.-', label='HMAC')
    plt.show()


plotPerf()

"""
avg for OMAC(n=100), HMAC(n=1000) 

 len, KB    OMAC, ms    HMAC, ms
   0.1        0.10        0.06
     1        0.60        0.10
    10        3.23        0.46
   100        32.8        3.22
  1024         384        32.0
  
"""
