import logging
from sys import stdout
from typing import Dict, List, Tuple

from functions import *
from functions.jacobi import JacobiSymbol

sh = logging.StreamHandler(stdout)
fh = logging.FileHandler('report.txt', 'w') 
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=(sh, fh))


if __name__ == '__main__':

    bits_len = 256
    e, d, n = gen_key_pair(bits_len)
    
    # Test encryption/decryption
    open_bytes = 123554323
    encrypted_bytes = encrypt(open_bytes, e, n)
    decrypted_bytes = decrypt(encrypted_bytes, d, n)
    logging.info("[*] RSA TEST\n    [-] Open bytes:      {}\n    [-] Encrypted bytes: {}\n    [-] Decrypted bytes: {}" \
        .format(open_bytes, encrypted_bytes, decrypted_bytes))


    logging.info("[*] Generating another key pair for testing key exchange")

    e1, d1, n1 = gen_key_pair(bits_len)

    # Value to be exchanged
    k = 11110000

    while n1 < n:
        e, d, n = gen_key_pair(bits_len)
        e1, d1, n1 = gen_key_pair(bits_len)

    logging.info("[*] Preparing data for sending ...")
    k1, S1 = send_key(k, d, n, e1, n1)
    logging.info("[*] Sending ...") 
    logging.info("[*] Receiving ...")

    if receive_key(k1, S1, d1, n1, e, n):
        logging.info("[!] Verified!")
    else:
        logging.info("[X] Not verified!")

