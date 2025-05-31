import random
from math import gcd

class RSA:
    # Function used to encrypt a block of data using a provided pubkey
    def encryptData(data, pubkey):
        n, e = pubkey

        byte_len = (n.bit_length() + 7) // 8
        chunk_len = byte_len - 1
        data_len = len(data)
        data = data_len.to_bytes(4, 'big') + data
        data_len = len(data)

        pad_len = (-len(data)) % chunk_len
        if pad_len == 0:
            pad_len = chunk_len
        padding = bytes([pad_len]) * pad_len
        data += padding


        encrypted = bytearray()
        
        for i in range(0, data_len, chunk_len):
            chunk = data[i:i+chunk_len]
            m = int.from_bytes(chunk, 'big')
            c = pow(m, e, n)
            c_bytes = c.to_bytes(byte_len, 'big')
            encrypted.extend(c_bytes)

        return encrypted
    
    # Function used to decrypt a block of data using a provided privkey
    def decryptData(data, privkey):
        n, d = privkey
        byte_len = (n.bit_length() + 7) // 8
        chunk_len = byte_len - 1

        decrypted = bytearray()
        for i in range(0, len(data), byte_len):
            chunk = data[i:i+byte_len]
            c = int.from_bytes(chunk, 'big')
            m = pow(c, d, n)
            m_bytes = m.to_bytes(chunk_len, 'big')
            decrypted.extend(m_bytes)

        orig_len = int.from_bytes(decrypted[:4], 'big')
        return decrypted[4:4+orig_len]


    def generateKeypair():
        primes = RSA.getPrimes(2)

        n = primes[0] * primes[1]
        phi_n = (primes[0]-1) * (primes[1]-1)
        e = RSA.getE(phi_n)
        d = RSA.modInv(e, phi_n)
            
        pubkey = (n, e)
        privkey = (n, d)

        return pubkey, privkey
    
    def checkPrime(n):
        if n <= 1:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True
    
    def getPrimes(n):
        primes = []
        while len(primes) < 2:
            prime = random.randint(int(10e9), int(10e15))
            if RSA.checkPrime(prime):
                primes.append(prime)
        return primes

    def getE(phi):
        e = 65537
        while( gcd(e, phi) != 1 ):
            e = random.randint(2, phi)
        return e
    
    def modInv(e , phi):
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            x, y, z = egcd(b % a, a)
            return x, z - (b // a) * y, y
        x, y, _ = egcd(e, phi)
        return y % phi if x == 1 else None
    
    def xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a,b))
    
    def encryptECB(data, pubkey):
        return RSA.encryptData(data, pubkey)
    
    def decryptECB(data, privkey):
        return RSA.decryptData(data, privkey)
    
    def encryptCBC(data, pubkey, iv):
        n, e = pubkey
                
        byte_len = (n.bit_length() + 7) // 8
        chunk_len = byte_len - 1
        data_len = len(data)

        data = data_len.to_bytes(4, 'big') + data
        padded_len = len(data)
            
        encrypted = bytearray()
        prev_cipher = iv

        for i in range(0, padded_len, chunk_len):
            chunk = data[i:i+chunk_len]
            c_chunk_len = len(chunk) 
            if c_chunk_len < chunk_len:
                chunk += bytes(chunk_len - c_chunk_len)

            chunk = RSA.xor_bytes(chunk, prev_cipher[:chunk_len])
            m = int.from_bytes(chunk, 'big')
            c = pow(m, e, n)
            c_bytes = c.to_bytes(byte_len, 'big')
            encrypted.extend(c_bytes)
            prev_cipher = c_bytes

        return bytes(encrypted)
        
    def decryptCBC(data, privkey, iv):
        n, d = privkey
        
        byte_len = (n.bit_length() + 7) // 8
        data_len = len(data)
            
        decrypted = bytearray()
        prev_cipher = iv

        for i in range(0, data_len, byte_len):
            chunk = data[i:i+byte_len]

            c = int.from_bytes(chunk, 'big')
            m = pow(c, d, n)
            m_bytes = m.to_bytes(byte_len - 1, 'big')

            decrypted_chunk = RSA.xor_bytes(m_bytes, prev_cipher[:byte_len - 1])
            decrypted.extend(decrypted_chunk)
            prev_cipher = chunk

        orig_len = int.from_bytes(decrypted[:4], 'big')
        return decrypted[4:4+orig_len]