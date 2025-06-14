import os
import random
import datetime
import zlib
from classes.png import PNG

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

    def encryptByte(byte, pubkey):
        n, e = pubkey
        return pow(byte, e, n)

    def decryptByte(byte, privkey):
        n, d = privkey
        return pow(byte, d, n)
    
    def generateKeypair(bits):
        primes = RSA.getPrimes(2, bits // 2)

        n = primes[0] * primes[1]
        phi_n = (primes[0]-1) * (primes[1]-1)
        e = RSA.getE(phi_n)
        d = RSA.modInv(e, phi_n)
            
        pubkey = (n, e)
        privkey = (n, d)

        return pubkey, privkey
    
    # Probabilistyczna metoda sprawdzania liczb pierwszych (Miller–Rabin primality test)
    def checkPrime(n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        # Perform k rounds of testing
        for _ in range(k):
            a = random.randrange(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def getPrimes(n, bits):
        primes = []
        while len(primes) < n:
            candidate = random.getrandbits(bits) | 1 
            if RSA.checkPrime(candidate):
                primes.append(candidate)
        return primes

    def getE(phi):
        e = 65537
        if RSA.gcd(e, phi) == 1:
            return e
        
        e = 3
        while e < phi:
            if RSA.gcd(e, phi) == 1:
                return e
            e += 2
        raise Exception('No e found')
    
    def modInv(e , phi):
        m0, x0, x1 = phi, 0, 1
        while e > 1:
            q = e // phi
            e, phi = phi, e % phi
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1
    
    def gcd(a, b):
        while b != 0:
            a, b = b , a % b
        return a 
    
    def xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a,b))
    
    def encryptECB(data, key):
        return RSA.encryptData(data, key)
    
    def decryptECB(data, key):
        return RSA.decryptData(data, key)
    
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
    
    def encryptFileCBC(filename, keypair):
        png = PNG(filename)
        png_name = os.path.basename(filename)
        crit_chunks = png.getCriticalChunks()
        anc_chunks = png.getAncillaryChunks()
        idat_chunks, crit_chunks_no_idat = png.getDataChunks(crit_chunks)
        pubkey = keypair[0]

        block_size = (pubkey[0].bit_length() + 7) // 8
        iv = random.randbytes(block_size)

        orig_data = []
        encrypted_idat_chunks = []
        for idat in idat_chunks:
            idat_data = idat[8:-4]
            orig_data.append(idat_data)

            try:
                idat_data = zlib.decompress(idat_data)
            except zlib.error:
                pass
            encrypted_data = RSA.encryptCBC(idat_data, pubkey, iv)
            compressed_encrypted = zlib.compress(encrypted_data)
            new_chunk = PNG.buildNewIDAT(compressed_encrypted)

            encrypted_idat_chunks.append(new_chunk)

        all_chunks = png.buildFromChunks(
            anc_chunks, crit_chunks_no_idat, encrypted_idat_chunks)

        timestamp = RSA.getTimeStamp()
        encrypt_path = RSA.writeEncrypted(all_chunks, png_name, "CBC")
        keyfile_path = RSA.saveKeys(keypair, png_name, "CBC")
        return (encrypt_path, keyfile_path, iv)
    
    def decryptFileCBC(filename, keyfile, iv):
        keys = RSA.loadKeys(keyfile)
        privkey = keys[1]

        png = PNG(filename)
        png_name = os.path.basename(filename)
        crit_chunks = png.getCriticalChunks()
        anc_chunks = png.getAncillaryChunks()
        encrypted_idat_chunks, crit_chunks_no_idat = png.getDataChunks(crit_chunks)

        decrypted_idat_chunks = []
        for chunk in encrypted_idat_chunks:
            chunk_data = chunk[8:-4]
            decompressed_data = zlib.decompress(chunk_data)
            decrypted_chunk_data = RSA.decryptCBC(decompressed_data, privkey, iv)
            decrypted_chunk_data = zlib.compress(decrypted_chunk_data)
            new_chunk = PNG.buildNewIDAT(decrypted_chunk_data)

            decrypted_idat_chunks.append(new_chunk)


        all_chunks = png.buildFromChunks(
            anc_chunks, crit_chunks_no_idat, decrypted_idat_chunks)

        decrypted_png_name = RSA.writeDecrypted(all_chunks, png_name)
        return decrypted_png_name

    def encryptFileECB(filename, keypair):
        png = PNG(filename)
        png_name = os.path.basename(filename)
        crit_chunks = png.getCriticalChunks()
        anc_chunks = png.getAncillaryChunks()
        idat_chunks, crit_chunks_no_idat = png.getDataChunks(crit_chunks)
        pubkey = keypair[0]

        encrypted_idat_chunks = []
        for idat in idat_chunks:
            idat_data = idat[8:-4]
            try:
                idat_data = zlib.decompress(idat_data)
            except zlib.error:
                pass
            encrypted_data = RSA.encryptECB(idat_data, pubkey)
            compressed_encrypted = zlib.compress(encrypted_data)
            new_chunk = PNG.buildNewIDAT(compressed_encrypted)
            encrypted_idat_chunks.append(new_chunk)
            
        all_chunks = png.buildFromChunks(
            anc_chunks, crit_chunks_no_idat, encrypted_idat_chunks)

        timestamp = RSA.getTimeStamp()
        encrypt_path = RSA.writeEncrypted(all_chunks, png_name, "ECB")
        keyfile_path = RSA.saveKeys(keypair, png_name, "ECB")
        return (encrypt_path, keyfile_path)
    
    def decryptFileECB(filename, keyfile):
        keys = RSA.loadKeys(keyfile)
        privkey = keys[1]

        png = PNG(filename)
        png_name = os.path.basename(filename)
        crit_chunks = png.getCriticalChunks()
        anc_chunks = png.getAncillaryChunks()
        encrypted_idat_chunks, crit_chunks_no_idat = png.getDataChunks(crit_chunks)

        decrypted_idat_chunks = []
        for chunk in encrypted_idat_chunks:
            chunk_data = chunk[8:-4]
            decompressed_data = zlib.decompress(chunk_data)
            decrypted_data = RSA.decryptECB(decompressed_data, privkey)
            decrypted_data = zlib.compress(decrypted_data)
            new_chunk = PNG.buildNewIDAT(decrypted_data)
            decrypted_idat_chunks.append(new_chunk)

        all_chunks = png.buildFromChunks(
            anc_chunks, crit_chunks_no_idat, decrypted_idat_chunks)

        decrypted_png_name = RSA.writeDecrypted(all_chunks, png_name)
        return decrypted_png_name

    @staticmethod
    def writeEncrypted(data, name, timestamp):
        filename_no_ext = os.path.basename(name[:-4])
        os.makedirs("files", exist_ok=True)
        new_name = f"files/{timestamp}_{filename_no_ext}_encrypted.png"
        with open(new_name, 'wb') as new_file:
            for chunk in data:
                new_file.write(chunk)
        return new_name

    @staticmethod
    def writeDecrypted(data, name):
        filename_no_ext = os.path.basename(name[:-14])
        new_name = f"files/{filename_no_ext}_decrypted.png"
        with open(new_name, 'wb') as new_file:
            for chunk in data:
                new_file.write(chunk)
        return new_name

    @staticmethod
    def saveKeys(keys, name, timestamp):
        filename_no_ext = name[:-4]
        new_name = f"files/{timestamp}_{filename_no_ext}_keys.txt"
        pubkey = keys[0]
        privkey = keys[1]
        with open(new_name, 'w') as new_file:
            new_file.write(f"Public key:\n{pubkey[0]}\n{pubkey[1]}\n")
            new_file.write(f"Private key:\n{privkey[0]}\n{privkey[1]}\n")
        return new_name

    @staticmethod
    def loadKeys(filename):
        with open(filename, 'r') as keyfile:
            lines = keyfile.readlines()
            n_pub = int(lines[1])
            e_pub = int(lines[2])
            d_priv = int(lines[4])
            e_priv = int(lines[5])

            pubkey = (n_pub, e_pub)
            privkey = (d_priv, e_priv)

            return (pubkey, privkey)  

    @staticmethod
    def getTimeStamp():
        return '{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())