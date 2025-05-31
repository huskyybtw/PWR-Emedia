import sys, os
import struct
import zlib
import datetime
from classes.rsa import RSA 
from classes.png import PNG 

def writeEncrypted(data, name, timestamp):
    filename_no_ext = name[:-4]
    new_name = f"{timestamp}_{filename_no_ext}_encrypted.png"
    with open(new_name, 'wb') as new_file:
        for chunk in data:
            new_file.write(chunk)

def writeDecrypted(data, name):
    filename_no_ext = name[:-14]
    new_name = f"{filename_no_ext}_decrypted.png"
    with open(new_name, 'wb') as new_file:
        for chunk in data:
            new_file.write(chunk)

def saveKeys(keys, name, timestamp):
    filename_no_ext = name[:-4]
    new_name = f"{timestamp}_{filename_no_ext}_keys.txt"
    pubkey = keys[0]
    privkey = keys[1]

    with open(new_name, 'w') as new_file:
        new_file.write(f"Public key:\n{pubkey[0]}\n{pubkey[1]}\n")
        new_file.write(f"Private key:\n{privkey[0]}\n{privkey[1]}\n")

def loadKeys(filename):
    with open(filename, 'r') as keyfile:
        lines = keyfile.readlines()
        n_pub = int(lines[1])
        e_pub = int(lines[2])
        d_priv = int(lines[4])
        e_priv = int(lines[5])

        pubkey = (n_pub, e_pub)
        privkey = (d_priv, e_pub)

        return (pubkey, privkey)
            
if __name__ == "__main__":
    arg_no = int(len(sys.argv))
    if arg_no < 1 or arg_no > 4:
        print("Usage: python script.py <image_path> <--decrypt or --encrypt>")
    elif arg_no >= 3:
        if sys.argv[2] in [ "-e", "--encrypt"]:
            img_path = sys.argv[1]

            png = PNG(img_path)
            png_name = os.path.basename(img_path)
            png_signature = png.png_signature
            crit_chunks = png.getCriticalChunks()
            anc_chunks = png.getAncillaryChunks()
            idat_chunks, crit_chunks_no_data = png.getDataChunks(crit_chunks)
            keypair = RSA.generateKeypair()

            combined_idat_data = b''.join(chunk[8:-4] for chunk in idat_chunks)
            decompressed_data = zlib.decompress(combined_idat_data)


            encrypted_uncompressed= RSA.encryptData(decompressed_data, keypair[0])
            encrypted_compressed= zlib.compress(encrypted_uncompressed)

            idat_type = b'IDAT'
            new_len = len(encrypted_compressed).to_bytes(4, 'big')
            new_crc = struct.pack('>I', zlib.crc32(idat_type + encrypted_compressed))
            new_chunk = new_len + idat_type + encrypted_compressed + new_crc

            crit_chunks_no_data.insert(-1, new_chunk)
            crit_chunks_no_data.insert(0, png_signature)
            
            for chunk in anc_chunks:
                crit_chunks_no_data.insert(-1, chunk)
                
            all_chunks = crit_chunks_no_data

            timestamp = '{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())
            writeEncrypted(all_chunks, png_name, timestamp)
            saveKeys(keypair, png_name, timestamp)

        elif sys.argv[2] in ["-d", "--decrypt"]:

            img_path = sys.argv[1]
            keyfile = sys.argv[3]
            keys = loadKeys(keyfile)
            privkey = keys[1]

            png = PNG(img_path)
            png_name = os.path.basename(img_path)
            png_signature = png.png_signature
            crit_chunks = png.getCriticalChunks()
            anc_chunks = png.getAncillaryChunks()
            encrypted_idat_chunks, crit_chunks_no_data = png.getDataChunks(crit_chunks)

            decrypted_idat_chunks = []
            for chunk in encrypted_idat_chunks:
                idat_type = b'IDAT'
                encrypted_data = chunk[8:-4]

                decrypted_data = RSA.decryptData(encrypted_data, privkey)

                new_len = len(decrypted_data).to_bytes(4, 'big')
                new_crc = struct.pack('>I', zlib.crc32(idat_type + decrypted_data))

                new_chunk = new_len + idat_type + decrypted_data + new_crc
                decrypted_idat_chunks.append(new_chunk)

            
            for chunk in decrypted_idat_chunks + anc_chunks:
                crit_chunks_no_data.insert(-1, chunk)
                
            crit_chunks_no_data.insert(0, png_signature)
            all_chunks = crit_chunks_no_data

            writeDecrypted(all_chunks, png_name)
