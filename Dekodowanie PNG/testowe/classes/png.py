import struct
import zlib
from PIL import Image, ImageOps
from PIL.ExifTags import TAGS, GPSTAGS, IFD
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as np

class PNG:
    path: str = ""
    valid: bool = None
    color_type: int = None
    palette: list = None
    critical_chunks = ["IHDR","PLTE","IDAT","IEND"]

    def __init__(self, path: str):
        self.path = path

    def verifySignature(self, file):
        signature = file.read(8)
        if signature != b"\x89PNG\r\n\x1a\n":
            self.valid = False 
        self.valid = True
        return signature

    def printChunkData(self, data):
        for k, v in data.items():
            print(f">> {k} : {v}")

    def parseIHDR(self, chunk_data, len):
        if len < 13:
            print("Invalid IHDR data")
            return
    
        data = dict({})
        data["width"] = int.from_bytes(chunk_data[:4], "big")
        data["height"] = int.from_bytes(chunk_data[4:8], "big")
        data["bit_depth"] = chunk_data[8]
        data["color_type"] = chunk_data[9]
        data["compression"] = chunk_data[10]
        data["filter"] = chunk_data[11]
        data["interalce"] = chunk_data[12]

        return data

    def parsePLTE(self, data, len):
        palettes = []
        n = 0
        while n < len:
            r = data[n]
            g = data[n+1]
            b = data[n+2]
            n += 3
            palettes.append((r,g,b))
        return palettes
            
    def getEXIF(self):
        img = Image.open(self.path)
        exif = img.getexif()

        print(">>>>A EXIF TAGS:")
        for k, v in exif.items():
            tag = TAGS.get(k, k)
            print('>>', tag,": " , v)
        print(">>>> EXIF TAGS END")

        print(">>>> IFDS:")
        for ifd_id in IFD:
            try:
                ifd = exif.get_ifd(ifd_id)

                if ifd_id == IFD.GPSInfo:
                    resolve = GPSTAGS
                else:
                    resolve = TAGS

                for k, v in ifd.items():
                    tag = resolve.get(k, k)
                    print(f'>> {ifd_id.name} >>', tag,": " , v)
            except KeyError:
                pass
        print(">>>> IFDS END")

    def getCriticalChunks(self):
        try:
            with open(self.path, 'rb') as f:
                self.verifySignature(f)
                if not self.valid:
                    print("Bad png signature")
                    return
                while True:
                    chunk_header = f.read(8)
                    if len(chunk_header) < 8:
                        break
                    chunk_len = int.from_bytes(chunk_header[:4])
                    chunk_type = (chunk_header[4:8]).decode("ascii","ignore")
                    chunk_data = f.read(chunk_len)
                    chunk_crc = f.read(4)
                    if chunk_type in self.critical_chunks: 
                        print(f">>>> Chunk type: {chunk_type} | size: {chunk_len}")

                        if chunk_type == "IHDR":
                            ihdr_data = self.parseIHDR(chunk_data, chunk_len)
                            self.color_type = ihdr_data["color_type"]
                            self.printChunkData(ihdr_data)

                        if chunk_type == "PLTE":
                            self.palette = self.parsePLTE(chunk_data, chunk_len)
                            for i, (r, g, b) in enumerate(self.palette):
                                if i % 8 == 0:
                                    print(">> ", end="")
                                hex_color = f"#{r:02X}{g:02X}{b:02X}"
                                ansi_color = f"\033[48;2;{r};{g};{b}m"
                                reset = "\033[0m"

                                print(f"{ansi_color}  {reset} {hex_color}", end="  ")

                                if (i + 1) % 8 == 0:
                                    print()

                        if chunk_type == "IEND":
                            break
                
        except Exception as e:
            print(f"Error: {e}")

    def getAncillaryChunks(self):
        try:
            with open(self.path, 'rb') as f:
                self.verifySignature(f)
                if not self.valid:
                    print("Bad png signature")
                    return
                while True:
                    chunk_header = f.read(8)
                    if len(chunk_header) < 8:
                        break
                    chunk_len = int.from_bytes(chunk_header[:4])
                    chunk_type = (chunk_header[4:8]).decode("ascii","ignore")
                    chunk_data = f.read(chunk_len)
                    chunk_crc = f.read(4)
                    if chunk_type not in self.critical_chunks: 
                        print(f">>>> Chunk type {chunk_type}, Chunk length {chunk_len}")
                        if chunk_type in ["tEXt", "iTXt"]:
                            try:
                                decoded_text = chunk_data.decode('utf-8')
                                print(f">> {decoded_text}")
                            except Exception as e:
                                decoded_text = chunk_data.decode('latin-1')
                                print(f">> {decoded_text}")

                        if chunk_type == "zTXt":
                            null_index = chunk_data.index(b'\x00')
                            keyword = chunk_data[:null_index].decode('utf-8')
                            compression = chunk_data[null_index + 1]
                            compressed_text = chunk_data[null_index + 2:]
                            if compression == 0:
                                decompressed_text = zlib.decompress(compressed_text).decode('utf-8')
                                print(f">> {decompressed_text}")

                        if chunk_type == "bKGD":
                            if chunk_len == 1:
                                print(f">> PLTE index: {chunk_data[0]}")
                            elif chunk_len == 2:
                                grayscale_value = struct.unpack(">H", chunk_data)[0]
                                print(f">> Grayscale: {grayscale_value}")
                            else:
                                r, g ,b = struct.unpack(">HHH", chunk_data)
                                print(f">> R: {r} G: {g}, B: {b}")

                        if chunk_type == "gAMA":
                            gamma_val = struct.unpack(">I", chunk_data)[0] / 100000.0
                            print(f">> Gamma: {gamma_val}")

                        if chunk_type == "pHYs":
                            x, y, unit = struct.unpack(">IIB", chunk_data)
                            print(f">> X: {x}, Y: {y}, Unit: {unit}")

                        if chunk_type == "tIME":
                            year, month, day, hour, min, sec = struct.unpack(">HBBBBB", chunk_data)
                            print(f">> {year}-{month}-{day}-{hour}-{min}-{sec}")


        except Exception as e:
            print(f"Error: {e}")

    def anonymize(self):
        try:
            with open(self.path, 'rb') as f:
                signature = self.verifySignature(f)

                clean_chunks = [signature]
                while True:
                    chunk_header = f.read(8)
                    if len(chunk_header) < 8:
                        break


                    chunk_len, chunk_type = struct.unpack('>I4s', chunk_header)
                    chunk_data = f.read(chunk_len)
                    chunk_crc = f.read(4)
                    if chunk_type.decode("utf-8") in self.critical_chunks: 
                        clean_chunks.append(chunk_header + chunk_data + chunk_crc)

            with open(self.path, 'wb') as f:
                for chunk in clean_chunks:
                    f.write(chunk)
                return True

        except Exception as e:
            print(f"Error: {e}")
            return False

    def showImage(self):
        img = mpimg.imread(self.path)

        plt.imshow(img)
        plt.axis("off")
        plt.show()

    def showSpectrum(self):
        orig_img = Image.open(self.path)
        
        if (self.color_type == 0):
            plt.figure(figsize=(10, 5))
            grayscale_img = orig_img.convert('L')

            mag_spectrum, phase_spectrum = self.getMagnitudeSpectrum(grayscale_img)

            plt.subplot(1,2,1)
            plt.imshow(mag_spectrum, cmap='gray')
            plt.title("Magnitude spectrum")

            plt.subplot(1,2,2)
            plt.imshow(phase_spectrum, cmap='gray')
            plt.title("Phase spectrum")

        elif (self.color_type == 2):
            plt.figure(figsize=(20, 10))
            img_array = np.array(orig_img)

            for i, color in enumerate(['Red', 'Green', 'Blue']):
                channel = img_array[:, :, i]

                mag_spectrum, phase_spectrum = self.getMagnitudeSpectrum(channel)

                plt.subplot(2, 3, i+1)
                plt.imshow(mag_spectrum)
                plt.title(f"Magnitude spectrum color: {color}")

                plt.subplot(2, 3, i+4)
                plt.imshow(phase_spectrum)
                plt.title(f"Magnitude spectrum color: {color}")
        
        elif (self.color_type == 3):
            plt.figure(figsize=(20, 10))
            img_array = np.array(orig_img)

            palette = np.array(self.palette, dtype=np.uint8).reshape(-1, 3)

            rgb_array = palette[img_array]

            for i, color in enumerate(['Red', 'Green', 'Blue']):
                channel = rgb_array[:, :, i]

                mag_spectrum, phase_spectrum = self.getMagnitudeSpectrum(channel)

                plt.subplot(2, 3, i+1)
                plt.imshow(mag_spectrum)
                plt.title(f"Magnitude spectrum color: {color}")

                plt.subplot(2, 3, i+4)
                plt.imshow(phase_spectrum)
                plt.title(f"Phase spectrum color: {color}")

        # elif (self.color_type == 4):

        # elif (self.color_type == 6):
        

        plt.show()

    def getMagnitudeSpectrum(self, channel):
        F = np.fft.fft2(channel)
        F_shift = np.fft.fftshift(F)
        mag_spectrum = np.log(1 + np.abs(F_shift))
        phase_spectrum = np.angle(F_shift)
        return mag_spectrum, phase_spectrum


