import sys
from classes.png import PNG 

if __name__ == "__main__":
    arg_no = len(sys.argv)
    if arg_no <= 1 or arg_no > 3:
        print("Usage: python script.py <image_path>")
    else:
        png = PNG(sys.argv[1])
        if arg_no == 3 and sys.argv[2] in ["-a", "--anonymize"]:
            if png.anonymize():
                print(f"File {sys.argv[1]} anonymized successfully")
        else:
            png.getEXIF()
            png.getCriticalChunks()
            png.getAncillaryChunks()
        print(png.color_type)
        # png.showImage()
        png.showSpectrum()

