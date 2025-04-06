import sys
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from PIL.ExifTags import TAGS

def get_png_metadata(image_path):
    try:
        with Image.open(image_path) as img:
            metadata = PngInfo()
            metadata.add_text("Test 1", "1")
            metadata.add_text("Test 2", "2")

            img.save("test2.png", pnginfo=metadata)
            


    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <image_path>")
    else:
        get_png_metadata(sys.argv[1])
