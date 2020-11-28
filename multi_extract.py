
from stegano import lsb
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from ciphers import unlukefuscate
import argparse
import os

parser = argparse.ArgumentParser(description='WHSPR\n\n')
# folder of images to extract data from
parser.add_argument('-i', action="store", dest="image", required=True,
                    help="Path to folder of images")
# password to use
parser.add_argument('-p', action="store", dest="password", default="3NCRYPT10N3D",
                    help="The password to unlock the encryption & embedded data")
# offset
parser.add_argument('-o', action="store", dest="offset", type=int, default=17,
                    help="offset of embedding")

comms = parser.parse_args()
if not comms.image:
    parser.print_help()
    quit()

img = comms.image               # path to folder of steg'ed images
offset = comms.offset           # offset of embedding
password = comms.password       # password used to encrypt & embed
imgs = []                       # list to hold steg'ed images in for extraction

valid_images = ['.jpg', '.jpeg', '.png', '.bmp']    # only accept these types of images


def extract(img, password, offset):
    # extract data from an image
    y = lsb.reveal(img, encoding="UTF-8", shift=offset)

    if y is None:
        return "Unable to retrieve any embedded data"

    x = unlukefuscate(y)

    s1 = x[:44]         # salt (first 44)
    s2 = x[44:68]       # Initialization Vector (next 24)
    s3 = x[68:]         # Cipher Text / encrypted message (rest of message)

    salt = b64decode(s1)  # base64 decoded salt
    iv = b64decode(s2)  # base64 decoded init vector
    ct = b64decode(s3)  # base64 decoded cipher text

    key = PBKDF2(password, salt, dkLen=32)  # Your key that you can encrypt with

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        dec_dat = pt.decode()
        sequence = dec_dat.split(":")[-1]
        p_seq = sequence.split(",")
        trimmed = dec_dat[:-(len(sequence) + 1)]
        ret_data = str(p_seq[0]) + " of " + str(p_seq[1]) + "\n" + trimmed

        return ret_data

    except ValueError:
        return "Decryption failed"


# grab all the images from our supplied path
for f in os.listdir(img):
    ext = os.path.splitext(f)[1]            # grab the extension of the file
    if ext.lower() not in valid_images:     # make it lower case & check against valid extensions
        continue
    imgs.append(f)      # if everything's cool, add the image to

for x in imgs:
    print(x)
    msg = extract(img + "\\" + x, password, offset)
    print(msg)

#msg = extract(img, password, offset)
#print(msg)