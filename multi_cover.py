import os, os.path, sys

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from stegano import lsb
from ciphers import lukefuscate, unlukefuscate


imgs = []
path = sys.argv[1]
dat = sys.argv[2]

valid_images = ['.jpg', '.jpeg', '.png', '.bmp']

def embed(img, saveas, password, inp, offset, pic_num, tps):
    # encrypt & embed a data string into an image
    salt = get_random_bytes(32)             # generate something salty..
    key = PBKDF2(password, salt, dkLen=32)  # encryption key generated from the password

    cipher = AES.new(key, AES.MODE_CBC)                     # let's get encrypting...
    data = inp.encode()                                     # encode input to a bytes object
    pd = str(":" + str(pic_num) + "," + str(tps)).encode()  # encode sequence position
    ct_bytes = cipher.encrypt(pad(data + pd, AES.block_size))    # cipher text bytes + sequence
    iv = b64encode(cipher.iv).decode('utf-8')               # base64 encoded IV
    ct = b64encode(ct_bytes).decode('utf-8')                # base64 encoded Cipher Text
    salt_s = b64encode(salt).decode('utf-8')                # base64 encoded Salt

    enc_string = lukefuscate(salt_s + iv + ct)      # obfuscation/substitution cipher

    steg_it = lsb.hide(img, enc_string, encoding="UTF-8", shift=offset, auto_convert_rgb=True)

    steg_it.save(saveas)        # save the image
    return "SAVED AS:  " + str(saveas)



for f in os.listdir(path):
    ext = os.path.splitext(f)[1]
    if ext.lower() not in valid_images:
        continue
    imgs.append(f)

for x in imgs:
    print(x)

x = str(os.path.abspath(path)) + "\output-images"
#os.makedirs(os.path.join(os.path), 'steg-output')
print("-----------------------")
print(x)

print("")
print("   --- splitting the data into sections ---")
print("")


try:
    with open(dat, "rb") as steg_dat:
        dat = steg_dat

        the_len = len(steg_dat.read())
        img_len = len(imgs)
        print(the_len)
        # check the file size
        print("We have " + str(the_len) + " bytes of data")
        # check how many images we have to embed over
        print("There are " + str(len(imgs)) + " image(s) to embed over")

        dat_piece = int(the_len / img_len)
        last_piece = the_len % img_len

        print(str(dat_piece) + " bytes per image to embed")
        print("Last piece of data:  " + str(last_piece))
        dat.seek(0)
        pn = 1
        for i in imgs:
            if pn < img_len:
                tmp = dat.read(int(dat_piece)).decode()
                the_path = path + "\\" + i
                print("DATA:  " + str(tmp))
                embed(the_path, i + ".steg.png", "password123", tmp, 17, pn, img_len)
                print(str(i) + ".steg.png")
                pn += 1
            else:
                tmp = dat.read(dat_piece + last_piece).decode()
                the_path = path + "\\" + i
                print("DATA:  " + str(tmp))
                embed(the_path, i + ".steg.png", "password123", tmp, 17, pn, img_len)
                print(str(i) + ".steg.png")


except FileExistsError:
    pass

