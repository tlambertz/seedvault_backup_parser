#!/usr/bin/env python3
import re
import os
import sys
import getpass
import glob
import string
import struct
import hashlib
from Crypto.Cipher import AES
from base64 import urlsafe_b64decode, urlsafe_b64encode

# separator can't be in urlsafe b64 alphabet. -> no A-Za-Z0-9-_ -> choose .
B64_SEPARATOR = "."

# parses file-path, where file is a base64 encoded key into the decoded filename
def filepath_to_key(filepath):
    filename = filepath.split("/")[-1]

    # seedvault removes padding =, add them back, else python complains
    return urlsafe_b64decode(filename + "=" * ((4 - len(filename) % 4) % 4))


# parses key-value pairs stored in the "kv" subfolder
# see KVBackup.kt
def parse_kv_backup(backupfolder, targetfolder, userkey):    
    kvs = sorted(glob.glob(f"{backupfolder}/kv/*"))
    #print("Found kv folders: ")
    #for kv in kvs:
    #    print("  "+"/".join(kv.split("/")[2:]))

    print("Decrypting Key-Value files: ")
    kv_parsed = {}
    for kv in kvs:
        appname = "/".join(kv.split("/")[2:])
        print("  for app "+appname)
        pairsb64 = glob.glob(kv+"/*")

        if targetfolder:
            os.makedirs(f"{targetfolder}/kv/{appname}", exist_ok=True)

        # verbose: dump all found paths
        if not targetfolder:
            for p in sorted([filepath_to_key(p) for p in pairsb64]):
                print(f"    {p.decode()}")

        pairs = {}
        for p in pairsb64:
            with open(p, "rb") as f:
                ct = f.read()

            key = filepath_to_key(p)
            b64 = urlsafe_b64encode(key)
            version = ct[0]
            ct = ct[1:]
            assert version == 0 # only version 0 supported

            versionheader_bytes, ct = decrypt_segment(ct, userkey)
            versionheader = parse_versionheader(versionheader_bytes)

            # if decrypted versionheader does not match folder/filename, something has gone wrong
            #print(versionheader, appname, filepath_to_key(p))
            assert versionheader['name'].decode() == appname
            assert versionheader['key'] == key
            assert versionheader['version'] == version

            # parse all remaining segments
            data = decrypt_segments(ct, userkey)
            
            if targetfolder:
                # we need to save as b64, since some keys contain "/" etc
                whitelist = string.ascii_letters + string.digits + '.'
                cleanname = re.sub(f'[^{whitelist}]', '', key.decode())
                with open(f"{targetfolder}/kv/{appname}/{cleanname}{B64_SEPARATOR}{b64.decode()}", "wb") as f:
                    f.write(data)

            pairs[key] = data
            #print(key, data, b64)
        
        kv_parsed[appname] = pairs

    return kv_parsed


# just prints all apk names found
def parse_apk_backup(backupfolder):
    apks = sorted(glob.glob(f"{backupfolder}/*.apk"))
    print("Found apks: ")
    for apk in apks:
        print("  "+"/".join(apk.split("/")[1:]))


# parses the full app backups, stored in the "full" subfolder
# see FullBackup.kt::performFullBackup()
def parse_full_app_backups(backupfolder, targetfolder, userkey):
    if targetfolder:
        os.makedirs(f"{targetfolder}/full", exist_ok=True)
    fulls = sorted(glob.glob(f"{backupfolder}/full/*"))
    print("Decrypting full backup for apps: ")
    for full in fulls:
        appname = "/".join(full.split("/")[2:])
        print("  "+appname)

        with open(full, "rb") as f:
            ct = f.read()

        #key = filepath_to_key(p)
        version = ct[0]
        ct = ct[1:]
        assert version == 0 # only version 0 supporte

        # parse all remaining segments
        data = decrypt_segments(ct, userkey)
        if targetfolder:
            with open(f"{targetfolder}/full/{appname}", "wb") as f:
                f.write(data)
        else:
            print("   Value: ", data)
            print("\n\n\n")


def parse_metadata(backupfolder, targetfolder, key):
    with open(f"{backupfolder}/.backup.metadata", "rb") as f:
        ct = f.read()

    version = ct[0]
    assert version == 0
    pt = decrypt_segments(ct[1:], key)

    if targetfolder:
        with open(f"{targetfolder}/.backup.metadata", "wb") as f:
            f.write(pt)
    else:
        print("Metadata:")
        print(pt)

# parses everything
def parse_backup(backupfolder, targetfolder, key):
    if targetfolder:
        os.mkdirs(targetfolder)
    
    parse_metadata(backupfolder, targetfolder, key)
    parse_apk_backup(backupfolder)

    kv_parsed = parse_kv_backup(backupfolder, targetfolder, key)
    if targetfolder == None:
        print_kv_pairs(kv_parsed)

    print("\n\n")

    # only decrypt apps into a folder, never print, since they might be huge
    if targetfolder:
        parse_full_app_backups(backupfolder, targetfolder, key)
    else:
        print("Skipping full app backup decryption, since they might be too large to show. Use the DECRYPT option")


    return kv_parsed


# "pretty" prints all found key-value pairs
def print_kv_pairs(kv):
    for app, pairs in kv.items():
        print("------------------------------------------------------\n")
        for key, value in pairs.items():
            print(f"APP: {app}\t\tKEY: {key.decode()}")
            print(value)
            print()


# takes a single segment, decrypts it. Returns trailing data (other segments)
# segment consists of
# 2  Bytes - Segment length x
# 12 Bytes - IV used for encryption
# x  Bytes - Encrypted Data (of which last 16 bytes are aes-gcm-tag)
def decrypt_segment(ct, key):
    # parse segment header to get iv and segment length
    length = struct.unpack(">H", ct[:2])[0]
    assert len(ct[2:]) >= length
    remainder = ct[2+12+length:]
    iv = ct[2:2+12]
    ct = ct[2+12:2+12+length]

    # use iv from segment header to decrypt
    pt = aes_decrypt(ct, key, iv)
    
    #print(length, iv, ct)
    return pt, remainder


# decrypt multiple consecutive segments
def decrypt_segments(ct, key):
    data = b""
    while ct:
        pt, ct = decrypt_segment(ct, key)
        data += pt
    return data

# decrypt a ciphertext with aesgcm and verify its tag. Last 16 bytes of ct are tag
def aes_decrypt(ct, key, iv):
    TAG_LEN = 128//8
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    tag = ct[-TAG_LEN:]
    try:
        pt = cipher.decrypt_and_verify(ct[:-TAG_LEN], tag)
    except ValueError as e:
        print(e)
        print("Could not decrypt data! Is your key correct?")
        sys.exit(-1)
    return pt


# encrypt a ciphertext with aesgcm. Last 16 bytes of ct are tag
def aes_encrypt(pt, key, iv):
    TAG_LEN = 128//8
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(pt)
    return ct + tag


# encrypts a segment, creates random iv and correct header
def encrypt_segment(pt, key):
    # create segment header
    assert len(pt) + 16 < 2**16
    header = struct.pack(">H", len(pt) + 16)
    iv = os.urandom(12) # random IV
    header += iv

    ct = aes_encrypt(pt, key, iv)
    
    return header + ct

# Version Header is:
# 1 Byte  - Version
# 2 Bytes - Packagename length x
# x Bytes - Packagename
# 2 Bytes - Keyname length y
# y Bytes - Keyname
# 
# see HeaderWriter.kt
def parse_versionheader(vb):
    version = vb[0]
    namelen = struct.unpack(">H", vb[1:3])[0]
    name = vb[3:3+namelen]
    keylen = struct.unpack(">H", vb[3+namelen:3+namelen+2])[0]
    assert len(vb) == namelen + keylen + 2 + 2 + 1
    key = vb[3+2+namelen:]
    return {
        "version": version,
        "name": name,
        "key": key,
    }


def create_versionheader(appname, key):
    data = b"\0" # version
    assert len(appname) < 255
    data += struct.pack(">H", len(appname))
    data += appname.encode()
    data += struct.pack(">H", len(key))
    data += key
    return data


# reencrypts key-value pairs from a decrypted backup, so they can be flashed to the device
def encrypt_backup(plainfolder, targetfolder, userkey):
    assert targetfolder

    os.makedirs(f"{targetfolder}/kv", exist_ok=True)
    kvs = sorted(glob.glob(f"{plainfolder}/kv/*"))

    print("Encrypting Key-Value files: ")
    for kv in kvs:
        appname = "/".join(kv.split("/")[2:])
        print("  for app "+appname, kv)
        pairsb64 = glob.glob(kv+"/*")
        os.makedirs(f"{targetfolder}/kv/{appname}", exist_ok=True)

        for p in pairsb64:
            with open(p, "rb") as f:
                pt = f.read()

            # file has to have an B64_SEPARATOR followed by the base64 of the key!
            keyb64 = p.split(B64_SEPARATOR)[-1]
            print(keyb64)
            key = urlsafe_b64decode(keyb64)
            print("    ", key)
            
            ct = b""
            # version is 0
            ct += b"\0"

            versionheader_bytes = create_versionheader(appname, key)
            ct += encrypt_segment(versionheader_bytes, userkey)
            # encrypt the plaintext
            ct += encrypt_segment(pt, userkey)
    
            with open(f"{targetfolder}/kv/{appname}/{keyb64.replace('=', '')}", "wb") as f:
                f.write(ct)

    print("Encrypting Metadata file")
    with open(f"{plainfolder}/.backup.metadata", "rb") as f:
        meta = f.read()

    metac = b"\0" + encrypt_segment(meta, userkey)
    with open(f"{targetfolder}/.backup.metadata", "wb") as f:
        f.write(metac)

    print("Done.")


# generate the key from a user-input mnemonic phrase
# uses the same algorithms as seedvault, see
# https://github.com/NovaCrypto/BIP39/blob/master/src/main/java/io/github/novacrypto/bip39/SeedCalculator.java
# https://github.com/NovaCrypto/BIP39/blob/master/src/main/java/io/github/novacrypto/bip39/JavaxPBKDF2WithHmacSHA512.java
def get_key():
    salt = b"mnemonic"
    rounds = 2048
    keysize = 256

    vis = input("Should mnemonic be visible while typing? [y/n]: ")
    if vis.lower().startswith("y"):
         mnemonic = input("Please enter mnemonic: ").encode()
    else:
        mnemonic = getpass.getpass("Please enter mnemonic: ").encode()
    key = hashlib.pbkdf2_hmac("sha512", mnemonic, salt, rounds)
    return key[:keysize//8]


def main():
    if len(sys.argv) < 3:
        print("Usage: %s SHOW    [BACKUPFOLDER]" % sys.argv[0])
        print("       %s DECRYPT [BACKUPFOLDER] [TARGETFOLDER]" % sys.argv[0])
        print("       %s ENCRYPT [PLAINFOLDER]  [TARGETFOLDER] (only KV support right now)" % sys.argv[0])
        sys.exit(-1)

    backupfolder = sys.argv[2]

    if sys.argv[1].lower() == "show":
        targetfolder = None
        print(f"Parsing backup {backupfolder}")
        userkey = get_key()
        kv_parsed = parse_backup(backupfolder, targetfolder, userkey)

    elif sys.argv[1].lower() == "decrypt":
        targetfolder = sys.argv[3]
        print(f"Decrypting backup from {backupfolder} into {targetfolder}")
        userkey = get_key()
        kv_parsed = parse_backup(backupfolder, targetfolder, userkey)

    elif sys.argv[1].lower() == "encrypt":
        plainfolder = sys.argv[2]
        targetfolder = sys.argv[3]
        print(f"Encrypting backup from {plainfolder} into {targetfolder}")
        userkey = get_key()
        kv_parsed = encrypt_backup(plainfolder, targetfolder, userkey)


if __name__ == "__main__":
    main()
