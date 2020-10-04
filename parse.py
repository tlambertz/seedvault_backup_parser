#!/usr/bin/env python3
import re
import os
import sys
import glob
import string
import struct
import hashlib
from Crypto.Cipher import AES
from base64 import b64decode, b64encode


# parses file-path, where file is a base64 encoded key into the decoded filename
def filepath_to_key(filepath):
    filename = filepath.split("/")[-1]

    # seedvault removes padding =, add them back, else python complains
    return b64decode(filename + "=" * ((4 - len(filename) % 4) % 4))


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
            b64 = b64encode(key)
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
                with open(f"{targetfolder}/kv/{appname}/{cleanname}_{b64.decode()}", "wb") as f:
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


# parses everything
def parse_backup(backupfolder, targetfolder, key):
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


# generate the key from a user-input mnemnonic phrase
# uses the same algorithms as seedvault, see
# https://github.com/NovaCrypto/BIP39/blob/master/src/main/java/io/github/novacrypto/bip39/SeedCalculator.java
# https://github.com/NovaCrypto/BIP39/blob/master/src/main/java/io/github/novacrypto/bip39/JavaxPBKDF2WithHmacSHA512.java
def get_key():
    salt = b"mnemonic"
    rounds = 2048
    keysize = 256

    mnemonic = input("Please enter mnemonic: ").encode()
    key = hashlib.pbkdf2_hmac("sha512", mnemonic, salt, rounds)
    return key[:keysize//8]


def main():
    if len(sys.argv) < 3:
        print("Usage: %s SHOW    [BACKUPFOLDER]" % sys.argv[0])
        print("       %s DECRYPT [BACKUPFOLDER] [TARGETFOLDER]" % sys.argv[0])
        sys.exit(-1)

    backupfolder = sys.argv[2]

    if sys.argv[1].lower() == "show":
        targetfolder = None
        print(f"Parsing backup {backupfolder}")
    elif sys.argv[1].lower() == "decrypt":
        targetfolder = sys.argv[3]
        print(f"Decrypting backup from {backupfolder} into {targetfolder}")


    userkey = get_key()
    kv_parsed = parse_backup(backupfolder, targetfolder, userkey)


if __name__ == "__main__":
    main()
