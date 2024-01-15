import sys
import datetime
from datetime import datetime
import requests
import argparse
import hashlib
import magic
import pefile
import ssdeep
import tlsh
import re
import pathlib
from pathlib import Path

parser = argparse.ArgumentParser(description='Enter a file path or directory path to upload')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--file", type=str, help="The path to the file you want to upload.")
group.add_argument("--directory", type=str, help="The path to the directory (of files) you want to upload.")
args = vars(parser.parse_args())


rl_base_url = 'https://YOUR_A1000_INSTANCE_HERE/api/uploads/'
rl_token = 'YOUR_API_KEY_HERE'
rl_headers = { 'Authorization': 'Token '+ rl_token }
rl_payload = { "analysis": "cloud" }

def submit_rl_a1000(file):
    try:
        resp = requests.post(rl_base_url, headers=rl_headers, data=rl_payload, files=files)
        if resp.status_code == 200 or 201:
            sampleid = resp.json()['detail']['id']
            submittedat = resp.json()['detail']['created']
            print()
            print()
            print("[ RLA1000 STATUS: Successful file submission ]")
            print('----------------------------------------------')
            print("  Submitted at: {0}".format(str(submittedat)))
            print("  Sample ID: {0}".format(str(sampleid)))
            print('----------------------------------------------')
            print()
            return sampleid
        else:
            print("ERROR: Something went wrong in {0}. Error: {1}".format(sys._getframe().f_code.co_name, str(resp.text)))
            print()
            print()
            #sys.exit()
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno, error=str(e), ))
        print()
        print()
        #sys.exit()

##################################################################################################
### FILE cenumeration ops
###########################

def md5hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()

def sha1hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashsha1 = hashlib.sha1()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashsha1.update(info)
    return hashsha1.hexdigest()

def sha256hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashsha256 = hashlib.sha256()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashsha256.update(info)
    return hashsha256.hexdigest()

def getSSDeep(file):
    return ssdeep.hash_from_file(str(file))

def getTLSH(file):
    return tlsh.hash(open(file, 'rb').read())

def getMagic(file):
    global fMagictype
    mgtype = re.match('[^,]*', (magic.from_buffer(open(str(file), "rb").read(2048))))
    #magmatch = re.match('[^,]*', mgtype)
    fMagictype = mgtype[0]
    return fMagictype

def getMime(file):
    global filemimetype
    filemimetype = magic.from_file(str(file), mime=True)
    return filemimetype

def getPEinfo(file):
    imphash = None
    compileTime = None
    match = re.match(r'^PE[0-9]{2}\s\S*\s\([A-Z]{3}\)|^PE[0-9]{2}\+\s\S*\s\([a-z]', fMagictype)
    if match:
        p = pefile.PE(file)
        imphash = p.get_imphash()
        compileTime = datetime.fromtimestamp(p.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M')
        return imphash, compileTime

##################################################################################################

if (args["file"]):
    input_param = (args["file"])
elif (args["directory"]):
    input_param = (args["directory"])

input_files = []

p = Path(input_param)
if p.is_file():
    input_files = [p]
elif p.is_dir():
    input_files = [f for f in p.glob('**/*') if f.is_file()]

unique_files = []

for file in input_files:
    filepath = pathlib.Path(file)
    file_hash = md5hash(file)
    if file_hash not in unique_files:
        unique_files.append(file_hash)        
    else:
        input_files.remove(file)
        filepath.unlink()
        print('Removed duplicate file: '+str(file))

##################################################################################################
####  FILE SUBMISSION OPS ####
##############################
    
for file in input_files:
    files = {'file': (open(file,'rb'))}
    submit_rl_a1000(file)
    
    ###Getting file info
    f256hash = sha256hash(file)
    filename = file.name
    fextension = (file.suffix).replace(".", "")
    fMIMEtype = getMime(file)
    fMagictype = getMagic(file)
    fsize = str(round((file.stat().st_size)/1024,3))
    createdTime = datetime.fromtimestamp(file.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
    fPEinfo = getPEinfo(file)
    if fPEinfo:
        fCompileTime = fPEinfo[1]
        fImphash = fPEinfo[0]
    else:
        fCompileTime = ''
        fImphash = ''
    fmd5hash = md5hash(file)
    fsha1hash = sha1hash(file)
    fTLSH = getTLSH(file)
    fSSDeep = getSSDeep(file)
    
    ###Print the results
    print()
    print('+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    print('     File [[ '+ filename +' ]]     ')
    print('+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    print()
    print('File Name: '+filename)
    print('File Ext:  '+fextension)
    print()
    print('File MIME Type:  '+fMIMEtype)
    print('File Magic Type: '+fMagictype)
    print()
    print('File Created Time: '+createdTime)
    if fCompileTime:
        print('File Compile Time: '+fCompileTime)
    print()
    print('MD5:    '+fmd5hash)
    print('SHA1:   '+fsha1hash)
    print('SHA256: '+f256hash)
    print()
    print('TLSH:    '+fTLSH)
    print('SSDEEP:  '+fSSDeep)
    if fImphash:
        print('IMPHASH: '+fImphash)
    print()
    print('-----------------------------------------------------------------')
    print()
