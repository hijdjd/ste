#!/usr/bin/env python3
import struct, sys, os, shutil
APP=sys.argv[1]          # path to .app
DYLIB_SRC=sys.argv[2]    # compiled stehook.dylib
EXEC=os.path.join(APP,'Info.plist')
import plistlib
exe=plistlib.load(open(EXEC,'rb'))['CFBundleExecutable']
binpath=os.path.join(APP,exe)
d=bytearray(open(binpath,'rb').read())
ncmds=struct.unpack('<I',d[16:20])[0]
sizeofcmds=struct.unpack('<I',d[20:24])[0]
# 找 __text fileoff
off=32; textoff=None
for i in range(ncmds):
    cmd,sz=struct.unpack('<II',d[off:off+8])
    if cmd==0x19:
        sg=d[off+8:off+24].rstrip(b'\0').decode()
        if sg=='__TEXT':
            ns=struct.unpack('<I',d[off+64:off+68])[0]; so=off+72
            for j in range(ns):
                if d[so:so+16].rstrip(b'\0')==b'__text':
                    textoff=struct.unpack('<I',d[so+48:so+52])[0]
            break
    off+=sz
hdr_end=32+sizeofcmds
# 新 load command: LC_LOAD_DYLIB
name=b'@executable_path/stehook.dylib\x00'
name=name+b'\x00'*((8-len(name)%8)%8)
cmdsize=24+len(name)
lc=struct.pack('<IIIIII',0xc,cmdsize,24,0,0,0)+name
assert hdr_end+len(lc)<=textoff, f"no space: {hdr_end+len(lc)}>{textoff}"
# 插到现有 load commands 末尾
d[hdr_end:hdr_end+len(lc)]=lc
struct.pack_into('<I',d,16,ncmds+1)
struct.pack_into('<I',d,20,sizeofcmds+len(lc))
open(binpath,'wb').write(d)
# 拷 dylib
shutil.copy(DYLIB_SRC, os.path.join(APP,'stehook.dylib'))
print("injected OK, lc size",len(lc),"new ncmds",ncmds+1)
