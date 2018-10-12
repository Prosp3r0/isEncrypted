import sys
import os
import struct
import shutil
import zipfile

from isEncrypted.macho_lib.mach_o import MH_FILETYPE_SHORTNAMES
from isEncrypted.macho_lib.mach_o import load_command, S_ZEROFILL, section_64, section
from isEncrypted.macho_lib.mach_o import LC_REGISTRY, LC_ID_DYLIB, LC_SEGMENT, fat_header
from isEncrypted.macho_lib.mach_o import LC_SEGMENT_64, MH_CIGAM_64, MH_MAGIC_64, FAT_MAGIC
from isEncrypted.macho_lib.mach_o import mach_header, fat_arch64, FAT_MAGIC_64, fat_arch
from isEncrypted.macho_lib.mach_o import mach_header_64
from isEncrypted.macho_lib.mach_o import MH_CIGAM, MH_MAGIC
from isEncrypted.macho_lib.mach_o import encryption_info_command, encryption_info_command_64
from isEncrypted.macho_lib.mach_o import LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64

from isEncrypted.macho_lib.ptypes import sizeof
from isEncrypted.macho_lib.util import fileview


def unzip(app_path):
    print("[INFO] Unzipping")
    ext_path = app_path.replace(".ipa", "")
    try:
        files = []
        with zipfile.ZipFile(app_path, "r") as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, str):
                    filename = str(
                        filename, encoding="utf-8", errors="replace")
                files.append(filename)
                zipptr.extract(fileinfo, str(ext_path))
        return ext_path
    except Exception as e:
        print("[ERROR] Unzipping Error: no such a file or file cannot be unzipped")
        '''
        if platform.system() == "Windows":
            print("\n[INFO] Not yet Implemented.")
        else:
            print("\n[INFO] Using the Default OS Unzip Utility.")
            try:
                subprocess.call(
                    ['unzip', '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output(['unzip', '-qq', '-l', app_path])
                dat = dat.split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except Exception as e:
                print("[ERROR] Unzipping Error")
                print(e)
        '''
def file_rm(filepath):
    if filepath.endswith(".ipa"):
        unzipfolder = filepath.replace(".ipa", "")
        if os.path.exists(unzipfolder):
            try:
                shutil.rmtree(unzipfolder)
            except Exception as e:
                print("[ERROR] Delete " + unzipfolder + " Failed")
                print(e)
                pass

def find_macho(ipa_path):
    try:
        payload_path = os.path.join(unzip(ipa_path), "Payload")
    except:
        print("[ERROR] Cannot find Mach-O file")
        return None
    dirs = os.listdir(payload_path)
    dot_app_dir = ""
    for dir_ in dirs:
        if dir_.endswith(".app"):
            dot_app_dir = dir_
            break
    # Bin Dir - Dir/Payload/x.app/
    bin_dir = os.path.join(payload_path, dot_app_dir)
    bin_name = dot_app_dir.replace(".app", "")
    bin_path = os.path.join(bin_dir, bin_name)
    return bin_path


def isPacked(filepath):
    ipa_path = ""
    if filepath.endswith(".ipa"):
        ipa_path = filepath
        filepath = find_macho(filepath)
        if filepath == None:
            return None
    fh = open(filepath, 'rb')
    assert fh.tell() == 0
    header = struct.unpack('>I', fh.read(4))[0]
    fh.seek(0)
    if header in (FAT_MAGIC, FAT_MAGIC_64):
        return load_fat(fh, ipa_path)
    else:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(0)
        return load_header(fh, 0, size, ipa_path)

def load_fat(fh, filepath):
    fat = fat_header.from_fileobj(fh)
    if fat.magic == FAT_MAGIC:
        archs = [fat_arch.from_fileobj(fh)
                 for i in range(fat.nfat_arch)]
    elif fat.magic == FAT_MAGIC_64:
        archs = [fat_arch64.from_fileobj(fh)
                 for i in range(fat.nfat_arch)]
    else:
        raise ValueError("Unknown fat header magic: %r" % (fat.magic))

    for arch in archs:
        return load_header(fh, arch.offset, arch.size, filepath)

def load_header(fh, offset, size, filepath):
    fh.seek(offset)
    header = struct.unpack('>I', fh.read(4))[0]
    fh.seek(offset)
    if header == MH_MAGIC:
        magic, hdr, endian = MH_MAGIC, mach_header, '>'
    elif header == MH_CIGAM:
        magic, hdr, endian = MH_CIGAM, mach_header, '<'
    elif header == MH_MAGIC_64:
        magic, hdr, endian = MH_MAGIC_64, mach_header_64, '>'
    elif header == MH_CIGAM_64:
        magic, hdr, endian = MH_CIGAM_64, mach_header_64, '<'
    else:
        raise ValueError("Unknown Mach-O header: 0x%08x in %r" % (
            header, fh))
    return isencripted(fh, offset, size, magic, hdr, endian, filepath)

def get_filetype_shortname(filetype):
    if filetype in MH_FILETYPE_SHORTNAMES:
        return MH_FILETYPE_SHORTNAMES[filetype]
    else:
        return 'unknown'

def isencripted(fh, offset, size, magic, hdr, endian, filepath):
    fh = fileview(fh, offset, size)
    fh.seek(0)

    sizediff = 0
    kw = {'_endian_': endian}
    header = hdr
    header = mach_header.from_fileobj(fh, **kw)

    # if header.magic != self.MH_MAGIC:
    #    raise ValueError("header has magic %08x, expecting %08x" % (
    #        header.magic, self.MH_MAGIC))

    cmd = commands = []

    filetype = get_filetype_shortname(header.filetype)
    read_bytes = 0
    low_offset = sys.maxsize
    for i in range(header.ncmds):
        # read the load command
        cmd_load = load_command.from_fileobj(fh, **kw)

        # read the specific command
        klass = LC_REGISTRY.get(cmd_load.cmd, None)
        if klass is None:
            raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
        cmd_cmd = klass.from_fileobj(fh, **kw)

        if cmd_load.cmd == LC_ID_DYLIB:
            # remember where this command was
            if id_cmd is not None:
                raise ValueError("This dylib already has an id")
            id_cmd = i

        if cmd_load.cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            #print('aaaa')
            if cmd_load.cmd == LC_ENCRYPTION_INFO_64:
                encryption_cls = encryption_info_command_64
            else:  # LC_ENCRYPTION_INFO_64
                encryption_cls = encryption_info_command
            enc = encryption_cls.from_fileobj(fh, **kw)
            #enc = encryption_cls.from_fileobj(fh, **kw)
            loadcmds = cmd_cmd.describe()["cryptid"]
            #print(loadcmds)
            file_rm(filepath)
            return loadcmds


        if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
            # for segment commands, read the list of segments
            segs = []
            # assert that the size makes sense
            if cmd_load.cmd == LC_SEGMENT:
                section_cls = section
            else:  # LC_SEGMENT_64
                section_cls = section_64

            expected_size = (
                sizeof(klass) + sizeof(load_command) +
                (sizeof(section_cls) * cmd_cmd.nsects)
            )
            if cmd_load.cmdsize != expected_size:
                raise ValueError("Segment size mismatch")
            # this is a zero block or something
            # so the beginning is wherever the fileoff of this command is
            if cmd_cmd.nsects == 0:
                if cmd_cmd.filesize != 0:
                    low_offset = min(low_offset, cmd_cmd.fileoff)
            else:
                # this one has multiple segments
                for j in range(cmd_cmd.nsects):
                    # read the segment
                    seg = section_cls.from_fileobj(fh, **kw)
                    # if the segment has a size and is not zero filled
                    # then its beginning is the offset of this segment
                    not_zerofill = ((seg.flags & S_ZEROFILL) != S_ZEROFILL)
                    if seg.offset > 0 and seg.size > 0 and not_zerofill:
                        low_offset = min(low_offset, seg.offset)
                    if not_zerofill:
                        c = fh.tell()
                        fh.seek(seg.offset)
                        sd = fh.read(seg.size)
                        seg.add_section_data(sd)
                        fh.seek(c)
                    segs.append(seg)
            # data is a list of segments
            cmd_data = segs
            #print(segs)

        # XXX: Disabled for now because writing back doesn't work
        # elif cmd_load.cmd == LC_CODE_SIGNATURE:
        #    c = fh.tell()
        #    fh.seek(cmd_cmd.dataoff)
        #    cmd_data = fh.read(cmd_cmd.datasize)
        #    fh.seek(c)
        # elif cmd_load.cmd == LC_SYMTAB:
        #    c = fh.tell()
        #    fh.seek(cmd_cmd.stroff)
        #    cmd_data = fh.read(cmd_cmd.strsize)
        #    fh.seek(c)

        else:
            # data is a raw str
            data_size = (
                cmd_load.cmdsize - sizeof(klass) - sizeof(load_command)
            )
            cmd_data = fh.read(data_size)
        cmd.append((cmd_load, cmd_cmd, cmd_data))
        read_bytes += cmd_load.cmdsize
'''
if __name__ == '__main__':
    macho_path = '/Users/Max/Documents/isEncrypted/Facebook'
    ipa_path = '/Users/Max/Documents/newipas/com.autonavi.amap_8.35.1.2154_1_20180517094430_am6net.ipa'
    src = '/Users/Max/Documents/newipas/'
    for dirpath, dirnames, files in os.walk(src):
        for i in files:
            if i.endswith(".ipa"):
                ipa_path = os.path.join(dirpath, i)
                print("[UNZIPPING] " + i)
                cryptid = isPacked(ipa_path)
                print(cryptid)
    #cryptid = isPacked(ipa_path)
    #print(cryptid)
    #cryptid = isPacked(macho_path)
    #print(cryptid)
    #isencripted(filepath)
'''
'''
if __name__ == '__main__':
    ipa_path = '/Users/Max/Documents/newipas/com.ganji.life_7.9.11_1_20180517183805_am6net.ipa'
    cryptid = isPacked(ipa_path)
    print(cryptid)
'''

