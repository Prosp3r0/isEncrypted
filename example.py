from isEncrypted.isEncripted import isPacked
import os

macho_file = 'example_ipas/WeiboHDPro'
ipa_path = 'example_ipas/aa.ipa'

# please input either ipa file or mach-o file.

cryptid = isPacked(ipa_path) # cryptid equals 0 indicating the Mach-O file is unpacked, otherwise, it is packed.
print(cryptid)


