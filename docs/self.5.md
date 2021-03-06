# NAME

self - Signed Executable and Linkable Format

# DESCRIPTION

SELF files start with a signature overhead followed by a standard ELF file.
Inner ELF file can be compressed (gzip), encrypted (AES CTR), signed (ECDSA + HMAC-SHA1).

# FORMAT

    SELF_HEADER (magic,version,type,lengths..., offsets...)
    ├ SELF_APP
    ├ ELF32_EHDR[N]
    ├ ELF32_PHDR[N]
    ├ SELF_VERSION
    ├ SELF_CTRL_5
    ├ SELF_CTRL_6
    ├ SELF_CTRL_7
    └ ELF


# SEE ALSO
  - <self.h>
  - https://playstationdev.wiki/psvitadevwiki/index.php?title=SELF_File_Format
