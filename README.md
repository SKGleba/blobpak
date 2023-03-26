# blobpak
unorganized encrypted file container aiming to be indistinguishable from garbage data

# usage
```./blobpak [pak] [mode] [file] [password] <overrides>```
- pak: target container or file to append to
- file: file or entry name
- password: file/entry password
- mode: one of
  - 'add' : encrypts file/entry and packs into the container
  - 'get' : decrypts and extracts file/entry from the container
  - 'del' : finds and deletes file/entry from the container
- overrides:
  - '--stdin' : gets input data from stdin
  - '--stdout' : writes output data to stdout, incompatible with '--replace'
  - '--replace' : for 'add' mode, if file/entry exists blobpak will remove it first
  - '--view' : for 'get' mode, prints data as ascii

# data layout
- entries are appended to the main pak consecutively one after another
- each entry starts with a random-sized block of random data
- after the random data block there is an entry header that contains the entry ID and size hashes
- the encrypted file is stored just after the header

# encryption
- entry name and size are stored as one-way salted hashes (sha1 and crc)
- entry AES-128 key is the first 128 bits of password's sha1
- entry AES-128 iv is the encrypted size crc, last 32 bits of password's sha1 and random 64bits

# notes
- this is a PoC
- its not platform-specific
- it is slow by design (unorganized, one-way hash)
- the package size is limited to 4GB, but can have unlimited file/entry count
- i strongly recommend extracting the data to a ramdisk so it cannot be scrapped from a disk image
  - after finishing, you should write garbage to the file before unmounting the ramdisk
- all operating data is trashed upon program exit, should be safe from RAM freeze attacks
 
 # todo
 - threads
 - other languages
 - more sanity checks
