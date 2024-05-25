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
  - '--math1v0' : use blobmath v1.0 - v1.2
  - '--maxpad [size]' : for 'add' mode, use random padding up to [size] bytes (default 2048)
  - '--hashparam [param]' : one of SHA1, SHA256_SHA1, SHA256_AES_SHA1 (default SHA256_SHA1)
  - '--enchdr' : encrypt the entry header
  - '--namesalt [salt]' : use [salt] as the entry name xor salt
  - '--pwdsalt [salt]' : use [salt] as the password xor salt
  - '--aes128param [param]' : one of AES_128_CBC, AES_128_CCBC (default AES_128_CBC)
  - '--threads [num]' : enable threading and use [num] threads, set to 1 for auto

# data layout
- entries are appended to the main pak consecutively one after another
- each entry starts and ends with a random-sized block of random data
- after the random data block there is an entry header that contains the entry ID and size hashes
- the encrypted entry data is stored after the header

# encryption
- entry name and size are stored as one-way salted hashes (sha1(sha256) and crc)
- entry AES-128 key is the first 128 bits of password's sha1(sha256)
- entry AES-128 iv is the encrypted size crc, last 32 bits of password's sha1(sha256) and random 64bits

# notes
- this is a PoC
- it is slow by design (unorganized, one-way hash)
- the package size is limited to 4GB, but can have unlimited file/entry count
- i strongly recommend extracting the data to a ramdisk so it cannot be scrapped from a disk image
  - after finishing, you should write garbage to the file before unmounting the ramdisk
- all operating data is trashed upon program exit, should be safe from RAM freeze attacks
 
 # todo
 - other languages
