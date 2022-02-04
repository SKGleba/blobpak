# blobpak
unorganized encrypted file container aiming to be indistinguishable from garbage data

# usage
```./blobpak [pak] [add | get | del] [file] [password]```
- pak: target container or file to append to
- file: file to be added/extracted/removed
- password: file/entry password

# data layout
- entries are appended to the main pak one after another
- each entry starts with a random-sized block of random data
- after the random data block there is an entry header that contains the entry ID and size hashes
- the encrypted file is stored just after the header

# encryption
- entry name and size are stored as one-way salted hashes (sha1 and crc)
- entry AES-128 key is the first 128 bits of password's sha1
- entry AES-128 iv is the encrypted size crc, last 32 bits of password's sha1 and random 64bits

# notes
- this is a PoC
- it is slow by design (unorganized, one-way hash)
- the package size is limited to 4GB, but unlimited file/entry count
- i strongly recommend extracting the data to a ramdisk so it cannot be scrapped from a disk image
  - after finishing write garbage to the file before unmounting the ramdisk, see below
- all operating data is trashed upon program exit, should be safe from RAM freeze attacks
- ```blobpak_example``` is a private picture of mine encrypted with this tool, good luck
  - at least try to find the file name or size :)
 
 # todo
 - threads
 - runtime user input to prevent name/pwd leak
 - other languages
 - output file trasher after use
