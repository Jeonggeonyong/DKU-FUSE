# DKU-FUSE
A simple FUSE-based filesystem for testing ransomware defense.  
It monitors write operations and blocks unauthorized modifications according to predefined rules.
## Defense Algorithm
### 
## How to Use
### Build
``` sh
make
```
### Mount
``` sh
./myfs ~/workspace/illusion
# options:
# --log: make logging file
```
### Unmount
``` sh
fusermount -u ~/workspace/illusion
```
### Check
``` sh
mount | grep illusion
```