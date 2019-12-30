# nntfs(aka. NTFS-defused)
# About the name
nntfs is "NOT EXACTLY"  a NTFS fs driver
nntfs is "NOT ONLY" a NTFS fs driver
nntfs is a "New" NTFS fs driver

# About the Author
a kernel developer

# How To use it
```
mount -t nntfs <the disk> <the folder>
```

# About the New feature aside of the NTFS itself
- A sys entry to show the MFT data struct

# About the NTFS datasheet
- https://flatcap.github.io/linux-ntfs/ntfs/

# User Interfaces
## Debug Mode
### Enable Debug Mode
- via proc
```
echo 1 > /proc/sys/fs/ntfs-debug
```
- via sysfs
```
echo 1 > /sys/fs/ntfs/features/debug_enabled 
```
### Disable Debug Mode
- via proc
```
echo 0 > /proc/sys/fs/ntfs-debug
```
- via sysfs
```
echo 0 > /sys/fs/ntfs/features/debug_enabled 
```
### Query Debug Mode
- via proc
```
cat /proc/sys/fs/ntfs-debug
```
- via sysfs
```
cat /sys/fs/ntfs/features/debug_enabled 
```
## Volume MFT info
### Query The Super Block MFT INFO
```
cat /sys/fs/ntfs/loop0/map_ino 
```
