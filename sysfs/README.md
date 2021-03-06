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
## Mount Option
### File system type
- To avoid the confliction with kernel ntfs driver and ntfs-3g driver, you can specified the FS type according to the sysfs interface
```
TYPE=`cat /sys/fs/ntfs/features/mount_type`
mount -t ${TYPE} /dev/sdN /mnt
```
