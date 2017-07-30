NTFS-defused
============

currently work-in-progress
===========================

An attempt to complete the native Linux NTFS read/write kernel driver using code from Apple (http://www.opensource.apple.com/source/ntfs/ntfs-83/kext/) as a reference.


currently work-in-progress
===========================

22nd June 2017

I will build some auto-test script. 

And then, I will upload my code to this project.

Please hold on. 

I have waiten for 8 years. It is easy to wait for a few more month, right?

PS:

the datasheet of NTFS:

https://flatcap.github.io/linux-ntfs/ntfs/

29nd June 2017

Currently this source can work with 4.1 kernel.

I am making a tag and go on for 4.4 kernel

Debug Tips 
===========================

sysctl fs.ntfs-debug=1

Or

echo 1 > /proc/sys/fs/ntfs-debug


