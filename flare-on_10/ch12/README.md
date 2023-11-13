## 1. I Wanted a VM challenge and all i got was an hypervisor challenge...

...and it was cool :)

opening the binary yields some clean pseudocode (for a change) that uses the [Windows Hypervisor Platform API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform).

It feeds the partition some code from the PE resource and respond to IO requests (namely IN and OUT instructions) by RC4 decrypting and encrypting code relative to plus or minus RIP offset.

## 2. Debugging

I wanted to a grasp of the code in the rsrc because offset 0 wasn't making much x64 sense and didnt know where to start (author explains why in the official solution).

I have no windows host, so filled with some sweet candid hope, enabled HyperV in my analysis VM, rebooted and ended up with a bricked VM... once more, yayy for snapshots.

Long story short, i have never been able to run the binary.

## 3. Static analysis

I loaded the extracted resource into Binary Ninja, found some random piece of code that made sense.
