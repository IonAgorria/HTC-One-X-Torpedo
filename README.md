# HTC One X / X+ hboot exploit Torpedo

HTC One X and X+ Tegra 3 variant hboot ZIP Exploit implementation.

## Requirements

- Working fastboot and adb on your PC
- Working android recovery on your phone
- Python 3
- Libraries in requirements.txt installed for your python 3
- A USB-A to USB Micro-B to connect your phone to PC
- A unlocked HOX/HOX+ phone with Tegra that is S-ON (displays "* UNLOCKED *" and "S-ON" in hboot)
- This repository

## How works

Exploit works by overflowing a heap buffer used to store zlib deflate state during ZIP file entry decompression.
This is archieved by setting ZIP file entry uncompressed size to 0xFFFFFFFF which becomes malloc(0) as this code is executed:

void* uncompressed_file = malloc(uncompressed_size + 1);

This 0 sized buffer is allocated right before the zlib deflate state struct is allocated, allowing the uncompressed data to overwrite and set any values for deflate state when decompressor executes STORED/COPY chunk.
We can gain arbitrary memcpy by using NAME state that allows overwriting the stack with our address to gain code execution once function returns. 

Current payload will flash a patched hboot (changes noted below) that disables security checks and allow full unrestricted access to device MMC.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT.

By using this exploit, you acknowledge that you are intentionally turning off the device's security features. While some potential brick situations have been restricted, the author is not liable for any consequence or warranty void and will not provide any support regarding the usage or results of this exploit.

## Why

As part of group [PostmarketOS on Tegra](https://t.me/pmos_on_tf) that intends to port U-Boot and mainline Linux to all possible Tegra devices, we wanted to port it to HOX+ which is quite similar to previously exploited HOX.

These device are the only one where PMC trick to enter RCM/APX wouldn't work, there is no special hardware button combo to access RCM/APX and BCT/bootloader region was locked down via eMMC write group protection so no way to flash any custom bootloader.

I took this as an interesting opportunity and challenge to learn about reverse engineering and exploitation of an old ARM device with goal to help installing open source counterparts instead of vendor bootloader and OS.

Also to find a new way that is more universal and accessible to users compared to previous exploit that involved special cable and device to trigger a code vulnerability.

## Patched hboot differences

- Disabled security check to avoid locked down state
- S-OFF hardcoded
- writesecureflag and writepid removed to avoid bricks in stock hboot
- Enabled entering RCM/APX by writing 0xDEADC0DE to SCRATCH5 and doing PMC reboot
- fastboot oem enterrcm added to enter RCM/APX mode like in uboot

## Content

- src: Script to generate zip payload that will be sent using fastboot.
- binaries: Contains collected different versions of hboot for each HTC One X Tegra device

## Usage

### Process to backup your phone partitions:

- Create a folder called backup
- Go to android recovery and backup the following partitions by using adb:
```
adb pull /dev/block/platform/sdhci-tegra.3/by-name/PDT backup/PDT.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/WDM backup/WDM.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/MSC backup/MSC.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/SIF backup/SIF.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/PG1 backup/PG1.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/PG2 backup/PG2.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/PG3 backup/PG3.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/RCA backup/RCA.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/RFS backup/RFS.img
adb pull /dev/block/platform/sdhci-tegra.3/by-name/WLN backup/WLN.img
```
- Power down the phone, don't use any other method to enter hboot
- Put hboot in fastboot menu by powering up with vol down pressed and switching to fastboot menu with power button
- Put phone into RUU mode by doing `fastboot oem rebootRUU` (script will do this for you if you don't)
- Run `src/main.py --mode backup` to backup your critical partitions that aren't accessible via recovery
- Check the messages given by this program, it may inform any issues or the progress of backup
- Do something else while it dumps the partitions, it may take 30 minutes total
- Move the files you obtained from android recovery to your device subfolder created by `--mode backup` such as `backup/YOURCODENAME/DEVICESERIAL_HBOOTVERSION`

### Flashing patched bootloader:
- If your phone is already S-OFF don't use this to flash!
- Follow the backup instructions above if you haven't already
- Run `src/main.py --bl binaries/YOURCODENAME/hboot_YOURDEVICE_1.72.img`
- Check the messages given by this program, it may inform you if some backup file is missing or the progress of flashing
- You should see patched hboot with S-OFF on reboot if all went OK

If phone gets stuck for a minute please long press power button and retry whole process from start again.
Tegra SoC may get hot when it hangs so is recommended to not wait too much.

## Something went wrong

In case the flashing went wrong and your device is in RCM/APX mode, you can ask us for help [PostmarketOS on Tegra](https://t.me/pmos_on_tf)
about using nvflash with Fusee-Geelee for Tegra 3 https://github.com/tofurky/tegra30_debrick/ or using the prepackaged NvFlash for HOX (it may work for HOX+ too)
most times only BCT and EBT needs to be restored.

You can find patched bootloader unencrypted in output/bootloader_patched_YOURDEVICE_1.72.0000.img.

In rare case where device doesn't boot into RCM/APX because BCT signature is OK but bootloader is not functional or you got into security locked state, you can trigger APX mode by grounding this testpad indicated at the pic to ground (any screw hole pad in board or USB connector are grounded):
- [HTC ONE X APX pad](/pictures/hox-apx.png)
- [HTC ONE X+ APX pad](/pictures/hoxplus-apx.png)

## Supported hboot versions

At this moment payloads for HOX 1.36 and HOX/HOX+ 1.72 hboot versions are supported
For adding new versions please consult HBOOT_CONFIG in src/consts.py.
It contains per device/version specific data required to generate the exploit zip

## Licence

depthcharge_generator and depthcharge_tinyusb are released under GPL v3
