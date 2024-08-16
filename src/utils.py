import struct

import consts
import patcher

def get_stack_base(bl_data: bytes) -> int:
    if bl_data is None:
        print(f"No bootloader provided!")
        exit(1)
    stack_setup_code_addr = patcher.search_code(bl_data, 1, patcher.CodeSearch(
        name = "Stack setup code",
        code = bytes([
            0x03, 0x30, 0x00, 0xf0, 0x91, 0x80, 0x33, 0x68,
            0x00, 0x2b, 0xf4, 0xd1, 0x92, 0x4e, 0x6f, 0xf0,
            0x01, 0x0b, 0x4f, 0xf0, 0xff, 0x0a, 0x23, 0x46,
            0x7e, 0x44, 0x36, 0x68, 0x2a, 0x46, 0x2e, 0x60,
            0x4f, 0xe0, 0xd8, 0xf8, 0x00, 0x70, 0x0a, 0xf1,
            0x01, 0x01, 0xd8, 0xf8, 0x04, 0x40, 0x5f, 0xfa,
            0x81, 0xfa, 0xd8, 0xf8, 0x08, 0x50, 0x4f, 0xea,
            0x17, 0x49, 0x8d, 0xe8, 0x0c, 0x00, 0x48, 0x46
        ]),
        matches = {}
    ))[0]
    stack_addr_ptr_offset_code = bytes([
            0x52, 0xfa, 0x81, 0xfe, 0x0e, 0xeb, 0x40, 0x13,
            0x98, 0xb2, 0x40, 0x45, 0x14, 0xbf, 0xc1, 0xf3,
            0x41, 0x71, 0x01, 0x21, 0x60, 0x45, 0x08, 0xbf,
            0x02, 0x21, 0xd1, 0xf1, 0x01, 0x0e, 0x38, 0xbf,
            0x4f, 0xf0, 0x00, 0x0e, 0x01, 0x29, 0x14, 0xbf,
            0x71, 0x46, 0x4e, 0xf0, 0x01, 0x01, 0x59, 0xb1,
            0x2b, 0x88, 0x05, 0xeb, 0x43, 0x01, 0x04, 0xe0,
            0x2b, 0x88, 0x4f, 0xf0, 0xff, 0x30, 0x05, 0xeb,
            0x43, 0x01, 0xc8, 0x80, 0x58, 0x1c, 0x28, 0x80,
            0x04, 0x34, 0x20, 0x68, 0x00, 0x28, 0xa8, 0xd1,
            0x09, 0xb0, 0xbd, 0xe8, 0xf0, 0x8f, 0x00, 0xbf
        ])
    stack_addr_ptr_offset_addr = patcher.search_code(bl_data, 1, patcher.CodeSearch(
        name = "Stack setup code before stack address ptr offset",
        code = stack_addr_ptr_offset_code,
        matches = {}
    ))[0]

    #Retrieve the offset to apply into PC to get the stack address pointer
    stack_addr_ptr_offset_addr += len(stack_addr_ptr_offset_code)
    stack_addr_ptr_offset = struct.unpack("<L", bl_data[stack_addr_ptr_offset_addr:stack_addr_ptr_offset_addr+4])[0]

    #Add offset value to PC and obtain address where stack address is located
    stack_addr_ptr_addr = stack_setup_code_addr + 0x1c + stack_addr_ptr_offset
    stack_addr = struct.unpack("<L", bl_data[stack_addr_ptr_addr:stack_addr_ptr_addr+4])[0]

    return stack_addr

def zip_slice(zip_buf: bytes, zip_length: int, extra_buf: bytes) -> bytes:
    #Split EOCD from zip
    zip_eocd = zip_buf[-consts.ZIP_EOCD_SIZE:]
    zip_buf = zip_buf[:-consts.ZIP_EOCD_SIZE]

    #Adjust zip_buf to expected length
    if len(zip_buf) > zip_length:
        raise RuntimeError(f"ZIP section exceeds reserved size {zip_length} with {len(zip_buf)}")
    else:
        zip_buf += b'\0' * (zip_length - len(zip_buf))

    #Check if EOCD is correct
    value = struct.unpack("<I", zip_eocd[0:4])[0]
    if value != consts.ZIP_EOCD_SIGNATURE:
        raise Exception("Generated zip EOCD was not cut correctly!")

    #Glue them
    return zip_buf + extra_buf + zip_eocd

"""
This generates a file that can be used to locate the buffer starting address by doing:
READ_ADDR-(READ_VALUE*4) -> BUF_START
"""
def generate_localizer(output, length):
    l = round((length * 1024 * 1024) / 4)
    print("%s generating file with %i ints that spans %i bytes" % (output, l, length))
    with open(output, "wb") as f:
        for x in range(1, l):
            value = struct.pack("<I", x)
            f.write(value)
    print("%s generated", output)


def align_padding(length, alignment = 4):
    pad = length % alignment
    if pad != 0:
        pad = alignment - pad
    return pad