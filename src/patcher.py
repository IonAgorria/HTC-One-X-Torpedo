import asm
from dataclasses import dataclass

import consts

@dataclass
class CodeSearch:
    """ID for code"""
    name: str
    """List of bytes to search to use as reference point, single match"""
    code: bytes
    """List of matches relative to search, used for extra verification"""
    matches: dict[int, bytes]

@dataclass
class PatchData:
    """Offset of patch in relation to search"""
    offset: int
    """Max size in bytes that compiled asm can have, 0 sets the max size to search length, None bypasses check"""
    size: int | None
    """Arch of code: arm or thumb or data if bytes"""
    arch: str
    """Asm code or bytes for patch"""
    code: str | bytes

@dataclass
class PatchInfoData:
    """ID for patch"""
    name: str
    """Description about patch"""
    description: str
    """Groups that this patch belongs to, patch is only applied if selected group is in this list"""
    groups: list[str]
    """Search info for patch"""
    search: CodeSearch
    """How many coincidences the search must yield, all coincidences will be patched"""
    count: int
    """List of patches to apply relative to search"""
    patches: list[PatchData]

"""List of patches to apply"""
_HBOOT_PATCHING = [
    PatchInfoData(
        name = "PKM print reboot",
        description = "Changes '[PKM] Power key is pressed' print with reboot for faster reboots",
        groups = ["test"],
        search = CodeSearch(
            name = "PKM print",
            code = bytes([
                0x01, 0x23, 0x23, 0x61,
                0x23, 0x6a, 0x33, 0xb1,
                0x20, 0x46, 0x98, 0x47,
                0x03, 0xe0, 0x05, 0x20
            ]),
            matches = {},
        ),
        count = 1,
        patches = [
            PatchData(
                offset = -8,
                size = 16,
                arch = "thumb",
                code = f"""
                RebootPMC:
                    {asm.mov32("r0", consts.PMC_ADDR)};
                    mov  r1, {hex(consts.PMC_REBOOT)};
                    str  r1, [r0];
                    //Shouldn't reach here
                    b    RebootPMC;
                """,
            )
        ],
    ),
    PatchInfoData(
        name = "Check magic and jump RCM patch",
        description = "Adds code to jump into enter RCM patch code where previously was checking if is T20 or T30",
        groups = ["patched", "test"],
        search = CodeSearch(
            name = "SoC check code",
            code = bytes([
                0x28, 0x30, 0x9f, 0xe5,
                0x03, 0x30, 0x9f, 0xe7,
                0x00, 0x30, 0x93, 0xe5,
                0x20, 0x00, 0x53, 0xe3,
                0x02, 0x00, 0x00, 0x0a,
                0x30, 0x00, 0x53, 0xe3,
                0x02, 0x00, 0x00, 0x1a,
                0x00, 0x00, 0x00, 0xea
            ]),
            matches = {
                40: bytes([
                    0x00, 0x00, 0xa0, 0xe3,
                    0x1e, 0xff, 0x2f, 0xe1
                ]),
                #Partial match (other bytes keep changing) for offset const we are replacing it with our magic
                50: bytes([
                    0x0e, 0x00
                ]),
            },
        ),
        count = 1,
        patches = [
            PatchData(
                offset = 0,
                size = 32,
                arch = "arm",
                code = bytes([
                    #ldr  r0, [+0x30]
                    0x28, 0x00, 0x9f, 0xe5,
                    #mov  r3, #0xe400
                    0x39, 0x3b, 0xa0, 0xe3,
                    #movt r3, #0x7000
                    0x00, 0x30, 0x47, 0xe3,
                    #ldr  r1, [r3, #0x64]
                    0x64, 0x10, 0x93, 0xe5,
                    #cmp  r1, r0
                    0x00, 0x00, 0x51, 0xe1,
                    #bne  +0x10
                    0x02, 0x00, 0x00, 0x1a,
                    #movw r2, #0xffff
                    0xff, 0x2f, 0x0f, 0xe3,
                    #str  r2, [r3, #0x64]
                    0x64, 0x20, 0x83, 0xe5
                ]),
            ),
            PatchData(
                offset = 48,
                size = 4,
                arch = "data",
                code = bytes([ 0xDE, 0xC0, 0xAD, 0xDE ]),
            )
        ],
    ),
    PatchInfoData(
        name = "Add patch code",
        description = "Unused T20 specific BCT checking code, we put our RCM enter here",
        groups = ["patched", "test"],
        search = CodeSearch(
            name = "T20 BCT",
            code = bytes([
                0x01, 0x31, 0xa0, 0xe3,
                0x21, 0x00, 0xd3, 0xe5,
                0x00, 0x00, 0x50, 0xe3,
                0x1e, 0xff, 0x2f, 0x01,
                0xe4, 0x00, 0x93, 0xe5,
                0x00, 0x00, 0x50, 0xe3,
                0x1e, 0xff, 0x2f, 0x01,
                0x04, 0x20, 0x40, 0xe2,
                0x14, 0x10, 0x9f, 0xe5,
                0x04, 0x00, 0x10, 0xe5,
                0x01, 0x00, 0x50, 0xe1,
                0xe4, 0x20, 0x83, 0x05,
                0x01, 0x00, 0xa0, 0x03,
                0x00, 0x00, 0xa0, 0x13,
                0x1e, 0xff, 0x2f, 0xe1,
                0xd8, 0xad, 0xfe, 0x5a
            ]),
            matches = {},
        ),
        count = 1,
        patches = [
            PatchData(
                offset = 0,
                size = 0,
                arch = "arm",
                code = f"""
                RebootRCM:
                    //Write SCRATCH0
                    mov  r1, {hex(consts.PMC_RCM)};
                    str  r1, [r3, #0x50];
                    dsb  SY;
                    //Write PMC to reboot
                    mov  r1, {hex(consts.PMC_REBOOT)};
                    str  r1, [r3];
                    b    RebootRCM;
                """,
            )
        ]
    ),
    PatchInfoData(
        name = "Replace UNKNOWN str",
        description = "Replaces UNKNOWN string with custom one",
        groups = ["test"],
        search = CodeSearch(
            name = "UNKNOWN string",
            code = b"UNKNOWN %d x %d\0",
            matches = {},
        ),
        count = 1,
        patches = [
            PatchData(
                offset = 0,
                size = 0,
                arch = "data",
                code = b"# DBG %x %x %x\n\0"
            )
        ]
    ),
    PatchInfoData(
        name = "Replace writepid cmd",
        description = "Replaces writepid string with enterrcm",
        groups = ["patched", "test"],
        search = CodeSearch(
            name = "writepid string",
            code = b"writepid\0",
            matches = {},
        ),
        count = 1,
        patches = [
            PatchData(
                offset = 0,
                size = 0,
                arch = "data",
                code = b"enterrcm\0"
            )
        ]
    ),
    PatchInfoData(
        name = "Repurpose writepid/writesecureflag cmd handler",
        description = "Disables writepid and writesecureflag commands that are dangerous and could brick device"
                      " unintentionally, instead we repurpose them for entering APX/RCM via standard SCRATCH0"
                      " and custom patched way via SCRATCH5 to bypass SCRATCH0 lockdown",
        groups = ["patched", "test"],
        search = CodeSearch(
            name = "writepid/writesecureflag",
            code = bytes([
                0x18, 0xb3, 0x4f, 0xf0,
                0xff, 0x33, 0xff, 0x20,
                0x02, 0x93, 0x02, 0xa9,
                0x8d, 0xf8, 0x07, 0x00,
                0x03, 0xaa, 0x03, 0x93,
                0x0d, 0xf1, 0x07, 0x00,
                0x01, 0x23
            ]),
            matches = {
                -22: bytes([
                    0x02, 0x28, 0x1f, 0xb5,
                    0x0c, 0x46, 0x04, 0xd0
                ]),
            },
        ),
        count = 2,
        patches = [
            PatchData(
                offset = -22,
                size = min(120, 36),  # Max is 120
                arch = "thumb",
                code = f"""
                RebootRCMCustom:
                    {asm.mov32("r0", consts.PMC_ADDR)};
                    //Write SCRATCH5
                    {asm.mov32("r1", consts.PMC_RCM_SCRATCH5)};
                    str  r1, [r0, #0x64];
                    //Write SCRATCH0
                    mov  r1, {hex(consts.PMC_RCM)};
                    str  r1, [r0, #0x50];
                    dsb  SY;
                    //Write PMC to reboot
                    mov  r1, {hex(consts.PMC_REBOOT)};
                    str  r1, [r0];
                    //Shouldn't reach here
                    b    RebootRCMCustom;
                """,
            )
        ]
    ),
    PatchInfoData(
        name = "Force trusted 1",
        description = "Patches so function returns 0 / trusted state, avoids locking device",
        groups = ["patched"],
        search = CodeSearch(
            name = "Is untrusted function",
            code = bytes([
                0x05, 0x4b, 0x7b, 0x44,
                0x1b, 0x68, 0x23, 0xb1,
                0x18, 0x68, 0x00, 0x30,
                0x18, 0xbf, 0x01, 0x20,
                0x70, 0x47, 0x4f, 0xf0,
                0xff, 0x30, 0x70, 0x47
            ]),
            matches = {}
        ),
        count = 1,
        patches = [
            PatchData(
                offset = 0,
                size = 0,
                arch = "thumb",
                code = f"""
                    movs r0, #0;
                    bx lr;
                """,
            )
        ],
    ),
    PatchInfoData(
        name = "Force trusted 2",
        description = "Patches so function returns 0 / trusted state, avoids locking device",
        groups = ["patched"],
        search = CodeSearch(
            name = "Is untrusted function",
            code = bytes([
                0x28, 0xb9, 0x05, 0x4b,
                0x7b, 0x44, 0x1b, 0x68,
                0x1b, 0xb1, 0x58, 0x68,
                0x08, 0xbd, 0x03, 0x20,
                0x08, 0xbd, 0x4f, 0xf0,
                0xff, 0x30, 0x08, 0xbd
            ]),
            matches = {
                -6: bytes([ 0x08, 0xb5 ]),
            },
        ),
        count = 1,
        patches = [
            PatchData(
                offset = -4,
                size = 4,
                arch = "thumb",
                code = f"""
                    movs r0, #0;
                    pop {{r3, pc}}
                """,
            )
        ],
    ),
    PatchInfoData(
        name = "Force S-OFF",
        description = "Patches so function returns 0 / S-OFF state",
        groups = ["patched"],
        search = CodeSearch(
            name = "S-ON function",
            code = bytes([
                0x40, 0xb9, 0x05, 0x49,
                0x79, 0x44, 0x09, 0x68,
                0x01, 0xf5, 0x80, 0x53,
                0xd8, 0x69, 0xc0, 0xf3,
                0x40, 0x10, 0x08, 0xbd,
                0x01, 0x20, 0x08, 0xbd,
                0x00, 0xbf
            ]),
            matches = {
                -6: bytes([ 0x08, 0xb5 ]),
            },
        ),
        count = 1,
        patches = [
            PatchData(
                offset = -4,
                size = 4,
                arch = "thumb",
                code = f"""
                    movs r0, #0;
                    pop {{r3, pc}}
                """,
            )
        ]
    ),
    PatchInfoData(
        name = "Replace writesecureflag cmd",
        description = "Replaces writesecureflag string with patched version",
        groups = ["patched", "test"],
        search = CodeSearch(
            name = "writesecureflag string",
            code = b"writesecureflag\0",
            matches = {},
        ),
        count = 1,
        patches = [
            PatchData(
                offset = 0,
                size = 0,
                arch = "data",
                code = b"# Patch ver 109\0"
            )
        ]
    )
]

def find_patch(name: str) -> PatchInfoData|None:
    for patch in _HBOOT_PATCHING:
        if patch.name == name:
            return patch
    return None

def search_code_at_index(data: bytes, search_index: int, search: CodeSearch):
    search_index = data.find(search.code, search_index)
    if search_index < 0:
        return search_index

    #Check the matches for this search
    for match_offset, match_bytes in search.matches.items():
        start = search_index + match_offset
        end = start + len(match_bytes)
        if data[start:end] != match_bytes:
            return -2
    return search_index

def search_code(data: bytes, count: int, search: CodeSearch) -> [int]:
    search_index = 0
    search_matches = []
    while True:
        #Attempt to search after the last coincidence
        search_index = search_code_at_index(data, search_index, search)
        if search_index == -1:
            #Not found
            break
        if search_index == -2:
            raise ValueError(f"Couldn't find match for patch")

        search_matches.append(search_index)

        #Move search forward
        search_index += 1

    if len(search_matches) != count:
        raise ValueError(f"Expected {count} search matches to patch, got {search_matches}")

    return search_matches


def apply_patch_info(data: bytearray, patch_info: PatchInfoData):
    print(f"-> Applying patch: {patch_info.name}")
    search_matches = search_code(data, patch_info.count, patch_info.search)

    for search_index in search_matches:
        #Apply the patches
        for patch_data in patch_info.patches:
            if patch_data.arch == "data" or type(patch_data.code) is bytes:
                patch_bytes = patch_data.code
            else:
                patch_bytes = asm.compile_arm(patch_data.code, patch_data.arch == "thumb")
            #Check bytes
            if patch_data.size == 0 and patch_data.offset == 0:
                #We are replacing existing code with our
                #Check if patch length fits the available space
                if len(patch_info.search.code) < len(patch_bytes):
                    raise ValueError(f"Got {len(patch_info.search.code)} bytes available but compiled patch uses {len(patch_bytes)}")
            elif patch_data.size is not None and patch_data.size != len(patch_bytes):
                #Check size matches expected amount to write
                raise ValueError(f"Expected {patch_data.size} bytes patch to apply, but compiled patch uses {len(patch_bytes)}")

            #Write the bytes
            start = search_index + patch_data.offset
            for i, b in enumerate(patch_bytes):
                data[start + i] = b

def apply_hboot_patches(data: bytearray, group: str):
    for patch_info in _HBOOT_PATCHING:
        if group not in patch_info.groups:
            continue
        apply_patch_info(data, patch_info)
