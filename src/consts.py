#Config

ZIP_EOCD_SIZE=0x16
ZIP_EOCD_SIGNATURE=0x06054b50

#Constants for reboot
HBOOT_REASON_ADDR = 0xbf7fe000
HBOOT_REASON_FASTBOOT = 0x77665500
HBOOT_REASON_RUU = 0x6f656D78
PMC_ADDR = 0x7000E400
PMC_REBOOT = 0x10
PMC_RCM = 0x2
PMC_RCM_SCRATCH5 = 0xDEADC0DE

#Apparently flashing hboot's bigger or smaller than this causes bricks (without triggering APX due to signature being OK) so we make sure that doesnt happen
HBOOT_LENGTH = 0x200010

#Tegra 3 address where bootloader is loaded
BL_LOAD_ADDRESS = 0x80108000

#Max length each STORED chunk can have incl headers
ZLIB_STORED_LIMIT = 0xFFFF
ZLIB_HEADER_SIZE = 5

#How much bytes to allocate for zip
PAYLOAD_ZIP_RESERVED = (ZLIB_STORED_LIMIT + 1) + 0x200000 + 200

#Max size for loader, this limit is arbitrary but the less the better
PAYLOAD_LOADER_RESERVED = 0x100

#Extra padding to wrap the payload with
PAYLOAD_EXTRA_PADDING = 0x10000

#Where to put the payload during relocation
PAYLOAD_RELOCATED_ADDR = 0xA1000000

PAYLOAD_MAGIC = 0xC0DECAFE

DUMP_START_MARKER = b"DUMP"

DUMP_PARTITIONS = [
    {"name": "BCT", "length":  0x400000, "hidden": True},
    {"name": "EBT", "length":  0x400000, "hidden": True},
    {"name": "PT",  "length":  0x200000, "hidden": True},
    {"name": "BIF", "length":  0x200000, "hidden": True},
    {"name": "GP1", "length":  0x200000, "hidden": True},
    {"name": "GPT", "length":  0x200000, "hidden": True},
    #These while important can be obtained with recovery
    {"name": "PDT", "length":  0x200000, "hidden": False},
    {"name": "WDM", "length":  0x200000, "hidden": False},
    {"name": "MSC", "length":  0x200000, "hidden": False},
    {"name": "SIF", "length":  0x400000, "hidden": False},
    {"name": "PG1", "length": 0x1000000, "hidden": False},
    {"name": "PG2", "length": 0x1000000, "hidden": False},
    {"name": "PG3", "length": 0x1000000, "hidden": False},
    {"name": "RCA", "length":  0x600000, "hidden": False},
    {"name": "RFS", "length":  0x600000, "hidden": False},
    {"name": "WLN", "length":  0x600000, "hidden": False},
]

########################################################################################################################
# Model + hboot specifics

#This contains per Device model and hboot version specific values:
# symbols: used to identify which tegra hboot the bootloader belongs to (HOX or HOX+)
# versions: hboot version specific values
#   stack_base: Address that is the base/start of stack for main thread, this tool contains a way to extract this value from a bootloader file
#   fastboot_start: Addresses where fastboot recv buffer starts, use utils -> generate_localizer to obtain this address for other versions
HBOOT_CONFIG = [
    {
        "device": "HOX",
        "symbols": [
            "board_phantom",
            "board_endeavoru",
            "board_endeavortd",
            "board_erau"
        ],
        "versions": {
            "1.36.0000": {
                "stack_base": 0x802b6640,
                "fastboot_start": 0x806be220,
            },
            "1.72.0000": {
                "stack_base": 0x802b8680,
                "fastboot_start": 0x806beee0,
            },
        },
    },
    {
        "device": "HOXplus",
        "symbols": [
            "board_enrc2_u",
            "board_opera_ul",
            "board_evitare_ul",
            "board_enrc2b_u"
        ],
        "versions": {
            "1.72.0000": {
                "stack_base": 0x802c2378,
                "fastboot_start": 0x806a2e00,
            },
        },
    }
]
