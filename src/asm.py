import keystone

def compile_arm(code: str, thumb=False) -> bytearray:
    code = code.strip()
    ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB if thumb else keystone.KS_MODE_ARM)
    try:
        binary, _ = ks.asm(code)
        if binary is None:
            error = "No assembler output!"
        else:
            return bytearray(binary)
    except keystone.KsError as e:
        error = e.message

    code_test = ""
    for code_line in code.split("\n"):
        try:
            code_test += code_line.strip() + "\n"
            ks.asm(code_test)
        except keystone.KsError:
            break

    if 0 == len(code_test):
        code_test = "Unknown line"
    else:
        code_test += "^^^^^^^^^^^^^^^^^^^^^^^^"
    
    import traceback
    print("\n>>> Keystone assembler error <<<")
    traceback.print_stack()
    print("\nAttempted code:\n%s\n%s" % (code_test, error))
    exit(1)


def mov32(register: str, constant: int):
    if constant < 0 or constant > 0xFFFFFFFF:
        raise ValueError(f"Value {constant} must be unsigned 32 bits!")
    if constant <= 0xFFFF:
        constant_l = "0x%x" % (constant & 0xFFFF)
        return f"mov {register}, #{constant_l};"
    constant_l = "0x%x" % (constant & 0xFFFF)
    constant_h = "0x%x" % ((constant & 0xFFFF0000) >> 16)
    return f"movw {register}, #{constant_l};\n\t\tmovt {register}, #{constant_h};"


def jump(addr, extra_code=None):
    if addr == 0 or addr is None:
        raise ValueError(f"The address to call '{addr}' is not set!")
    code = f"""
        {mov32("r11", addr)};
    """
    if extra_code is not None:
        code += extra_code
    code += f"""
        blx r11;
    """
    return code


def call(addr, extra_code=None):
    return f"""
        push {{r11}};
        {jump(addr, extra_code)}
        pop {{r11}};
    """

def br(text):
    return "{" + text + "}"

def code_data(register, start_addr, buf, data):
    addr = len(buf)
    buf += data
    while (len(buf) % 4) != 0:
        buf += b'\0'
    return mov32(register, start_addr + addr)

def code_string(register, start_addr, buf, text, nl=1):
    if 0 < nl and not text.endswith("\n"):
        text += "\n" * nl
    if not text.endswith("\0"):
        text += "\0"
    text = bytearray(text.encode("ascii"))
    return code_data(register, start_addr, buf, text)
