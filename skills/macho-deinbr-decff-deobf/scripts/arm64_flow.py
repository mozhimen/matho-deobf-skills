#!/usr/bin/env python3
import struct
from collections import deque

import capstone
from capstone import arm64


UNKNOWN = object()
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
NOP = 0xD503201F


def parse_int(value):
    return int(value, 0)


def u32(value):
    return value & MASK32


def u64(value):
    return value & MASK64


def s32(value):
    value &= MASK32
    return value - 0x100000000 if value & 0x80000000 else value


def reg_width(name):
    return 64 if name.startswith("x") else 32


def x_alias(name):
    if name in {"wzr", "xzr"}:
        return "xzr"
    if name.startswith("w"):
        return "x" + name[1:]
    return name


def w_alias(name):
    if name in {"wzr", "xzr"}:
        return "wzr"
    if name.startswith("x"):
        return "w" + name[1:]
    return name


def read_reg(regs, name):
    if name in {"wzr", "xzr"}:
        return 0
    if name.startswith("x"):
        return regs.get(x_alias(name), UNKNOWN)
    value = regs.get(w_alias(name), UNKNOWN)
    if value is not UNKNOWN:
        return u32(value)
    value = regs.get(x_alias(name), UNKNOWN)
    return UNKNOWN if value is UNKNOWN else u32(value)


def write_reg(regs, name, value):
    if name in {"wzr", "xzr"}:
        return
    if value is UNKNOWN:
        regs[x_alias(name)] = UNKNOWN
        regs[w_alias(name)] = UNKNOWN
        return
    if name.startswith("x"):
        regs[x_alias(name)] = u64(value)
        regs[w_alias(name)] = u32(value)
    else:
        regs[w_alias(name)] = u32(value)
        regs[x_alias(name)] = u32(value)


def disasm_range(data, start, end, file_delta=0):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    off_start = start + file_delta
    off_end = end + file_delta
    return list(md.disasm(data[off_start:off_end], start))


def branch_target(insn):
    if insn.operands and insn.operands[0].type == arm64.ARM64_OP_IMM:
        return insn.operands[0].imm
    return None


def is_cond_branch(insn):
    return insn.mnemonic.startswith("b.") and insn.mnemonic != "b"


def is_any_branch(insn):
    return insn.mnemonic == "b" or is_cond_branch(insn) or insn.mnemonic == "ret"


def find_blocks(insns, func_start, func_end, entry):
    starts = {func_start, entry}
    for idx, insn in enumerate(insns):
        if insn.mnemonic == "b" or is_cond_branch(insn):
            target = branch_target(insn)
            if target is not None and func_start <= target < func_end:
                starts.add(target)
        if is_any_branch(insn) and idx + 1 < len(insns):
            starts.add(insns[idx + 1].address)
    return sorted(starts)


def block_for(starts, address):
    current = starts[0]
    for start in starts:
        if start > address:
            break
        current = start
    return current


def build_blocks(insns, starts):
    blocks = {start: [] for start in starts}
    for insn in insns:
        blocks.setdefault(block_for(starts, insn.address), []).append(insn)
    return blocks


def successors(block_insns, func_start, func_end):
    if not block_insns:
        return []
    last = block_insns[-1]
    if last.mnemonic == "ret":
        return []
    if last.mnemonic == "b":
        return [branch_target(last)]
    if is_cond_branch(last):
        return [branch_target(last), last.address + 4]
    fall = last.address + 4
    return [fall] if func_start <= fall < func_end else []


def reachable_blocks(blocks, starts, entry, func_start, func_end):
    seen = set()
    queue = deque([entry])
    while queue:
        address = queue.popleft()
        block = block_for(starts, address)
        if block in seen or block not in blocks:
            continue
        seen.add(block)
        for succ in successors(blocks[block], func_start, func_end):
            if succ is not None and func_start <= succ < func_end:
                queue.append(succ)
    return seen


def read_mem(data, address, size, file_delta=0):
    offset = address + file_delta
    if offset < 0 or offset + size > len(data):
        return UNKNOWN
    if size == 4:
        return struct.unpack_from("<I", data, offset)[0]
    if size == 8:
        return struct.unpack_from("<Q", data, offset)[0]
    return UNKNOWN


def operand_value(data, regs, insn, operand, file_delta=0):
    if operand.type == arm64.ARM64_OP_IMM:
        return operand.imm
    if operand.type != arm64.ARM64_OP_REG:
        return UNKNOWN
    value = read_reg(regs, insn.reg_name(operand.reg))
    if value is UNKNOWN:
        return UNKNOWN
    if operand.shift.type == arm64.ARM64_SFT_LSR:
        return value >> operand.shift.value
    if operand.shift.type == arm64.ARM64_SFT_LSL:
        return u64(value << operand.shift.value)
    return value


def eval_cond(cond, flags):
    if flags is UNKNOWN:
        return UNKNOWN
    left, right = flags
    if cond == "eq":
        return u32(left) == u32(right)
    if cond == "ne":
        return u32(left) != u32(right)
    if cond == "lt":
        return s32(left) < s32(right)
    if cond == "le":
        return s32(left) <= s32(right)
    if cond == "gt":
        return s32(left) > s32(right)
    if cond == "ge":
        return s32(left) >= s32(right)
    if cond in {"lo", "cc"}:
        return u32(left) < u32(right)
    if cond in {"hs", "cs"}:
        return u32(left) >= u32(right)
    if cond == "hi":
        return u32(left) > u32(right)
    if cond == "ls":
        return u32(left) <= u32(right)
    return UNKNOWN


def step(data, regs, insn, file_delta=0):
    ops = insn.operands
    mnemonic = insn.mnemonic
    flags = None
    if mnemonic == "adrp" and len(ops) == 2:
        write_reg(regs, insn.reg_name(ops[0].reg), ops[1].imm)
    elif mnemonic in {"add", "sub"} and len(ops) >= 3:
        left = operand_value(data, regs, insn, ops[1], file_delta)
        right = operand_value(data, regs, insn, ops[2], file_delta)
        write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN if UNKNOWN in {left, right} else (left + right if mnemonic == "add" else left - right))
    elif mnemonic == "mov" and len(ops) == 2:
        write_reg(regs, insn.reg_name(ops[0].reg), operand_value(data, regs, insn, ops[1], file_delta))
    elif mnemonic == "movk" and len(ops) >= 2:
        dst = insn.reg_name(ops[0].reg)
        old = read_reg(regs, dst)
        old = 0 if old is UNKNOWN else old
        shift = ops[1].shift.value if ops[1].shift.type else 0
        width_mask = MASK64 if reg_width(dst) == 64 else MASK32
        mask = (0xFFFF << shift) & width_mask
        write_reg(regs, dst, (old & ~mask) | ((ops[1].imm & 0xFFFF) << shift))
    elif mnemonic in {"mvn", "lsl"} and len(ops) >= 2:
        value = operand_value(data, regs, insn, ops[1], file_delta)
        if mnemonic == "mvn":
            write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN if value is UNKNOWN else ~value)
        else:
            shift = operand_value(data, regs, insn, ops[2], file_delta) if len(ops) > 2 else 0
            write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN if UNKNOWN in {value, shift} else value << shift)
    elif mnemonic in {"and", "orr", "eor", "bic", "orn", "mul", "udiv"} and len(ops) >= 3:
        left = operand_value(data, regs, insn, ops[1], file_delta)
        right = operand_value(data, regs, insn, ops[2], file_delta)
        if UNKNOWN in {left, right}:
            write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN)
        elif mnemonic == "and":
            write_reg(regs, insn.reg_name(ops[0].reg), left & right)
        elif mnemonic == "orr":
            write_reg(regs, insn.reg_name(ops[0].reg), left | right)
        elif mnemonic == "eor":
            write_reg(regs, insn.reg_name(ops[0].reg), left ^ right)
        elif mnemonic == "bic":
            write_reg(regs, insn.reg_name(ops[0].reg), left & ~right)
        elif mnemonic == "orn":
            write_reg(regs, insn.reg_name(ops[0].reg), left | ~right)
        elif mnemonic == "mul":
            write_reg(regs, insn.reg_name(ops[0].reg), left * right)
        elif mnemonic == "udiv":
            write_reg(regs, insn.reg_name(ops[0].reg), 0 if right == 0 else u32(left) // u32(right))
    elif mnemonic == "madd" and len(ops) == 4:
        values = [operand_value(data, regs, insn, op, file_delta) for op in ops[1:]]
        write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN if UNKNOWN in values else values[0] * values[1] + values[2])
    elif mnemonic == "umull" and len(ops) == 3:
        left = operand_value(data, regs, insn, ops[1], file_delta)
        right = operand_value(data, regs, insn, ops[2], file_delta)
        write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN if UNKNOWN in {left, right} else u64(u32(left) * u32(right)))
    elif mnemonic == "lsr" and len(ops) == 3:
        left = operand_value(data, regs, insn, ops[1], file_delta)
        right = operand_value(data, regs, insn, ops[2], file_delta)
        write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN if UNKNOWN in {left, right} else left >> right)
    elif mnemonic in {"ldr", "ldur"} and len(ops) == 2 and ops[1].type == arm64.ARM64_OP_MEM:
        mem = ops[1].mem
        base = read_reg(regs, insn.reg_name(mem.base))
        dst = insn.reg_name(ops[0].reg)
        size = 8 if dst.startswith("x") else 4
        write_reg(regs, dst, UNKNOWN if base is UNKNOWN else read_mem(data, base + mem.disp, size, file_delta))
    elif mnemonic == "cmp" and len(ops) == 2:
        left = operand_value(data, regs, insn, ops[0], file_delta)
        right = operand_value(data, regs, insn, ops[1], file_delta)
        flags = UNKNOWN if UNKNOWN in {left, right} else (left, right)
    elif mnemonic == "csel" and len(ops) == 4:
        write_reg(regs, insn.reg_name(ops[0].reg), UNKNOWN)
    elif mnemonic.startswith("bl"):
        write_reg(regs, "x0", UNKNOWN)
    return flags


def encode_b(address, destination):
    delta = destination - address
    if delta % 4:
        raise ValueError(f"unaligned branch 0x{address:x} -> 0x{destination:x}")
    imm26 = delta // 4
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError(f"branch out of range 0x{address:x} -> 0x{destination:x}")
    return 0x14000000 | (imm26 & 0x03FFFFFF)


def put_u32(buf, vmaddr, value, file_delta=0):
    struct.pack_into("<I", buf, vmaddr + file_delta, value & MASK32)


def is_state_store_pair(insns, idx, state_base="x23", state_disp=0x1138):
    if idx <= 0:
        return False
    cur = insns[idx]
    prev = insns[idx - 1]
    if cur.mnemonic != "str" or len(cur.operands) != 2:
        return False
    mem = cur.operands[1]
    if mem.type != arm64.ARM64_OP_MEM:
        return False
    ptr_reg = cur.reg_name(mem.mem.base)
    if prev.mnemonic not in {"ldr", "ldur"} or len(prev.operands) != 2:
        return False
    if prev.reg_name(prev.operands[0].reg) != ptr_reg:
        return False
    src = prev.operands[1]
    if src.type != arm64.ARM64_OP_MEM:
        return False
    return prev.reg_name(src.mem.base) == state_base and src.mem.disp == state_disp


def has_state_store(insns, state_base="x23", state_disp=0x1138):
    return any(is_state_store_pair(insns, idx, state_base, state_disp) for idx in range(len(insns)))


def direct_path_back(blocks, starts, target, source, func_start, func_end, state_base="x23", state_disp=0x1138, max_blocks=8, max_insns=180):
    start = block_for(starts, target)
    source = block_for(starts, source)
    stack = [(start, 0, 0, False)]
    seen = set()
    found = False
    saw_state_store = False
    while stack:
        block, depth, insn_count, state_store = stack.pop()
        if block == source and depth > 0:
            found = True
            saw_state_store = saw_state_store or state_store
            continue
        if block in seen or block not in blocks or depth >= max_blocks:
            continue
        seen.add(block)
        block_insns = blocks[block]
        if insn_count + len(block_insns) > max_insns:
            continue
        state_store = state_store or has_state_store(block_insns, state_base, state_disp)
        if not block_insns:
            continue
        last = block_insns[-1]
        if last.mnemonic == "b":
            target = branch_target(last)
            if target is not None and func_start <= target < func_end:
                stack.append((block_for(starts, target), depth + 1, insn_count + len(block_insns), state_store))
        elif last.mnemonic == "ret" or is_cond_branch(last):
            continue
        else:
            fall = last.address + 4
            if func_start <= fall < func_end:
                stack.append((block_for(starts, fall), depth + 1, insn_count + len(block_insns), state_store))
    return found and saw_state_store
