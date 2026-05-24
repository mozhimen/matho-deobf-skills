#!/usr/bin/env python3
import argparse
import shutil

import arm64_flow as flow


def collect_known(data, start, end, entry, file_delta):
    insns = flow.disasm_range(data, start, end, file_delta)
    by_addr = {insn.address: insn for insn in insns}
    starts = flow.find_blocks(insns, start, end, entry)
    blocks = flow.build_blocks(insns, starts)
    reachable = flow.reachable_blocks(blocks, starts, entry, start, end)
    known = []
    unknown = 0
    for block in sorted(reachable):
        regs = {}
        flags = flow.UNKNOWN
        for insn in blocks[block]:
            if flow.is_cond_branch(insn):
                cond = insn.mnemonic.split(".", 1)[1]
                outcome = flow.eval_cond(cond, flags)
                if outcome is flow.UNKNOWN:
                    unknown += 1
                else:
                    known.append((block, insn, outcome))
                break
            new_flags = flow.step(data, regs, insn, file_delta)
            if new_flags is not None:
                flags = new_flags
    return known, unknown, by_addr


def collect_loopbacks(data, start, end, entry, file_delta, state_base, state_disp):
    insns = flow.disasm_range(data, start, end, file_delta)
    by_addr = {insn.address: insn for insn in insns}
    starts = flow.find_blocks(insns, start, end, entry)
    blocks = flow.build_blocks(insns, starts)
    reachable = flow.reachable_blocks(blocks, starts, entry, start, end)
    out = []
    for block in sorted(reachable):
        for insn in blocks[block]:
            if not flow.is_cond_branch(insn):
                continue
            next_insn = by_addr.get(insn.address + 4)
            if not next_insn or next_insn.mnemonic != "b":
                break
            true_dest = flow.branch_target(insn)
            false_dest = flow.branch_target(next_insn)
            if true_dest is None or false_dest is None:
                break
            true_back = flow.direct_path_back(blocks, starts, true_dest, block, start, end, state_base, state_disp)
            false_back = flow.direct_path_back(blocks, starts, false_dest, block, start, end, state_base, state_disp)
            if true_back != false_back:
                real_dest = false_dest if true_back else true_dest
                junk_dest = true_dest if true_back else false_dest
                out.append((block, insn, next_insn, real_dest, junk_dest))
            break
    return out


def paired_destination(insn, outcome, by_addr):
    true_dest = flow.branch_target(insn)
    next_insn = by_addr.get(insn.address + 4)
    if next_insn and next_insn.mnemonic == "b":
        false_dest = flow.branch_target(next_insn)
        return true_dest if outcome else false_dest, next_insn
    return true_dest if outcome else insn.address + 4, None


def main():
    parser = argparse.ArgumentParser(description="Patch proven ARM64 BCF branches in a Mach-O function range.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--start", required=True, type=flow.parse_int)
    parser.add_argument("--end", required=True, type=flow.parse_int)
    parser.add_argument("--entry", type=flow.parse_int)
    parser.add_argument("--file-delta", default=0, type=flow.parse_int, help="file offset delta: fileoff = vmaddr + delta")
    parser.add_argument("--state-base", default="x23")
    parser.add_argument("--state-disp", default=0x1138, type=flow.parse_int)
    args = parser.parse_args()
    entry = args.entry if args.entry is not None else args.start

    shutil.copyfile(args.input, args.output)
    with open(args.output, "rb") as f:
        buf = bytearray(f.read())

    loopbacks = collect_loopbacks(bytes(buf), args.start, args.end, entry, args.file_delta, args.state_base, args.state_disp)
    known, unknown, by_addr = collect_known(bytes(buf), args.start, args.end, entry, args.file_delta)

    patched_addrs = set()
    patched_loopbacks = []
    patched_known = []
    skipped = []

    for block, insn, next_insn, real_dest, junk_dest in loopbacks:
        if real_dest is None or not args.start <= real_dest < args.end:
            skipped.append((insn.address, "loopback destination outside range"))
            continue
        flow.put_u32(buf, insn.address, flow.encode_b(insn.address, real_dest), args.file_delta)
        flow.put_u32(buf, next_insn.address, flow.NOP, args.file_delta)
        patched_addrs.add(insn.address)
        patched_loopbacks.append((block, insn.address, insn.mnemonic, junk_dest, real_dest, next_insn.address))

    for block, insn, outcome in known:
        if insn.address in patched_addrs:
            continue
        dest, next_insn = paired_destination(insn, outcome, by_addr)
        if dest is None or not args.start <= dest < args.end:
            skipped.append((insn.address, "destination outside range"))
            continue
        if dest == insn.address + 4 and next_insn is None:
            flow.put_u32(buf, insn.address, flow.NOP, args.file_delta)
        else:
            flow.put_u32(buf, insn.address, flow.encode_b(insn.address, dest), args.file_delta)
        if next_insn:
            flow.put_u32(buf, next_insn.address, flow.NOP, args.file_delta)
        patched_known.append((block, insn.address, insn.mnemonic, outcome, dest, next_insn.address if next_insn else None))

    with open(args.output, "wb") as f:
        f.write(buf)

    print(f"input={args.input}")
    print(f"output={args.output}")
    print(f"known_conditional={len(known)}")
    print(f"unknown_conditional_kept={unknown}")
    print(f"loopback_conditional={len(loopbacks)}")
    print(f"patched={len(patched_loopbacks) + len(patched_known)}")
    print(f"patched_loopback={len(patched_loopbacks)}")
    print(f"patched_known={len(patched_known)}")
    print(f"skipped={len(skipped)}")
    for block, addr, mnem, junk, real, nop_addr in patched_loopbacks:
        print(f"0x{addr:x} block=0x{block:x} {mnem} junk=0x{junk:x} -> b 0x{real:x} nop_next=0x{nop_addr:x}")
    for block, addr, mnem, outcome, dest, nop_addr in patched_known:
        suffix = f" nop_next=0x{nop_addr:x}" if nop_addr else ""
        print(f"0x{addr:x} block=0x{block:x} {mnem} outcome={outcome} -> b 0x{dest:x}{suffix}")
    for addr, reason in skipped:
        print(f"skip 0x{addr:x}: {reason}")


if __name__ == "__main__":
    main()
