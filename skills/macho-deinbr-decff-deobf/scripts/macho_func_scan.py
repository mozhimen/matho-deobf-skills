#!/usr/bin/env python3
import argparse
from collections import Counter

import arm64_flow as flow


def main():
    parser = argparse.ArgumentParser(description="Scan an ARM64 Mach-O function range for deobfuscation patterns.")
    parser.add_argument("binary")
    parser.add_argument("--start", required=True, type=flow.parse_int)
    parser.add_argument("--end", required=True, type=flow.parse_int)
    parser.add_argument("--entry", type=flow.parse_int)
    parser.add_argument("--file-delta", default=0, type=flow.parse_int, help="file offset delta: fileoff = vmaddr + delta")
    parser.add_argument("--state-base", default="x23")
    parser.add_argument("--state-disp", default=0x1138, type=flow.parse_int)
    args = parser.parse_args()
    entry = args.entry if args.entry is not None else args.start

    with open(args.binary, "rb") as f:
        data = f.read()

    insns = flow.disasm_range(data, args.start, args.end, args.file_delta)
    starts = flow.find_blocks(insns, args.start, args.end, entry)
    blocks = flow.build_blocks(insns, starts)
    reachable = flow.reachable_blocks(blocks, starts, entry, args.start, args.end)
    by_addr = {insn.address: insn for insn in insns}

    mnems = Counter(insn.mnemonic for insn in insns if flow.block_for(starts, insn.address) in reachable)
    cond_pairs = 0
    state_stores = 0
    loopbacks = []
    for block in sorted(reachable):
        block_insns = blocks.get(block, [])
        if flow.has_state_store(block_insns, args.state_base, args.state_disp):
            state_stores += 1
        for insn in block_insns:
            if not flow.is_cond_branch(insn):
                continue
            next_insn = by_addr.get(insn.address + 4)
            if next_insn and next_insn.mnemonic == "b":
                cond_pairs += 1
                true_dest = flow.branch_target(insn)
                false_dest = flow.branch_target(next_insn)
                if true_dest is not None and false_dest is not None:
                    true_back = flow.direct_path_back(blocks, starts, true_dest, block, args.start, args.end, args.state_base, args.state_disp)
                    false_back = flow.direct_path_back(blocks, starts, false_dest, block, args.start, args.end, args.state_base, args.state_disp)
                    if true_back != false_back:
                        loopbacks.append((insn.address, true_dest if true_back else false_dest, false_dest if true_back else true_dest))
            break

    print(f"binary={args.binary}")
    print(f"range=0x{args.start:x}-0x{args.end:x} entry=0x{entry:x} file_delta={args.file_delta}")
    print(f"instructions={len(insns)} blocks={len(blocks)} reachable_blocks={len(reachable)}")
    print(f"reachable_br={mnems.get('br', 0)} reachable_blr={mnems.get('blr', 0)}")
    print(f"reachable_conditional={sum(count for mnem, count in mnems.items() if mnem.startswith('b.') and mnem != 'b')}")
    print(f"conditional_pairs={cond_pairs}")
    print(f"state_store_blocks={state_stores} state=[{args.state_base},#0x{args.state_disp:x}]")
    print(f"loopback_candidates={len(loopbacks)}")
    for addr, junk, real in loopbacks:
        print(f"0x{addr:x}: junk=0x{junk:x} real=0x{real:x}")


if __name__ == "__main__":
    main()
