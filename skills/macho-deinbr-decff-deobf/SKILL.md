---
name: macho-deinbr-decff-deobf
description: Deobfuscate ARM64 Mach-O functions protected by O-LLVM/Hikari-style indirect branch, control-flow flattening, and bogus control flow. Use when the user gives a Mach-O/dylib binary and a function or text address and asks to remove BR indirect jumps, CFF dispatchers, BCF bogus branches, opaque predicates, or recover readable control flow.
---

# Mach-O DeinBR DecFF Deobf

Use this skill for ARM64 Mach-O function-level binary deobfuscation. Work in stages, always producing a new artifact for each stage and verifying before moving to the next.

## Workflow

1. Locate the function range.
   - Treat the user-provided `text:` address as a VM address unless evidence says otherwise.
   - Determine `FUNC_START`, `FUNC_END`, and the real entry after any prologue/dispatcher.
   - For Mach-O files whose `__TEXT` `vmaddr == fileoff` mapping is aligned, VM addresses can often be patched as file offsets. Verify this before writing.

2. Scan for indirect branch obfuscation.
   - Disassemble from the provided address to the function end.
   - If reachable code contains `br xN`/`blr xN` controlled by `csel`, `cset`, loaded jump targets, or symbolic state, run a DeinBR pass first.
   - Prefer symbolic execution plus BFS traversal to recover direct edges. Patch each indirect `br` to a direct `b target` only when the target is proven.
   - Verify the function range has no remaining `br` before continuing.

3. Scan for CFF.
   - Look for a common dispatcher, repeated state stores such as `ldr x?, [x23,#disp]; str w?, [x?]`, state comparisons, and many blocks returning to the dispatcher.
   - Recover state value to target block mapping.
   - Patch each state-write tail into a direct branch to the next semantic block.
   - Patch the entry to jump to the first semantic block.
   - Leave dead dispatcher bytes in place unless removal is explicitly needed; correctness is controlled by active edges.
   - Verify no active state-write-to-dispatch transitions remain.

4. Remove BCF/opaque predicates.
   - First patch constant predicates where arithmetic over constant data deterministically decides `b.cond`.
   - Then patch loopback bogus branches: in `b.cond junk; b real`, if the `junk` target only writes a fake state and jumps back to the current decision block, replace the conditional branch with `b real` and NOP the paired branch.
   - Keep branches that depend on parameters, ObjC return values, memory state, or calls unless another proof exists.

5. Validate the final artifact.
   - Re-run the scan script on the final output.
   - Check indirect `br` count, CFF transition count, and remaining known BCF predicates.
   - Spot-disassemble every newly patched address.
   - Report output paths, patch counts, skipped cases, and signing status.

## Bundled Scripts

- `scripts/macho_func_scan.py`: quick scanner for ARM64 Mach-O function ranges. Use it to count `br`, conditional pairs, state-store candidates, and loopback candidates.
- `scripts/debcf_arm64.py`: conservative BCF patcher for constant predicates and loopback bogus branches after DeinBR and DecFF.

Example:

```bash
python3 scripts/macho_func_scan.py libX.dylib --start 0x85b10 --end 0x8ad90 --entry 0x89054
python3 scripts/debcf_arm64.py libX_decff.dylib libX_debcf.dylib --start 0x85b10 --end 0x8ad90 --entry 0x89054 --state-base x23 --state-disp 0x1138
```

## References

- Read `references/workflow.md` when planning a full multi-stage deobfuscation.
- Read `references/patterns.md` when deciding whether a pattern is safe to patch.

## Safety Rules

- Patch only proven edges. Unknown branches are better left intact than guessed.
- Never overwrite the input binary; always write a stage-named output.
- Keep a machine-readable patch log or console output with every changed address.
- Do not re-sign automatically unless the user requests it.
