# Workflow Reference

## Stage Naming

Use explicit artifact names:

- `*_deinbr.dylib`
- `*_deinbr_decff.dylib`
- `*_deinbr_decff_debcf.dylib`

Keep scripts next to the artifacts, for example `Result/patch_<addr>_deinbr.py`.

## Stage 1: DeinBR

Goal: replace indirect control flow with direct branches.

Procedure:

1. Disassemble the requested function range.
2. Count reachable `br` instructions.
3. Identify target-computing patterns:
   - `csel reg, true_target, false_target, cond; br reg`
   - `cset` or arithmetic-controlled table target
   - target loaded from constant pool or stack slot with symbolic state
4. Use symbolic execution or local emulation to resolve both branch outcomes.
5. Patch only fully resolved `br` sites to direct `b target`.
6. Verify remaining `br` count is zero or explain every remaining site.

## Stage 2: DecFF

Goal: bypass flattened dispatch and recover direct semantic edges.

Procedure:

1. Find dispatcher state storage. Common pattern:

```asm
ldr x9, [x23, #0x1138]
str w8, [x9]
b dispatcher
```

2. Build a mapping from state constants to semantic blocks.
3. For each block tail, recover the state selected by `csel`/constant predicate.
4. Replace `str state; b dispatcher` with `b next_block`.
5. Patch the original entry to branch to the first semantic block.
6. Verify active transition count is zero.

## Stage 3: DeBCF/Deobf

Goal: remove fake branches left after flattening.

Use two proofs:

- Constant predicate proof: local emulation can decide `cmp` flags before `b.cond`.
- Loopback proof: one branch target is a short fake block that writes state and jumps back to the current decision block.

Patch form:

```asm
b.cond junk_or_true
b      other
```

When proven, replace with:

```asm
b      chosen_real_target
nop
```

Do not remove arithmetic noise before the branch unless side effects are proven irrelevant.

## Verification Checklist

- Input and output file sizes match unless intentional.
- Patched address count matches script output.
- Final reachable `br` count is expected.
- Final active CFF transition count is expected.
- Final known BCF predicate count is zero or documented.
- Spot checks show expected `b target; nop` replacements.
