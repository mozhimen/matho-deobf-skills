# Pattern Reference

## Indirect Branch

Suspicious:

```asm
csel x16, x8, x9, eq
br   x16
```

Patch only after both `x8` and `x9` are concrete targets. If the target depends on external memory or a call result, keep it or add a stronger analysis pass.

## CFF Dispatcher

Indicators:

- Many blocks end by writing a state value then branching to the same address.
- The dispatcher compares the state against many constants.
- Semantic blocks are reachable only through the dispatcher.
- Dead dispatcher code may remain after patching; active edges matter more than deleting bytes.

Common state write:

```asm
csel w8, w_true, w_false, cond
ldr  x9, [x23, #0x1138]
str  w8, [x9]
b    dispatcher
```

## Constant Predicate BCF

Indicators:

- Arithmetic uses constants from `adrp/ldr` data slots.
- `cmp` is fully determined locally.
- `b.cond` is immediately followed by `b other_target`.

Safe patch:

```asm
b      proven_target
nop
```

## Loopback Bogus Branch

Indicators:

- A conditional target enters a short block with similar register-immediate noise.
- The block writes a fake dispatcher state.
- The block returns to the current decision block or an equivalent re-check block.
- The paired branch continues to a distinct semantic block.

Example:

```asm
block_A:
  ...
  b.eq junk_B
  b    real_C

junk_B:
  ...
  ldr x8, [x23, #0x1138]
  str w1, [x8]
  b   block_A
```

Patch:

```asm
block_A:
  b real_C
  nop
```

Do not apply this rule to real program loops. Require a state-store marker and a short direct path back.
