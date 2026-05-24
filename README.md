# matho-deobf-skills

Codex skills for ARM64 Mach-O function-level deobfuscation, focused on O-LLVM/Hikari-style protection:

1. **DeinBR**: remove indirect `BR` control flow.
2. **DecFF**: remove control-flow flattening dispatchers.
3. **DeBCF/Deobf**: remove bogus control flow, opaque predicates, and loopback junk branches.

The workflow was extracted from real-world dylib cleanup work and is intentionally conservative: patch only proven control-flow edges, keep unknown business branches intact, and emit a new artifact for every stage.

## Repository Layout

```text
skills/
└── macho-deinbr-decff-deobf/
    ├── SKILL.md
    ├── agents/openai.yaml
    ├── references/
    │   ├── patterns.md
    │   └── workflow.md
    └── scripts/
        ├── arm64_flow.py
        ├── debcf_arm64.py
        └── macho_func_scan.py
```

## Install

Install the skill from this repository:

```bash
python3 ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo <your-github-user>/matho-deinbr-decff-deobf-skills \
  --path skills/macho-deinbr-decff-deobf
```

Or clone the repository and copy the skill folder manually:

```bash
mkdir -p ~/.codex/skills
cp -R skills/macho-deinbr-decff-deobf ~/.codex/skills/
```

Then invoke it in Codex:

```text
Use $macho-deinbr-decff-deobf to deobfuscate libX.dylib at text:0x85b10.
```

## Dependencies

The bundled scripts require Python 3 and Capstone:

```bash
python3 -m pip install capstone
```

For full DeinBR/DecFF work, you may also use external tooling such as `otool`, `llvm-objdump`, Keystone, LIEF, Unicorn, or angr depending on the target. The skill describes the workflow and includes final-stage BCF helpers; it does not force one symbolic execution framework.

## Workflow Summary

### 1. Scan and DeinBR

Read the function range from the user-provided `text:` address to the function end. If reachable code contains indirect `br`/`blr` sites, recover their targets first and patch them to direct branches.

Verification target:

```text
reachable br count == 0
```

### 2. DecFF

Look for a shared dispatcher and state-write patterns such as:

```asm
ldr x9, [x23, #0x1138]
str w8, [x9]
b   dispatcher
```

Recover state-to-block mappings and patch semantic block tails directly to their next blocks. Patch the entry to the first semantic block.

Verification target:

```text
active state-write-to-dispatch transitions == 0
```

### 3. DeBCF/Deobf

Patch two proven BCF forms:

- constant opaque predicates, where local emulation can decide `b.cond`
- loopback junk branches, where one branch target writes fake state and jumps back to the current decision block

Example:

```asm
b.eq junk
b    real
```

becomes:

```asm
b    real
nop
```

## Bundled Script Examples

Scan a function range:

```bash
python3 skills/macho-deinbr-decff-deobf/scripts/macho_func_scan.py \
  libX_deinbr_decff.dylib \
  --start 0x85b10 \
  --end 0x8ad90 \
  --entry 0x89054 \
  --state-base x23 \
  --state-disp 0x1138
```

Patch BCF in a second-stage artifact:

```bash
python3 skills/macho-deinbr-decff-deobf/scripts/debcf_arm64.py \
  libX_deinbr_decff.dylib \
  libX_deinbr_decff_debcf.dylib \
  --start 0x85b10 \
  --end 0x8ad90 \
  --entry 0x89054 \
  --state-base x23 \
  --state-disp 0x1138
```

If VM addresses are not equal to file offsets, provide:

```bash
--file-delta <fileoff_minus_vmaddr>
```

## Safety Notes

- Always write to a new output file.
- Do not patch a branch whose destination is not proven.
- Keep a patch log with every modified address.
- Do not re-sign Mach-O outputs automatically unless explicitly requested.
- Unknown branches depending on parameters, ObjC calls, or mutable memory should remain intact.
