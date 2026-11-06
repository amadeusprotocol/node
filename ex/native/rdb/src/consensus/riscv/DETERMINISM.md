# RISC-V contract VM: determinism rules

Every validator must compute the same outcome, exec units used, storage writes and logs for the same
contract, call and prior state. `vm.rs` implements these rules; the differential fuzzer in the vmbench
repo (`runner/src/fuzz.rs`, compiled against this exact `vm.rs`) checks them against an independent
reference interpreter.

## Loading (`vm::load`, also run at deploy)

- Only the 64-byte ELF header and the program header table are read (no sections, dynamic or symbol data).
  ELF64, little-endian, `e_machine` 243 (RISC-V), `e_phentsize` 56, header table inside the file, at most 512 KiB (`MAX_CONTRACT_SIZE`), at most 16 `PT_LOAD`
  segments, each with its file range inside the file, `filesz <= memsz` and `vaddr + memsz <= 16 MiB`.
- Non-empty `PT_LOAD` segments must not overlap. Exactly one is executable; its base and the entry point are
  4-byte aligned and the entry is inside it.
- Memory size is `round_up(max(vaddr + memsz) + 256 KiB, 4096)`: zeroed, then each segment's file bytes are
  copied to its address (the code segment too, as data). `sp = (memory size - 16) & !15`, other registers 0.

## Instructions

RV64IM plus Zba and Zbb per the ratified specs. Everything else (floating point, atomics, `fence.i`,
`ebreak`, compressed and reserved encodings) is an invalid instruction and traps. Stores into the code
range change data memory only, never the instructions executed.

## Gas

- Costs: loads/stores 2, `mul*` 3, `div*`/`rem*` 10, `jalr` 4, everything else 1, invalid 1.
- A block runs up to and including the next jump, branch, `ecall` or invalid instruction. Its remaining cost is
  charged on entry: at the entry point, after every jump or branch (taken or not) and after a returning `ecall`.
  Entering mid-block via `jalr` pays only the remainder.
- Not enough gas at block entry: out of gas, nothing charged for that block. A trap mid-block keeps the whole
  block's charge. A jump to a misaligned or out-of-code target, and falling off the end, trap at no extra cost.
- Gas maps to exec units at `RISCV_GAS_PER_UNIT` (2) per unit, rounding down, synchronised around every host
  call. Host calls charge exec units directly (`protocol::RISCV_*`, storage and call costs) before doing work.
- Each call also charges `RISCV_CODE_WORD_COST` per code word and `RISCV_PAGE_COST` per memory page up front,
  whether or not the program was cached.

## Outcome

- `exit(0)` or `return`: success. Any other exit code or `abort`: `abort`. Trap: `trap` with the
  trap reason logged. Out of gas: `exec_insufficient_exec_budget`. Every failure reverts through the normal
  transaction machinery; the reason strings are fixed constants.
- Mainnet never executes contracts (`riscv_noop`), and `Contract.deploy` exists on testnet only.

## Conditions

1. All validators run the same node release; any change to these rules is a coordinated fork.
2. 64-bit hosts only (compile-time assert); x86-64 by build policy.
3. Toolchain pinned in `ex/rust-toolchain.toml`; rerun the vmbench `detcheck` digest on every bump.
4. Host resource failures (allocation, storage I/O) abort or halt the node; they never become a contract
   result (`DbFault`). Memory, contract size and segment count are capped, and the interpreter has no recursion.
5. The program cache and the shared memory pool never change results: costs are charged the same whether a
   program or memory buffer is reused, and every call starts from the exact initial image. A buffer last used by
   the same program has every page touched since restored from the image; any other buffer (another program's,
   or a prefaulted spare) is overwritten with the whole image (fuzzed, including memory left by other programs
   and oversized spares).
6. Nothing in the VM reads time, randomness, thread identity or hash-map iteration order.
