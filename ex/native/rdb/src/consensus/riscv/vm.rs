#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
enum K {
    Lui, Jal, Jalr,
    Beq, Bne, Blt, Bge, Bltu, Bgeu,
    Lb, Lh, Lw, Ld, Lbu, Lhu, Lwu,
    Sb, Sh, Sw, Sd,
    Addi, Slti, Sltiu, Xori, Ori, Andi, Slli, Srli, Srai,
    Addiw, Slliw, Srliw, Sraiw,
    Add, Sub, Sll, Slt, Sltu, Xor, Srl, Sra, Or, And,
    Mul, Mulh, Mulhsu, Mulhu, Div, Divu, Rem, Remu,
    Addw, Subw, Sllw, Srlw, Sraw,
    Mulw, Divw, Divuw, Remw, Remuw,
    Fence, Ecall, Invalid,
    AddiAddi, LdLd, SdSd, Li2, Call,
    AddAdd, MulMulhu, LwLw, SwSw, AddiSb, LbuAddi,
    LbuLbu, XorXor, SrliXor, AddiAdd, LdAdd, RoriwRoriw, MulWide,
    AddUw, Sh1add, Sh2add, Sh3add, Sh1addUw, Sh2addUw, Sh3addUw, SlliUw,
    Andn, Orn, Xnor, Clz, Ctz, Cpop, Clzw, Ctzw, Cpopw, Max, Maxu, Min, Minu,
    SextB, SextH, ZextH, Rol, Ror, Rori, Rolw, Rorw, Roriw, OrcB, Rev8,
    AddiBeq, AddiBne, AddiBlt, AddiBge, AddiBltu, AddiBgeu,
}

#[derive(Clone, Copy)]
struct Ins {
    k: K,
    rd: u8,
    rs1: u8,
    rs2: u8,
    t: u32,
    imm: i64,
}

const INVALID: Ins = Ins { k: K::Invalid, rd: 0, rs1: 0, rs2: 0, t: 0, imm: 0 };
const ZERO_SINK: u8 = 32;

fn cost(k: K) -> u64 {
    match k {
        K::Mul | K::Mulh | K::Mulhsu | K::Mulhu | K::Mulw => 3,
        K::Div | K::Divu | K::Rem | K::Remu | K::Divw | K::Divuw | K::Remw | K::Remuw => 10,
        K::Lb | K::Lh | K::Lw | K::Ld | K::Lbu | K::Lhu | K::Lwu | K::Sb | K::Sh | K::Sw | K::Sd => 2,
        K::Jalr => 4,
        _ => 1,
    }
}

fn decode(i: u32, pc: u64) -> Ins {
    let rd = match ((i >> 7) & 31) as u8 { 0 => ZERO_SINK, r => r };
    let rs1 = ((i >> 15) & 31) as u8;
    let rs2 = ((i >> 20) & 31) as u8;
    let f3 = (i >> 12) & 7;
    let f7 = i >> 25;
    let imm_i = ((i as i32) >> 20) as i64;
    let imm_s = ((((i as i32) >> 25) << 5) | (((i >> 7) & 31) as i32)) as i64;
    let imm_b = ((((i as i32) >> 31) << 12) as u32 | ((i >> 25) & 0x3f) << 5 | ((i >> 8) & 0xf) << 1 | ((i >> 7) & 1) << 11) as i32 as i64;
    let imm_u = (i & 0xfffff000) as i32 as i64;
    let imm_j = ((((i as i32) >> 31) << 20) as u32 | ((i >> 21) & 0x3ff) << 1 | ((i >> 20) & 1) << 11 | (i & 0xff000)) as i32 as i64;
    let mk = |k: K, imm: i64| Ins { k, rd, rs1, rs2, t: 0, imm };
    match i & 0x7f {
        0x37 => mk(K::Lui, imm_u),
        0x17 => mk(K::Lui, pc.wrapping_add(imm_u as u64) as i64),
        0x6f => mk(K::Jal, imm_j),
        0x67 if f3 == 0 => mk(K::Jalr, imm_i),
        0x63 => match f3 {
            0 => mk(K::Beq, imm_b), 1 => mk(K::Bne, imm_b), 4 => mk(K::Blt, imm_b),
            5 => mk(K::Bge, imm_b), 6 => mk(K::Bltu, imm_b), 7 => mk(K::Bgeu, imm_b), _ => INVALID,
        },
        0x03 => match f3 {
            0 => mk(K::Lb, imm_i), 1 => mk(K::Lh, imm_i), 2 => mk(K::Lw, imm_i), 3 => mk(K::Ld, imm_i),
            4 => mk(K::Lbu, imm_i), 5 => mk(K::Lhu, imm_i), 6 => mk(K::Lwu, imm_i), _ => INVALID,
        },
        0x23 => match f3 {
            0 => mk(K::Sb, imm_s), 1 => mk(K::Sh, imm_s), 2 => mk(K::Sw, imm_s), 3 => mk(K::Sd, imm_s), _ => INVALID,
        },
        0x13 => match f3 {
            0 => mk(K::Addi, imm_i), 2 => mk(K::Slti, imm_i), 3 => mk(K::Sltiu, imm_i), 4 => mk(K::Xori, imm_i),
            6 => mk(K::Ori, imm_i), 7 => mk(K::Andi, imm_i),
            1 if (i >> 26) == 0 => mk(K::Slli, imm_i & 63),
            5 if (i >> 26) == 0 => mk(K::Srli, imm_i & 63),
            5 if (i >> 26) == 0x10 => mk(K::Srai, imm_i & 63),
            5 if (i >> 26) == 0x18 => mk(K::Rori, imm_i & 63),
            1 => match i >> 20 { 0x600 => mk(K::Clz, 0), 0x601 => mk(K::Ctz, 0), 0x602 => mk(K::Cpop, 0), 0x604 => mk(K::SextB, 0), 0x605 => mk(K::SextH, 0), _ => INVALID },
            5 => match i >> 20 { 0x287 => mk(K::OrcB, 0), 0x6b8 => mk(K::Rev8, 0), _ => INVALID },
            _ => INVALID,
        },
        0x1b => match (f3, f7) {
            (0, _) => mk(K::Addiw, imm_i),
            (1, 0) => mk(K::Slliw, imm_i & 31),
            (5, 0) => mk(K::Srliw, imm_i & 31),
            (5, 0x20) => mk(K::Sraiw, imm_i & 31),
            (1, 0x04 | 0x05) => mk(K::SlliUw, imm_i & 63),
            (1, 0x30) => match rs2 { 0 => mk(K::Clzw, 0), 1 => mk(K::Ctzw, 0), 2 => mk(K::Cpopw, 0), _ => INVALID },
            (5, 0x30) => mk(K::Roriw, imm_i & 31),
            _ => INVALID,
        },
        0x33 => match (f3, f7) {
            (0, 0) => mk(K::Add, 0), (0, 0x20) => mk(K::Sub, 0), (1, 0) => mk(K::Sll, 0), (2, 0) => mk(K::Slt, 0),
            (3, 0) => mk(K::Sltu, 0), (4, 0) => mk(K::Xor, 0), (5, 0) => mk(K::Srl, 0), (5, 0x20) => mk(K::Sra, 0),
            (6, 0) => mk(K::Or, 0), (7, 0) => mk(K::And, 0),
            (0, 1) => mk(K::Mul, 0), (1, 1) => mk(K::Mulh, 0), (2, 1) => mk(K::Mulhsu, 0), (3, 1) => mk(K::Mulhu, 0),
            (4, 1) => mk(K::Div, 0), (5, 1) => mk(K::Divu, 0), (6, 1) => mk(K::Rem, 0), (7, 1) => mk(K::Remu, 0),
            (2, 0x10) => mk(K::Sh1add, 0), (4, 0x10) => mk(K::Sh2add, 0), (6, 0x10) => mk(K::Sh3add, 0),
            (7, 0x20) => mk(K::Andn, 0), (6, 0x20) => mk(K::Orn, 0), (4, 0x20) => mk(K::Xnor, 0),
            (6, 0x05) => mk(K::Max, 0), (7, 0x05) => mk(K::Maxu, 0), (4, 0x05) => mk(K::Min, 0), (5, 0x05) => mk(K::Minu, 0),
            (1, 0x30) => mk(K::Rol, 0), (5, 0x30) => mk(K::Ror, 0),
            _ => INVALID,
        },
        0x3b => match (f3, f7) {
            (0, 0) => mk(K::Addw, 0), (0, 0x20) => mk(K::Subw, 0), (1, 0) => mk(K::Sllw, 0),
            (5, 0) => mk(K::Srlw, 0), (5, 0x20) => mk(K::Sraw, 0),
            (0, 1) => mk(K::Mulw, 0), (4, 1) => mk(K::Divw, 0), (5, 1) => mk(K::Divuw, 0),
            (6, 1) => mk(K::Remw, 0), (7, 1) => mk(K::Remuw, 0),
            (0, 0x04) => mk(K::AddUw, 0),
            (4, 0x04) if rs2 == 0 => mk(K::ZextH, 0),
            (2, 0x10) => mk(K::Sh1addUw, 0), (4, 0x10) => mk(K::Sh2addUw, 0), (6, 0x10) => mk(K::Sh3addUw, 0),
            (1, 0x30) => mk(K::Rolw, 0), (5, 0x30) => mk(K::Rorw, 0),
            _ => INVALID,
        },
        0x0f if f3 == 0 => mk(K::Fence, 0),
        0x73 if i == 0x73 => mk(K::Ecall, 0),
        _ => INVALID,
    }
}

pub struct Program {
    code_base: u64,
    ins: Vec<Ins>,
    costs: Vec<u64>,
    image: Vec<u8>,
    data: Vec<(u64, Vec<u8>)>,
    id: u64,
    entry: usize,
    mem_size: usize,
}

const STACK: u64 = 256 * 1024;
pub const MAX_MEM: u64 = 16 << 20;
pub const MAX_ELF: usize = 4 << 20;
pub const MAX_SEGMENTS: usize = 16;
const _: () = assert!(usize::BITS == 64, "the interpreter requires a 64-bit host");
const _: () = assert!(((MAX_MEM + STACK) >> 12) as usize + 8 < DIRTY_SLOTS);

pub fn load_raw(code_base: u64, entry: u64, code: &[u8], data: Vec<(u64, Vec<u8>)>, top: u64) -> Result<Program, &'static str> {
    build(code_base, entry, code, data, top, true, true)
}

impl Program {
    pub fn code_words(&self) -> usize {
        self.ins.len() - 1
    }

    pub fn pages(&self) -> usize {
        self.mem_size >> 12
    }

    pub fn footprint(&self) -> usize {
        self.ins.len() * 16 + self.costs.len() * 8 + self.image.len() + self.data.iter().map(|(_, d)| d.len()).sum::<usize>()
    }

    pub fn image(&self) -> &[u8] {
        &self.image
    }

    pub fn code_base(&self) -> u64 {
        self.code_base
    }

    #[inline(always)]
    fn addr(&self, idx: usize) -> u64 {
        self.code_base.wrapping_add((idx as u64) << 2)
    }
}

pub fn load(elf: &[u8]) -> Result<Program, &'static str> {
    load_opts(elf, true)
}

pub fn load_opts(elf: &[u8], extra_fusion: bool) -> Result<Program, &'static str> {
    load_opts2(elf, extra_fusion, true)
}

struct Segment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
    exec: bool,
}

fn rd<const N: usize>(b: &[u8], at: usize) -> u64 {
    let mut le = [0u8; 8];
    le[..N].copy_from_slice(&b[at..at + N]);
    u64::from_le_bytes(le)
}

fn load_segments(elf: &[u8]) -> Result<(u64, Vec<Segment>), &'static str> {
    if elf.len() < 64 || &elf[..4] != b"\x7fELF" || rd::<2>(elf, 54) != 56 {
        return Err("riscv_load_elf_parse_failed");
    }
    if elf[4] != 2 || elf[5] != 1 || rd::<2>(elf, 18) != 243 {
        return Err("riscv_load_not_rv64_little_endian_elf");
    }
    let (entry, phoff, phnum) = (rd::<8>(elf, 24), rd::<8>(elf, 32), rd::<2>(elf, 56));
    if phoff.checked_add(56 * phnum).map_or(true, |end| end > elf.len() as u64) {
        return Err("riscv_load_elf_parse_failed");
    }
    let mut segments = Vec::new();
    for k in 0..phnum as usize {
        let h = phoff as usize + 56 * k;
        if rd::<4>(elf, h) != 1 {
            continue;
        }
        if segments.len() == MAX_SEGMENTS {
            return Err("riscv_load_too_many_segments");
        }
        segments.push(Segment { vaddr: rd::<8>(elf, h + 16), offset: rd::<8>(elf, h + 8), filesz: rd::<8>(elf, h + 32), memsz: rd::<8>(elf, h + 40), exec: rd::<4>(elf, h + 4) & 1 == 1 });
    }
    Ok((entry, segments))
}

pub fn load_opts2(elf: &[u8], extra_fusion: bool, more_fusion: bool) -> Result<Program, &'static str> {
    if elf.len() > MAX_ELF {
        return Err("riscv_load_elf_too_large");
    }
    let (entry, segments) = load_segments(elf)?;
    let mut code = None;
    let mut data = Vec::new();
    let mut top = 0u64;
    for ph in &segments {
        let file_end = ph.offset.checked_add(ph.filesz).ok_or("riscv_load_segment_file_range_overflow")?;
        if file_end > elf.len() as u64 || ph.filesz > ph.memsz {
            return Err("riscv_load_segment_file_range_invalid");
        }
        let mem_end = ph.vaddr.checked_add(ph.memsz).ok_or("riscv_load_segment_address_overflow")?;
        if mem_end > MAX_MEM {
            return Err("riscv_load_segment_exceeds_memory_limit");
        }
        top = top.max(mem_end);
        let bytes = &elf[ph.offset as usize..file_end as usize];
        if ph.exec && code.replace((ph.vaddr, bytes)).is_some() {
            return Err("riscv_load_multiple_executable_segments");
        }
        data.push((ph.vaddr, bytes.to_vec()));
    }
    let mut ranges: Vec<(u64, u64)> = segments.iter().filter(|p| p.memsz > 0).map(|p| (p.vaddr, p.vaddr + p.memsz)).collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[1].0 < w[0].1) {
        return Err("riscv_load_overlapping_segments");
    }
    let (code_base, code) = code.ok_or("riscv_load_no_executable_segment")?;
    build(code_base, entry, code, data, top, extra_fusion, more_fusion)
}

fn build(code_base: u64, entry: u64, code: &[u8], data: Vec<(u64, Vec<u8>)>, top: u64, extra_fusion: bool, more_fusion: bool) -> Result<Program, &'static str> {
    if code_base & 3 != 0 {
        return Err("riscv_load_code_misaligned");
    }
    if top > MAX_MEM || code.len() as u64 > MAX_MEM || code_base.checked_add(code.len() as u64).map_or(true, |end| end > top) {
        return Err("riscv_load_code_outside_memory");
    }
    if data.len() > MAX_SEGMENTS || data.iter().map(|(_, d)| d.len() as u64).sum::<u64>() > MAX_MEM {
        return Err("riscv_load_too_much_segment_data");
    }
    if data.iter().any(|(addr, d)| addr.checked_add(d.len() as u64).map_or(true, |end| end > top)) {
        return Err("riscv_load_segment_outside_memory");
    }
    let n = code.len() / 4;
    let target = |addr: u64| -> u32 {
        let off = addr.wrapping_sub(code_base);
        if off & 3 == 0 && off < (n as u64) << 2 { (off >> 2) as u32 } else { n as u32 }
    };
    let entry_off = entry.wrapping_sub(code_base);
    if entry & 3 != 0 || entry_off >= (n as u64) << 2 {
        return Err("riscv_load_entry_outside_code_or_misaligned");
    }
    let mut ins = Vec::with_capacity(n + 1);
    for (idx, w) in code.chunks_exact(4).enumerate() {
        let pc = code_base + ((idx as u64) << 2);
        let mut d = decode(u32::from_le_bytes([w[0], w[1], w[2], w[3]]), pc);
        if matches!(d.k, K::Jal | K::Beq | K::Bne | K::Blt | K::Bge | K::Bltu | K::Bgeu) {
            d.t = target(pc.wrapping_add(d.imm as u64));
        }
        ins.push(d);
    }
    ins.push(INVALID);
    let mut costs = vec![0u64; n + 1];
    costs[n] = 0;
    for j in (0..n).rev() {
        let k = ins[j].k;
        let ends = matches!(k, K::Jal | K::Jalr | K::Beq | K::Bne | K::Blt | K::Bge | K::Bltu | K::Bgeu | K::Ecall | K::Invalid);
        costs[j] = cost(k) + if ends { 0 } else { costs[j + 1] };
    }
    fuse(&mut ins, code_base, extra_fusion, more_fusion);
    let mem_size = ((top + STACK + 0xfff) & !0xfff) as usize;
    let mut image = vec![0u8; mem_size];
    for (addr, d) in &data {
        image[*addr as usize..*addr as usize + d.len()].copy_from_slice(d);
    }
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT_ID
        .fetch_update(std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed, |id| id.checked_add(1))
        .unwrap_or_else(|_| panic!("program id space exhausted"));
    Ok(Program { code_base, ins, costs, image, data, id, entry: (entry_off >> 2) as usize, mem_size })
}

fn pack2(rd: u8, rs: u8, imm: i64) -> u32 {
    rd as u32 | (rs as u32) << 8 | (imm as i16 as u16 as u32) << 16
}

fn fuse(ins: &mut [Ins], code_base: u64, extra: bool, more: bool) {
    let n = ins.len() - 1;
    let orig = ins.to_vec();
    for j in 0..n.saturating_sub(1) {
        let (a, b) = (orig[j], orig[j + 1]);
        let addi_br = |k: K| match k {
            K::Beq => Some(K::AddiBeq), K::Bne => Some(K::AddiBne), K::Blt => Some(K::AddiBlt),
            K::Bge => Some(K::AddiBge), K::Bltu => Some(K::AddiBltu), K::Bgeu => Some(K::AddiBgeu), _ => None,
        };
        let pack3 = |x: Ins| x.rd as u32 | (x.rs1 as u32) << 8 | (x.rs2 as u32) << 16;
        let same_ops = (b.rs1 == a.rs1 && b.rs2 == a.rs2) || (b.rs1 == a.rs2 && b.rs2 == a.rs1);
        let clobbers = a.rd == a.rs1 || a.rd == a.rs2;
        ins[j] = match (a.k, b.k) {
            (K::Mul, K::Mulhu) if more && same_ops && !clobbers => Ins { k: K::MulWide, t: b.rd as u32, ..a },
            (K::Lbu, K::Lbu) if more => Ins { k: K::LbuLbu, t: pack2(b.rd, b.rs1, b.imm), ..a },
            (K::Xor, K::Xor) if more => Ins { k: K::XorXor, t: pack3(b), ..a },
            (K::Srli, K::Xor) if more => Ins { k: K::SrliXor, t: pack3(b), ..a },
            (K::Addi, K::Add) if more => Ins { k: K::AddiAdd, t: pack3(b), ..a },
            (K::Ld, K::Add) if more => Ins { k: K::LdAdd, t: pack3(b), ..a },
            (K::Roriw, K::Roriw) if more => Ins { k: K::RoriwRoriw, t: pack2(b.rd, b.rs1, b.imm), ..a },
            (K::Add, K::Add) if extra => Ins { k: K::AddAdd, t: pack3(b), ..a },
            (K::Mul, K::Mulhu) if extra => Ins { k: K::MulMulhu, t: pack3(b), ..a },
            (K::Lw, K::Lw) if extra => Ins { k: K::LwLw, t: pack2(b.rd, b.rs1, b.imm), ..a },
            (K::Sw, K::Sw) if extra => Ins { k: K::SwSw, t: pack2(b.rs2, b.rs1, b.imm), ..a },
            (K::Addi, K::Sb) if extra => Ins { k: K::AddiSb, t: pack2(b.rs2, b.rs1, b.imm), ..a },
            (K::Lbu, K::Addi) if extra => Ins { k: K::LbuAddi, t: pack2(b.rd, b.rs1, b.imm), ..a },
            (K::Addi, K::Addi) => Ins { k: K::AddiAddi, t: pack2(b.rd, b.rs1, b.imm), ..a },
            (K::Ld, K::Ld) => Ins { k: K::LdLd, t: pack2(b.rd, b.rs1, b.imm), ..a },
            (K::Sd, K::Sd) => Ins { k: K::SdSd, t: pack2(b.rs2, b.rs1, b.imm), ..a },
            (K::Lui, K::Addi) if b.rd == a.rd && b.rs1 == a.rd => Ins { k: K::Li2, imm: (a.imm as u64).wrapping_add(b.imm as u64) as i64, ..a },
            (K::Lui, K::Jalr) if b.rs1 == a.rd => {
                let off = ((a.imm as u64).wrapping_add(b.imm as u64) & !1).wrapping_sub(code_base);
                if off & 3 != 0 || off >= (n as u64) << 2 {
                    continue;
                }
                Ins { k: K::Call, rd: a.rd, rs1: 0, rs2: b.rd, t: (off >> 2) as u32, imm: a.imm }
            }
            (K::Addi, bk) => match addi_br(bk) {
                Some(k) => Ins { k, rd: a.rd, rs1: a.rs1, rs2: b.rs1, t: b.t, imm: (a.imm as i32 as u32 as u64 | (b.rs2 as u64) << 32) as i64 },
                None => continue,
            },
            _ => continue,
        };
    }
}

pub enum Exit {
    Done(u64),
    OutOfGas,
    Trap(&'static str),
}

pub enum Ecall {
    Continue,
    Done(u64),
    OutOfGas,
    Trap(&'static str),
}

const DIRTY_SLOTS: usize = 8192;

pub struct Memory {
    prog: u64,
    buf: Vec<u8>,
    dirty: Box<[u8; DIRTY_SLOTS]>,
}

impl Memory {
    pub fn blank(size: usize) -> Memory {
        let mut buf = Vec::with_capacity(size);
        buf.resize(size, 0);
        Memory { prog: 0, buf, dirty: Box::new([0; DIRTY_SLOTS]) }
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    pub fn bytes(&self) -> usize {
        self.buf.capacity() + DIRTY_SLOTS
    }
}

pub struct Machine<'p> {
    p: &'p Program,
    mem: Vec<u8>,
    dirty: Box<[u8; DIRTY_SLOTS]>,
    pub regs: [u64; 256],
    pub gas: u64,
    pub hits: Vec<u64>,
    pub trans: std::collections::HashMap<(u32, u32), u64>,
}

impl<'p> Machine<'p> {
    pub fn new(p: &'p Program, gas: u64) -> Machine<'p> {
        let mut mem = vec![0u8; p.mem_size];
        for (addr, d) in &p.data {
            mem[*addr as usize..*addr as usize + d.len()].copy_from_slice(d);
        }
        Self::init(p, gas, mem, Box::new([0; DIRTY_SLOTS]))
    }

    pub fn reuse(p: &'p Program, gas: u64, prev: Option<Memory>) -> Machine<'p> {
        Self::reuse_opts(p, gas, prev, true)
    }

    pub fn reuse_opts(p: &'p Program, gas: u64, prev: Option<Memory>, word_scan: bool) -> Machine<'p> {
        let pages = p.mem_size >> 12;
        match prev {
            Some(Memory { prog, mut buf, mut dirty }) if prog == p.id && buf.len() == p.mem_size => {
                if word_scan {
                    for (c, chunk) in dirty[..pages.next_multiple_of(8)].chunks_exact_mut(8).enumerate() {
                        if u64::from_ne_bytes((&*chunk).try_into().unwrap()) == 0 {
                            continue;
                        }
                        for (j, flag) in chunk.iter_mut().enumerate() {
                            if std::mem::take(flag) != 0 {
                                let r = (c * 8 + j) << 12;
                                buf[r..r + 4096].copy_from_slice(&p.image[r..r + 4096]);
                            }
                        }
                    }
                } else {
                    for pg in 0..pages {
                        if std::mem::take(&mut dirty[pg]) != 0 {
                            let r = pg << 12;
                            buf[r..r + 4096].copy_from_slice(&p.image[r..r + 4096]);
                        }
                    }
                }
                Self::init(p, gas, buf, dirty)
            }
            Some(Memory { mut buf, mut dirty, .. }) if buf.capacity() >= p.mem_size => {
                buf.clear();
                buf.extend_from_slice(&p.image);
                dirty.fill(0);
                Self::init(p, gas, buf, dirty)
            }
            _ => Self::init(p, gas, p.image.clone(), Box::new([0; DIRTY_SLOTS])),
        }
    }

    fn init(p: &'p Program, gas: u64, mem: Vec<u8>, dirty: Box<[u8; DIRTY_SLOTS]>) -> Machine<'p> {
        let mut regs = [0u64; 256];
        regs[2] = (p.mem_size as u64 - 16) & !15;
        Machine { p, mem, dirty, regs, gas, hits: Vec::new(), trans: Default::default() }
    }

    pub fn memory(&self) -> &[u8] {
        &self.mem
    }

    pub fn into_memory(self) -> Memory {
        Memory { prog: self.p.id, buf: self.mem, dirty: self.dirty }
    }

    #[inline(always)]
    fn mark(&mut self, start: usize, end: usize) {
        for pg in start >> 12..=(end - 1) >> 12 {
            self.dirty[pg & (DIRTY_SLOTS - 1)] = 1;
        }
    }

    pub fn charge(&mut self, n: u64) -> bool {
        if self.gas < n {
            return false;
        }
        self.gas -= n;
        true
    }

    #[inline(always)]
    fn range(&self, addr: u64, len: u64) -> Option<std::ops::Range<usize>> {
        let end = addr.checked_add(len)?;
        if end > self.mem.len() as u64 {
            return None;
        }
        Some(addr as usize..end as usize)
    }
    pub fn mem(&self, addr: u64, len: u64) -> Option<&[u8]> {
        let r = self.range(addr, len)?;
        Some(&self.mem[r])
    }
    pub fn mem_mut(&mut self, addr: u64, len: u64) -> Option<&mut [u8]> {
        let r = self.range(addr, len)?;
        if len > 0 {
            self.mark(r.start, r.end);
        }
        Some(&mut self.mem[r])
    }

    #[inline(always)]
    fn ld<const N: usize>(&self, addr: u64) -> Option<u64> {
        let r = self.range(addr, N as u64)?;
        let mut b = [0u8; 8];
        b[..N].copy_from_slice(&self.mem[r]);
        Some(u64::from_le_bytes(b))
    }
    #[inline(always)]
    fn st<const N: usize>(&mut self, addr: u64, v: u64) -> bool {
        let Some(r) = self.range(addr, N as u64) else { return false };
        self.dirty[(r.start >> 12) & (DIRTY_SLOTS - 1)] = 1;
        self.dirty[((r.end - 1) >> 12) & (DIRTY_SLOTS - 1)] = 1;
        self.mem[r].copy_from_slice(&v.to_le_bytes()[..N]);
        true
    }

    pub fn run(&mut self, ecall: &mut dyn FnMut(&mut Machine<'p>) -> Ecall) -> Exit {
        self.run_inner::<false>(ecall)
    }

    pub fn run_profiled(&mut self, ecall: &mut dyn FnMut(&mut Machine<'p>) -> Ecall) -> Exit {
        self.hits = vec![0; self.p.ins.len()];
        self.run_inner::<true>(ecall)
    }

    fn run_inner<const PROF: bool>(&mut self, ecall: &mut dyn FnMut(&mut Machine<'p>) -> Ecall) -> Exit {
        let p = self.p;
        let prog: &[Ins] = &p.ins;
        let costs: &[u64] = &p.costs;
        let code_len = ((prog.len() - 1) as u64) << 2;
        let mut i = p.entry;
        let mut prev = u32::MAX;
        macro_rules! enter {
            ($j:expr) => {{
                let c = costs[$j];
                if self.gas < c {
                    return Exit::OutOfGas;
                }
                self.gas -= c;
            }};
        }
        enter!(i);
        macro_rules! step {
            () => {{
            if PROF { self.hits[i] += 1; *self.trans.entry((prev, i as u32)).or_default() += 1; prev = i as u32; }
            let ins = prog[i];
            let (a, b) = (self.regs[ins.rs1 as usize], self.regs[ins.rs2 as usize]);
            let imm = ins.imm as u64;
            let rd = ins.rd as usize;
            let mut next = i + 1;
            macro_rules! load {
                ($n:literal, $ext:ty) => {{
                    let Some(x) = self.ld::<$n>(a.wrapping_add(imm)) else { return Exit::Trap("riscv_trap_load_out_of_bounds") };
                    self.regs[rd] = x as $ext as i64 as u64;
                }};
            }
            macro_rules! store {
                ($n:literal) => {
                    if !self.st::<$n>(a.wrapping_add(imm), b) {
                        return Exit::Trap("riscv_trap_store_out_of_bounds");
                    }
                };
            }
            macro_rules! second {
                () => {
                    ((ins.t & 0xff) as usize, ((ins.t >> 8) & 0xff) as usize, (ins.t >> 16) as u16 as i16 as i64 as u64)
                };
            }
            macro_rules! third {
                () => {
                    ((ins.t & 0xff) as usize, ((ins.t >> 8) & 0xff) as usize, ((ins.t >> 16) & 0xff) as usize)
                };
            }
            macro_rules! addi_br {
                ($c:expr) => {{
                    self.regs[rd] = a.wrapping_add(ins.imm as i32 as i64 as u64);
                    let (x, y) = (self.regs[ins.rs2 as usize], self.regs[(imm >> 32) as u8 as usize]);
                    next = if $c(x, y) { ins.t as usize } else { i + 2 };
                    enter!(next);
                }};
            }
            let r = &mut self.regs;
            macro_rules! w {
                ($v:expr) => { r[rd] = $v };
            }
            match ins.k {
                K::Lui => w!(imm),
                K::Jal => { w!(p.addr(next)); next = ins.t as usize; enter!(next); }
                K::Jalr => {
                    let off = (a.wrapping_add(imm) & !1).wrapping_sub(p.code_base);
                    if off & 3 != 0 || off >= code_len {
                        return Exit::Trap("riscv_trap_jump_outside_code_or_misaligned");
                    }
                    w!(p.addr(next));
                    next = (off >> 2) as usize;
                    enter!(next);
                }
                K::Beq => { if a == b { next = ins.t as usize } enter!(next); }
                K::Bne => { if a != b { next = ins.t as usize } enter!(next); }
                K::Blt => { if (a as i64) < (b as i64) { next = ins.t as usize } enter!(next); }
                K::Bge => { if (a as i64) >= (b as i64) { next = ins.t as usize } enter!(next); }
                K::Bltu => { if a < b { next = ins.t as usize } enter!(next); }
                K::Bgeu => { if a >= b { next = ins.t as usize } enter!(next); }
                K::Lb => load!(1, i8),
                K::Lh => load!(2, i16),
                K::Lw => load!(4, i32),
                K::Ld => load!(8, i64),
                K::Lbu => load!(1, u8),
                K::Lhu => load!(2, u16),
                K::Lwu => load!(4, u32),
                K::Sb => store!(1),
                K::Sh => store!(2),
                K::Sw => store!(4),
                K::Sd => store!(8),
                K::Addi => w!(a.wrapping_add(imm)),
                K::Slti => w!(((a as i64) < ins.imm) as u64),
                K::Sltiu => w!((a < imm) as u64),
                K::Xori => w!(a ^ imm),
                K::Ori => w!(a | imm),
                K::Andi => w!(a & imm),
                K::Slli => w!(a << imm),
                K::Srli => w!(a >> imm),
                K::Srai => w!(((a as i64) >> imm) as u64),
                K::Addiw => w!((a as u32).wrapping_add(imm as u32) as i32 as i64 as u64),
                K::Slliw => w!(((a as u32) << imm) as i32 as i64 as u64),
                K::Srliw => w!(((a as u32) >> imm) as i32 as i64 as u64),
                K::Sraiw => w!(((a as i32) >> imm) as i64 as u64),
                K::Add => w!(a.wrapping_add(b)),
                K::Sub => w!(a.wrapping_sub(b)),
                K::Sll => w!(a << (b & 63)),
                K::Slt => w!(((a as i64) < (b as i64)) as u64),
                K::Sltu => w!((a < b) as u64),
                K::Xor => w!(a ^ b),
                K::Srl => w!(a >> (b & 63)),
                K::Sra => w!(((a as i64) >> (b & 63)) as u64),
                K::Or => w!(a | b),
                K::And => w!(a & b),
                K::Mul => w!(a.wrapping_mul(b)),
                K::Mulh => w!((((a as i64 as i128) * (b as i64 as i128)) >> 64) as u64),
                K::Mulhsu => w!((((a as i64 as i128) * (b as u128 as i128)) >> 64) as u64),
                K::Mulhu => w!((((a as u128) * (b as u128)) >> 64) as u64),
                K::Div => w!(if b == 0 { u64::MAX } else { (a as i64).wrapping_div(b as i64) as u64 }),
                K::Divu => w!(if b == 0 { u64::MAX } else { a / b }),
                K::Rem => w!(if b == 0 { a } else { (a as i64).wrapping_rem(b as i64) as u64 }),
                K::Remu => w!(if b == 0 { a } else { a % b }),
                K::Addw => w!((a as u32).wrapping_add(b as u32) as i32 as i64 as u64),
                K::Subw => w!((a as u32).wrapping_sub(b as u32) as i32 as i64 as u64),
                K::Sllw => w!(((a as u32) << (b & 31)) as i32 as i64 as u64),
                K::Srlw => w!(((a as u32) >> (b & 31)) as i32 as i64 as u64),
                K::Sraw => w!(((a as i32) >> (b & 31)) as i64 as u64),
                K::Mulw => w!((a as u32).wrapping_mul(b as u32) as i32 as i64 as u64),
                K::Divw => w!(if b as u32 == 0 { u64::MAX } else { (a as i32).wrapping_div(b as i32) as i64 as u64 }),
                K::Divuw => w!(if b as u32 == 0 { u64::MAX } else { ((a as u32) / (b as u32)) as i32 as i64 as u64 }),
                K::Remw => w!(if b as u32 == 0 { a as i32 as i64 as u64 } else { (a as i32).wrapping_rem(b as i32) as i64 as u64 }),
                K::Remuw => w!(if b as u32 == 0 { a as i32 as i64 as u64 } else { ((a as u32) % (b as u32)) as i32 as i64 as u64 }),
                K::Fence => {}
                K::Ecall => match ecall(self) {
                    Ecall::Continue => enter!(next),
                    Ecall::Done(code) => return Exit::Done(code),
                    Ecall::OutOfGas => return Exit::OutOfGas,
                    Ecall::Trap(t) => return Exit::Trap(t),
                },
                K::Invalid => return Exit::Trap("riscv_trap_invalid_instruction"),
                K::AddUw => w!(b.wrapping_add(a as u32 as u64)),
                K::Sh1add => w!(b.wrapping_add(a << 1)),
                K::Sh2add => w!(b.wrapping_add(a << 2)),
                K::Sh3add => w!(b.wrapping_add(a << 3)),
                K::Sh1addUw => w!(b.wrapping_add((a as u32 as u64) << 1)),
                K::Sh2addUw => w!(b.wrapping_add((a as u32 as u64) << 2)),
                K::Sh3addUw => w!(b.wrapping_add((a as u32 as u64) << 3)),
                K::SlliUw => w!((a as u32 as u64) << imm),
                K::Andn => w!(a & !b),
                K::Orn => w!(a | !b),
                K::Xnor => w!(!(a ^ b)),
                K::Clz => w!(a.leading_zeros() as u64),
                K::Ctz => w!(a.trailing_zeros() as u64),
                K::Cpop => w!(a.count_ones() as u64),
                K::Clzw => w!((a as u32).leading_zeros() as u64),
                K::Ctzw => w!((a as u32).trailing_zeros() as u64),
                K::Cpopw => w!((a as u32).count_ones() as u64),
                K::Max => w!((a as i64).max(b as i64) as u64),
                K::Maxu => w!(a.max(b)),
                K::Min => w!((a as i64).min(b as i64) as u64),
                K::Minu => w!(a.min(b)),
                K::SextB => w!(a as i8 as i64 as u64),
                K::SextH => w!(a as i16 as i64 as u64),
                K::ZextH => w!(a as u16 as u64),
                K::Rol => w!(a.rotate_left((b & 63) as u32)),
                K::Ror => w!(a.rotate_right((b & 63) as u32)),
                K::Rori => w!(a.rotate_right(imm as u32)),
                K::Rolw => w!((a as u32).rotate_left((b & 31) as u32) as i32 as i64 as u64),
                K::Rorw => w!((a as u32).rotate_right((b & 31) as u32) as i32 as i64 as u64),
                K::Roriw => w!((a as u32).rotate_right(imm as u32) as i32 as i64 as u64),
                K::OrcB => w!(u64::from_le_bytes(a.to_le_bytes().map(|x| if x != 0 { 0xff } else { 0 }))),
                K::Rev8 => w!(a.swap_bytes()),
                K::AddiAddi => {
                    let (rd2, rs2nd, imm2) = second!();
                    r[rd] = a.wrapping_add(imm);
                    r[rd2] = r[rs2nd].wrapping_add(imm2);
                    next = i + 2;
                }
                K::Li2 => { r[rd] = imm; next = i + 2; }
                K::AddAdd => {
                    r[rd] = a.wrapping_add(b);
                    let (d2, s1, s2) = third!();
                    r[d2] = r[s1].wrapping_add(r[s2]);
                    next = i + 2;
                }
                K::MulMulhu => {
                    r[rd] = a.wrapping_mul(b);
                    let (d2, s1, s2) = third!();
                    r[d2] = (((r[s1] as u128) * (r[s2] as u128)) >> 64) as u64;
                    next = i + 2;
                }
                K::LwLw => {
                    let (rd2, rs2nd, imm2) = second!();
                    load!(4, i32);
                    let Some(x) = self.ld::<4>(self.regs[rs2nd].wrapping_add(imm2)) else { return Exit::Trap("riscv_trap_load_out_of_bounds") };
                    self.regs[rd2] = x as i32 as i64 as u64;
                    next = i + 2;
                }
                K::SwSw => {
                    let (rd2, rs2nd, imm2) = second!();
                    store!(4);
                    if !self.st::<4>(self.regs[rs2nd].wrapping_add(imm2), self.regs[rd2]) {
                        return Exit::Trap("riscv_trap_store_out_of_bounds");
                    }
                    next = i + 2;
                }
                K::AddiSb => {
                    let (rd2, rs2nd, imm2) = second!();
                    self.regs[rd] = a.wrapping_add(imm);
                    if !self.st::<1>(self.regs[rs2nd].wrapping_add(imm2), self.regs[rd2]) {
                        return Exit::Trap("riscv_trap_store_out_of_bounds");
                    }
                    next = i + 2;
                }
                K::MulWide => {
                    let w = (a as u128) * (b as u128);
                    r[rd] = w as u64;
                    r[(ins.t & 0xff) as usize] = (w >> 64) as u64;
                    next = i + 2;
                }
                K::XorXor => {
                    r[rd] = a ^ b;
                    let (d2, s1, s2) = third!();
                    r[d2] = r[s1] ^ r[s2];
                    next = i + 2;
                }
                K::SrliXor => {
                    r[rd] = a >> imm;
                    let (d2, s1, s2) = third!();
                    r[d2] = r[s1] ^ r[s2];
                    next = i + 2;
                }
                K::AddiAdd => {
                    r[rd] = a.wrapping_add(imm);
                    let (d2, s1, s2) = third!();
                    r[d2] = r[s1].wrapping_add(r[s2]);
                    next = i + 2;
                }
                K::RoriwRoriw => {
                    let (rd2, rs2nd, imm2) = second!();
                    r[rd] = (a as u32).rotate_right(imm as u32) as i32 as i64 as u64;
                    r[rd2] = (r[rs2nd] as u32).rotate_right(imm2 as u32) as i32 as i64 as u64;
                    next = i + 2;
                }
                K::LdAdd => {
                    load!(8, i64);
                    let (d2, s1, s2) = third!();
                    self.regs[d2] = self.regs[s1].wrapping_add(self.regs[s2]);
                    next = i + 2;
                }
                K::LbuLbu => {
                    let (rd2, rs2nd, imm2) = second!();
                    load!(1, u8);
                    let Some(x) = self.ld::<1>(self.regs[rs2nd].wrapping_add(imm2)) else { return Exit::Trap("riscv_trap_load_out_of_bounds") };
                    self.regs[rd2] = x;
                    next = i + 2;
                }
                K::LbuAddi => {
                    let (rd2, rs2nd, imm2) = second!();
                    load!(1, u8);
                    self.regs[rd2] = self.regs[rs2nd].wrapping_add(imm2);
                    next = i + 2;
                }
                K::LdLd => {
                    let (rd2, rs2nd, imm2) = second!();
                    load!(8, i64);
                    let Some(x) = self.ld::<8>(self.regs[rs2nd].wrapping_add(imm2)) else { return Exit::Trap("riscv_trap_load_out_of_bounds") };
                    self.regs[rd2] = x;
                    next = i + 2;
                }
                K::SdSd => {
                    let (rd2, rs2nd, imm2) = second!();
                    store!(8);
                    if !self.st::<8>(self.regs[rs2nd].wrapping_add(imm2), self.regs[rd2]) {
                        return Exit::Trap("riscv_trap_store_out_of_bounds");
                    }
                    next = i + 2;
                }
                K::Call => {
                    r[rd] = imm;
                    r[ins.rs2 as usize] = p.addr(i + 2);
                    next = ins.t as usize;
                    enter!(next);
                }
                K::AddiBeq => addi_br!(|x: u64, y: u64| x == y),
                K::AddiBne => addi_br!(|x: u64, y: u64| x != y),
                K::AddiBlt => addi_br!(|x: u64, y: u64| (x as i64) < (y as i64)),
                K::AddiBge => addi_br!(|x: u64, y: u64| (x as i64) >= (y as i64)),
                K::AddiBltu => addi_br!(|x: u64, y: u64| x < y),
                K::AddiBgeu => addi_br!(|x: u64, y: u64| x >= y),
            }
            i = next;
            }};
        }
        loop {
            step!();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const BASE: u64 = 0x1000;

    fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
        rs2 << 20 | rs1 << 15 | rd << 7 | 0x33
    }
    pub(crate) fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        (imm as u32) << 20 | rs1 << 15 | rd << 7 | 0x13
    }
    pub(crate) fn lui(rd: u32, imm20: u32) -> u32 {
        imm20 << 12 | rd << 7 | 0x37
    }
    fn auipc(rd: u32, imm20: u32) -> u32 {
        imm20 << 12 | rd << 7 | 0x17
    }
    fn jalr(rd: u32, rs1: u32, imm: i32) -> u32 {
        (imm as u32) << 20 | rs1 << 15 | rd << 7 | 0x67
    }
    fn jal(rd: u32, imm: i32) -> u32 {
        let i = imm as u32;
        (i >> 20 & 1) << 31 | (i >> 1 & 0x3ff) << 21 | (i >> 11 & 1) << 20 | (i >> 12 & 0xff) << 12 | rd << 7 | 0x6f
    }
    fn beq(rs1: u32, rs2: u32, imm: i32) -> u32 {
        let i = imm as u32;
        (i >> 12 & 1) << 31 | (i >> 5 & 0x3f) << 25 | rs2 << 20 | rs1 << 15 | (i >> 1 & 0xf) << 8 | (i >> 11 & 1) << 7 | 0x63
    }
    fn sw(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let i = imm as u32;
        (i >> 5 & 0x7f) << 25 | rs2 << 20 | rs1 << 15 | 2 << 12 | (i & 31) << 7 | 0x23
    }
    fn lw(rd: u32, rs1: u32, imm: i32) -> u32 {
        (imm as u32) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03
    }
    pub(crate) const ECALL: u32 = 0x73;

    pub(crate) fn prog(words: &[u32]) -> Program {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let top = BASE + code.len() as u64;
        build(BASE, BASE, &code, vec![(BASE, code.clone())], top, true, true).unwrap()
    }

    fn exec(words: &[u32], gas: u64) -> Result<u64, &'static str> {
        let p = prog(words);
        let mut m = Machine::new(&p, gas);
        match m.run(&mut |m: &mut Machine| Ecall::Done(m.regs[10])) {
            Exit::Done(v) => Ok(v),
            Exit::OutOfGas => Err("oog"),
            Exit::Trap(t) => Err(t),
        }
    }

    const BAD_JUMP: Result<u64, &str> = Err("riscv_trap_jump_outside_code_or_misaligned");
    const INVALID_INS: Result<u64, &str> = Err("riscv_trap_invalid_instruction");

    #[test]
    fn x0_stays_zero() {
        assert_eq!(exec(&[addi(0, 0, 5), addi(10, 0, 0), add(10, 10, 0), ECALL], 100), Ok(0));
    }

    #[test]
    fn auipc_and_links_use_real_addresses() {
        assert_eq!(exec(&[addi(0, 0, 0), auipc(10, 1), ECALL], 100), Ok(BASE + 4 + 0x1000));
        assert_eq!(exec(&[jal(10, 8), addi(10, 0, 9), ECALL], 100), Ok(BASE + 4));
        assert_eq!(exec(&[lui(5, 1), addi(5, 5, 16), jalr(10, 5, 0), addi(10, 0, 9), ECALL], 100), Ok(BASE + 12));
    }

    #[test]
    fn jalr_rejects_bad_targets() {
        assert_eq!(exec(&[lui(5, 1), addi(5, 5, 6), jalr(0, 5, 0), ECALL], 100), BAD_JUMP);
        assert_eq!(exec(&[lui(5, 1), addi(5, 5, 16), jalr(0, 5, 0), ECALL], 100), BAD_JUMP);
        assert_eq!(exec(&[addi(5, 0, 0), jalr(0, 5, 0), ECALL], 100), BAD_JUMP);
        assert_eq!(exec(&[lui(5, 1), addi(5, 5, 13), jalr(0, 5, 0), ECALL], 100), Ok(0));
    }

    #[test]
    fn bad_static_targets_trap_only_when_taken() {
        assert_eq!(exec(&[addi(5, 0, 1), beq(5, 0, 0x400), addi(10, 0, 7), ECALL], 100), Ok(7));
        assert_eq!(exec(&[beq(0, 0, 0x400), ECALL], 100), INVALID_INS);
        assert_eq!(exec(&[beq(0, 0, 6), ECALL, ECALL], 100), INVALID_INS);
        assert_eq!(exec(&[jal(0, -8), ECALL], 100), INVALID_INS);
    }

    #[test]
    fn falling_off_the_end_traps() {
        assert_eq!(exec(&[addi(10, 0, 1)], 100), INVALID_INS);
    }

    #[test]
    fn stores_into_code_do_not_change_execution() {
        let code = [lui(5, 1), lui(6, 0x00a00), addi(6, 6, 0x513), sw(6, 5, 20), addi(10, 0, 3), ECALL];
        assert_eq!(exec(&code, 100), Ok(3));
        let code = [lui(5, 1), addi(6, 0, 0x55), sw(6, 5, 0), lw(10, 5, 0), ECALL];
        assert_eq!(exec(&code, 100), Ok(0x55));
    }

    #[test]
    fn memory_bounds() {
        assert_eq!(exec(&[addi(5, 0, -1), lw(10, 5, 0), ECALL], 100), Err("riscv_trap_load_out_of_bounds"));
        assert_eq!(exec(&[addi(5, 0, -4), sw(0, 5, 0), ECALL], 100), Err("riscv_trap_store_out_of_bounds"));
        let p = prog(&[ECALL]);
        let m = Machine::new(&p, 0);
        assert!(m.mem(u64::MAX - 1, 4).is_none());
        assert!(m.mem(p.mem_size as u64 - 4, 4).is_some());
        assert!(m.mem(p.mem_size as u64 - 3, 4).is_none());
    }

    #[test]
    fn reserved_encodings_trap() {
        assert_eq!(exec(&[0x0000100f, ECALL], 100), INVALID_INS);
        assert_eq!(exec(&[0x0000200f, ECALL], 100), INVALID_INS);
        assert_eq!(exec(&[0x0ff0000f, ECALL], 100), Ok(0));
        assert_eq!(exec(&[0x00100073], 100), INVALID_INS);
    }

    #[test]
    fn gas_is_exact() {
        let code = [addi(10, 0, 1), lw(11, 2, 0), ECALL];
        assert_eq!(exec(&code, 4), Ok(1));
        assert_eq!(exec(&code, 3), Err("oog"));
        let p = prog(&[beq(0, 0, 0)]);
        let mut m = Machine::new(&p, 1000);
        assert!(matches!(m.run(&mut |_: &mut Machine| Ecall::Continue), Exit::OutOfGas));
        assert_eq!(m.gas, 0);
    }

    #[test]
    fn block_gas_matches_executed_instructions() {
        let bne = |rs1: u32, rs2: u32, imm: i32| beq(rs1, rs2, imm) | 1 << 12;
        let code = [addi(5, 0, 3), addi(5, 5, -1), bne(5, 0, -4), addi(10, 0, 0), ECALL];
        assert_eq!(exec(&code, 9), Ok(0));
        assert_eq!(exec(&code, 8), Err("oog"));
        let code = [lui(5, 1), addi(5, 5, 16), jalr(0, 5, 0), addi(10, 0, 9), addi(10, 10, 1), ECALL];
        assert_eq!(exec(&code, 8), Ok(1));
        assert_eq!(exec(&code, 7), Err("oog"));
    }

    #[test]
    fn host_call_ends_a_block() {
        let p = prog(&[addi(10, 0, 1), ECALL, addi(10, 0, 2), ECALL]);
        let mut m = Machine::new(&p, 100);
        let mut calls = vec![];
        let exit = m.run(&mut |m: &mut Machine| {
            calls.push(m.gas);
            if m.regs[10] == 2 { Ecall::Done(2) } else { Ecall::Continue }
        });
        assert!(matches!(exit, Exit::Done(2)));
        assert_eq!(calls, vec![98, 96]);
    }

    fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
        (imm as u32) << 20 | rs1 << 15 | 3 << 12 | rd << 7 | 0x03
    }
    fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let i = imm as u32;
        (i >> 5 & 0x7f) << 25 | rs2 << 20 | rs1 << 15 | 3 << 12 | (i & 31) << 7 | 0x23
    }

    fn kinds(words: &[u32]) -> Vec<K> {
        prog(words).ins.iter().map(|i| i.k).collect()
    }

    #[test]
    fn fused_pairs_keep_semantics() {
        assert_eq!(kinds(&[addi(5, 0, 1), addi(10, 5, 2), ECALL])[0], K::AddiAddi);
        assert_eq!(exec(&[addi(5, 0, 1), addi(10, 5, 2), ECALL], 100), Ok(3));
        assert_eq!(exec(&[addi(0, 0, 7), addi(10, 0, 2), ECALL], 100), Ok(2));
        assert_eq!(exec(&[lui(10, 1), addi(10, 10, -1), ECALL], 100), Ok(0xfff));
        assert_eq!(kinds(&[lui(10, 1), addi(10, 10, -1), ECALL])[0], K::Li2);
        let code = [addi(5, 2, -64), addi(6, 0, 11), sd(6, 5, 0), sd(5, 5, 8), ld(7, 5, 8), ld(10, 7, 0), ECALL];
        assert_eq!(kinds(&code)[2], K::SdSd);
        assert_eq!(kinds(&code)[4], K::LdLd);
        assert_eq!(exec(&code, 100), Ok(11));
    }

    #[test]
    fn extra_fused_pairs() {
        let mul = |rd: u32, a: u32, b: u32| 1 << 25 | add(rd, a, b);
        let mulhu = |rd: u32, a: u32, b: u32| 1 << 25 | 3 << 12 | add(rd, a, b);
        let sb = |rs2: u32, rs1: u32, imm: i32| sw(rs2, rs1, imm) & !(7 << 12);
        let lbu = |rd: u32, rs1: u32, imm: i32| lw(rd, rs1, imm) & !(7 << 12) | 4 << 12;
        let run = |words: &[u32], x: u64, y: u64| {
            let p = prog(words);
            let mut m = Machine::new(&p, 100);
            m.regs[5] = x;
            m.regs[6] = y;
            assert!(matches!(m.run(&mut |m: &mut Machine| Ecall::Done(m.regs[10])), Exit::Done(_)));
            (m.regs[10], m.regs[11])
        };
        let code = [mul(10, 5, 6), mulhu(11, 5, 6), ECALL];
        assert_eq!(kinds(&code)[0], K::MulWide);
        assert_eq!(run(&code, u64::MAX, 3), (u64::MAX.wrapping_mul(3), 2));
        let code = [mul(5, 5, 6), mulhu(11, 5, 6), addi(10, 5, 0), ECALL];
        assert_eq!(run(&code, 3, u64::MAX), (u64::MAX - 2, u64::MAX - 3));
        let code = [add(10, 5, 6), add(11, 10, 10), ECALL];
        assert_eq!(kinds(&code)[0], K::AddAdd);
        assert_eq!(run(&code, 2, 3), (5, 10));
        let code = [addi(7, 2, -16), sw(5, 7, 0), sw(6, 7, 4), lw(10, 7, 0), lw(11, 7, 4), ECALL];
        assert_eq!(kinds(&code)[1], K::SwSw);
        assert_eq!(kinds(&code)[3], K::LwLw);
        assert_eq!(run(&code, 0xffff_ffff, 7), (u64::MAX, 7));
        let code = [addi(7, 2, -16), addi(5, 5, 1), sb(5, 7, 0), lbu(10, 7, 0), addi(11, 10, 1), ECALL];
        assert_eq!(kinds(&code)[1], K::AddiSb);
        assert_eq!(kinds(&code)[3], K::LbuAddi);
        assert_eq!(run(&code, 0x1ff, 0), (0, 1));
        let code = [addi(7, 2, -16), sb(6, 7, 0), lbu(10, 7, 0), addi(11, 10, 1), ECALL];
        assert_eq!(run(&code, 0, 0xff), (0xff, 0x100));
    }

    #[test]
    fn more_fused_pairs() {
        let mul = |rd: u32, a: u32, b: u32| 1 << 25 | add(rd, a, b);
        let mulhu = |rd: u32, a: u32, b: u32| 1 << 25 | 3 << 12 | add(rd, a, b);
        let xor = |rd: u32, a: u32, b: u32| 4 << 12 | add(rd, a, b);
        let srli = |rd: u32, a: u32, sh: u32| sh << 20 | a << 15 | 5 << 12 | rd << 7 | 0x13;
        let roriw = |rd: u32, a: u32, sh: u32| (0x600 | sh) << 20 | a << 15 | 5 << 12 | rd << 7 | 0x1b;
        let lbu = |rd: u32, rs1: u32, imm: i32| lw(rd, rs1, imm) & !(7 << 12) | 4 << 12;
        let run = |words: &[u32], x: u64, y: u64| {
            let p = prog(words);
            let mut m = Machine::new(&p, 200);
            m.regs[5] = x;
            m.regs[6] = y;
            assert!(matches!(m.run(&mut |m: &mut Machine| Ecall::Done(m.regs[10])), Exit::Done(_)));
            (m.regs[10], m.regs[11])
        };
        let wide = |x: u64, y: u64| (x.wrapping_mul(y), ((x as u128 * y as u128) >> 64) as u64);

        let code = [mul(10, 5, 6), mulhu(11, 6, 5), ECALL];
        assert_eq!(kinds(&code)[0], K::MulWide);
        assert_eq!(run(&code, u64::MAX, 0x1234_5678_9abc), wide(u64::MAX, 0x1234_5678_9abc));
        let code = [mul(10, 5, 6), mulhu(10, 5, 6), ECALL];
        assert_eq!(kinds(&code)[0], K::MulWide);
        assert_eq!(run(&code, u64::MAX, 7).0, wide(u64::MAX, 7).1);
        let code = [mul(5, 5, 6), mulhu(11, 5, 6), addi(10, 5, 0), ECALL];
        assert_eq!(kinds(&code)[0], K::MulMulhu);
        assert_eq!(run(&code, 3, u64::MAX), (u64::MAX - 2, u64::MAX - 3));
        let code = [mul(10, 5, 6), mulhu(11, 5, 5), ECALL];
        assert_eq!(kinds(&code)[0], K::MulMulhu);

        let code = [xor(10, 5, 6), xor(11, 10, 5), ECALL];
        assert_eq!(kinds(&code)[0], K::XorXor);
        assert_eq!(run(&code, 0b1100, 0b1010), (0b0110, 0b1010));
        let code = [srli(10, 5, 18), xor(11, 10, 5), ECALL];
        assert_eq!(kinds(&code)[0], K::SrliXor);
        assert_eq!(run(&code, 0xdead_beef_cafe_f00d, 0), (0xdead_beef_cafe_f00d >> 18, (0xdead_beef_cafe_f00d >> 18) ^ 0xdead_beef_cafe_f00d));
        let code = [addi(10, 5, -3), add(11, 10, 6), ECALL];
        assert_eq!(kinds(&code)[0], K::AddiAdd);
        assert_eq!(run(&code, 10, 5), (7, 12));
        let code = [addi(7, 2, -16), sd(5, 7, 0), sd(6, 7, 8), ld(10, 7, 8), add(11, 10, 10), ECALL];
        assert_eq!(kinds(&code)[3], K::LdAdd);
        assert_eq!(run(&code, 1, 21), (21, 42));
        let code = [addi(7, 2, -16), sd(5, 7, 0), lbu(10, 7, 0), lbu(11, 7, 1), ECALL];
        assert_eq!(kinds(&code)[2], K::LbuLbu);
        assert_eq!(run(&code, 0xbeef, 0), (0xef, 0xbe));
        let code = [roriw(10, 5, 1), roriw(11, 10, 31), ECALL];
        assert_eq!(kinds(&code)[0], K::RoriwRoriw);
        assert_eq!(run(&code, 0xdead_0000_0000_0001, 0), (0xffff_ffff_8000_0000, 1));
    }

    #[test]
    fn jumping_into_the_second_half_of_a_pair() {
        let code = [jal(0, 8), addi(10, 0, 100), addi(10, 10, 5), ECALL];
        assert_eq!(kinds(&code)[1], K::AddiAddi);
        assert_eq!(exec(&code, 100), Ok(5));
        let code = [jal(0, 8), lui(10, 1), addi(10, 10, 5), ECALL];
        assert_eq!(kinds(&code)[1], K::Li2);
        assert_eq!(exec(&code, 100), Ok(5));
    }

    #[test]
    fn static_calls() {
        let code = [auipc(1, 0), jalr(1, 1, 12), addi(10, 10, 1), addi(10, 1, 0), ECALL];
        assert_eq!(kinds(&code)[0], K::Call);
        assert_eq!(exec(&code, 100), Ok(BASE + 8));
        let code = [auipc(5, 0), jalr(0, 5, 10), ECALL];
        assert_eq!(kinds(&code)[0], K::Lui);
        assert_eq!(exec(&code, 100), BAD_JUMP);
        let code = [auipc(5, 0), jalr(0, 5, 64), ECALL];
        assert_eq!(exec(&code, 100), BAD_JUMP);
    }

    #[test]
    fn fused_loop_counts_gas_exactly() {
        let bne = |rs1: u32, rs2: u32, imm: i32| beq(rs1, rs2, imm) | 1 << 12;
        let code = [addi(5, 0, 50), addi(6, 6, 2), addi(5, 5, -1), bne(5, 0, -8), addi(10, 6, 0), ECALL];
        assert_eq!(kinds(&code)[2], K::AddiBne);
        assert_eq!(exec(&code, 1 + 50 * 3 + 2), Ok(100));
        assert_eq!(exec(&code, 1 + 50 * 3 + 1), Err("oog"));
    }

    fn op(word: u32, x: u64, y: u64) -> u64 {
        let p = prog(&[word, ECALL]);
        let mut m = Machine::new(&p, 100);
        m.regs[5] = x;
        m.regs[6] = y;
        assert!(matches!(m.run(&mut |m: &mut Machine| Ecall::Done(m.regs[10])), Exit::Done(_)));
        m.regs[10]
    }

    #[test]
    fn zba_zbb() {
        let rr = |f7: u32, f3: u32, opc: u32| f7 << 25 | 6 << 20 | 5 << 15 | f3 << 12 | 10 << 7 | opc;
        let ri = |imm12: u32, f3: u32, opc: u32| imm12 << 20 | 5 << 15 | f3 << 12 | 10 << 7 | opc;
        let m1 = u64::MAX;
        let cases: &[(&str, u32, u64, u64, u64)] = &[
            ("add.uw", rr(0x04, 0, 0x3b), 0xffff_ffff_8000_0000, 1, 0x8000_0001),
            ("sh1add", rr(0x10, 2, 0x33), 3, 10, 16),
            ("sh2add", rr(0x10, 4, 0x33), 3, 10, 22),
            ("sh3add", rr(0x10, 6, 0x33), 3, 10, 34),
            ("sh1add.uw", rr(0x10, 2, 0x3b), 0xffff_ffff_0000_0001, 0, 2),
            ("sh2add.uw", rr(0x10, 4, 0x3b), 0xffff_ffff_0000_0001, 1, 5),
            ("sh3add.uw", rr(0x10, 6, 0x3b), 0xffff_ffff_8000_0000, 0, 0x4_0000_0000),
            ("slli.uw", ri(0x080 | 1, 1, 0x1b), 0xffff_ffff_8000_0000, 0, 0x1_0000_0000),
            ("slli.uw 32", ri(0x080 | 32, 1, 0x1b), 0xffff_ffff_0000_0003, 0, 0x3_0000_0000),
            ("andn", rr(0x20, 7, 0x33), 0b1100, 0b1010, 0b0100),
            ("orn", rr(0x20, 6, 0x33), 0, 0xff, !0xff),
            ("xnor", rr(0x20, 4, 0x33), 5, 5, m1),
            ("clz", ri(0x600, 1, 0x13), 1, 0, 63),
            ("clz 0", ri(0x600, 1, 0x13), 0, 0, 64),
            ("ctz", ri(0x601, 1, 0x13), 8, 0, 3),
            ("cpop", ri(0x602, 1, 0x13), 0xff00_0000_0000_00ff, 0, 16),
            ("clzw", ri(0x600, 1, 0x1b), 0xffff_ffff_0000_0001, 0, 31),
            ("ctzw", ri(0x601, 1, 0x1b), 0xffff_ffff_0000_0000, 0, 32),
            ("cpopw", ri(0x602, 1, 0x1b), 0xffff_ffff_0000_0003, 0, 2),
            ("max", rr(0x05, 6, 0x33), m1, 1, 1),
            ("maxu", rr(0x05, 7, 0x33), m1, 1, m1),
            ("min", rr(0x05, 4, 0x33), m1, 1, m1),
            ("minu", rr(0x05, 5, 0x33), m1, 1, 1),
            ("sext.b", ri(0x604, 1, 0x13), 0x180, 0, (-128i64) as u64),
            ("sext.h", ri(0x605, 1, 0x13), 0x1_8000, 0, (-32768i64) as u64),
            ("zext.h", 4 << 12 | 0x04 << 25 | 5 << 15 | 10 << 7 | 0x3b, 0xffff_1234, 0, 0x1234),
            ("rol", rr(0x30, 1, 0x33), 0x8000_0000_0000_0001, 65, 3),
            ("ror", rr(0x30, 5, 0x33), 1, 1, 0x8000_0000_0000_0000),
            ("rori", ri(0x600 | 4, 5, 0x13), 1, 0, 0x1000_0000_0000_0000),
            ("rolw", rr(0x30, 1, 0x3b), 0x8000_0001, 33, 3),
            ("rorw", rr(0x30, 5, 0x3b), 1, 1, 0xffff_ffff_8000_0000),
            ("roriw", ri(0x600 | 1, 5, 0x1b), 0xdead_0000_0000_0001, 0, 0xffff_ffff_8000_0000),
            ("orc.b", ri(0x287, 5, 0x13), 0x0001_0000_0000_0100, 0, 0x00ff_0000_0000_ff00),
            ("rev8", ri(0x6b8, 5, 0x13), 0x0102_0304_0506_0708, 0, 0x0807_0605_0403_0201),
        ];
        for &(name, word, x, y, want) in cases {
            assert_eq!(op(word, x, y), want, "{name}");
        }
        for bad in [ri(0x603, 1, 0x13), ri(0x288, 5, 0x13), ri(0x603, 1, 0x1b), rr(0x30, 4, 0x33), 4 << 12 | 0x04 << 25 | 1 << 20 | 0x3b] {
            assert_eq!(exec(&[bad, ECALL], 100), INVALID_INS, "{bad:#x}");
        }
    }

    #[test]
    fn word_scan_restore_matches_byte_scan() {
        let code = [lui(5, 0x20), sd(5, 5, -8), sd(5, 2, -8), addi(6, 0, 0x7ff), sd(6, 5, 0x7f8), lui(7, 0x21), sd(7, 7, -4), ECALL];
        let p = prog(&code);
        for word in [false, true] {
            let mut mem = None;
            for _ in 0..3 {
                let mut m = Machine::reuse_opts(&p, 1000, mem.take(), word);
                assert_eq!(m.mem, p.image);
                assert!(matches!(m.run(&mut |_: &mut Machine| Ecall::Done(0)), Exit::Done(0)));
                m.mem_mut(p.mem_size as u64 - 1, 1).unwrap()[0] = 9;
                mem = Some(m.into_memory());
            }
        }
    }

    #[test]
    fn reused_memory_is_restored_exactly() {
        let code = [lui(5, 0x20), sd(5, 5, -8), sd(5, 2, -8), addi(6, 0, 0x7ff), sd(6, 5, 0x7f8), lui(7, 0x21), sd(7, 7, -4), ECALL];
        let p = prog(&code);
        let mut mem = None;
        for round in 0..3 {
            let mut m = Machine::reuse(&p, 1000, mem.take());
            assert_eq!(m.mem, p.image, "round {round}");
            assert!(matches!(m.run(&mut |_: &mut Machine| Ecall::Done(0)), Exit::Done(0)));
            assert_ne!(m.mem, p.image);
            m.mem_mut(0x1000, 3).unwrap().copy_from_slice(b"abc");
            mem = Some(m.into_memory());
        }
        let other = prog(&code);
        let m = Machine::reuse(&other, 1000, mem);
        assert_eq!(m.mem, other.image);
    }

    #[test]
    fn spare_buffers_from_other_programs_start_from_the_image() {
        let code = [lui(5, 0x20), sd(5, 5, -8), sd(5, 2, -8), addi(6, 0, 0x7ff), sd(6, 5, 0x7f8), lui(7, 0x21), sd(7, 7, -4), ECALL];
        let p = prog(&code);
        let mut junk = Memory::blank(4 * p.mem_size);
        junk.buf.fill(0xa5);
        junk.dirty.fill(1);
        let mut mem = Some(junk);
        for round in 0..3 {
            let mut m = Machine::reuse(&p, 1000, mem.take());
            assert_eq!(m.mem, p.image, "round {round}");
            assert!(matches!(m.run(&mut |_: &mut Machine| Ecall::Done(0)), Exit::Done(0)));
            m.mem_mut(0x1000, 3).unwrap().copy_from_slice(b"abc");
            mem = Some(m.into_memory());
        }
        let other = prog(&[addi(10, 0, 1), ECALL]);
        let m = Machine::reuse(&other, 1000, mem);
        assert_eq!(m.mem, other.image);
        let small = Memory::blank(16);
        let m = Machine::reuse(&p, 1000, Some(small));
        assert_eq!(m.mem, p.image);
    }

    fn elf_with_segments(n: usize) -> Vec<u8> {
        let code = [addi(10, 0, 7), ECALL];
        let code: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let phoff = 64usize;
        let data_off = phoff + 56 * n;
        let mut f = vec![0u8; data_off];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&243u16.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&BASE.to_le_bytes());
        f[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&(n as u16).to_le_bytes());
        f[58..60].copy_from_slice(&64u16.to_le_bytes());
        for k in 0..n {
            let h = &mut f[phoff + 56 * k..phoff + 56 * (k + 1)];
            h[0..4].copy_from_slice(&1u32.to_le_bytes());
            h[4..8].copy_from_slice(&(if k == 0 { 5u32 } else { 4 }).to_le_bytes());
            h[8..16].copy_from_slice(&(data_off as u64).to_le_bytes());
            h[16..24].copy_from_slice(&(BASE + 0x1000 * k as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(code.len() as u64).to_le_bytes());
            h[40..48].copy_from_slice(&(code.len() as u64).to_le_bytes());
        }
        f.extend_from_slice(&code);
        f
    }

    #[test]
    fn loader_rejects_overlapping_segments() {
        let mut f = elf_with_segments(2);
        let ph1 = 64 + 56;
        f[ph1 + 16..ph1 + 24].copy_from_slice(&(BASE + 0x100).to_le_bytes());
        assert!(load(&f).is_ok());
        f[ph1 + 16..ph1 + 24].copy_from_slice(&(BASE + 4).to_le_bytes());
        assert_eq!(load(&f).err(), Some("riscv_load_overlapping_segments"));
    }

    #[test]
    fn loader_bounds_segment_amplification() {
        let p = load(&elf_with_segments(2)).unwrap();
        let mut m = Machine::new(&p, 100);
        assert!(matches!(m.run(&mut |m: &mut Machine| Ecall::Done(m.regs[10])), Exit::Done(7)));
        assert!(load(&elf_with_segments(MAX_SEGMENTS)).is_ok());
        assert_eq!(load(&elf_with_segments(MAX_SEGMENTS + 1)).err(), Some("riscv_load_too_many_segments"));
        assert_eq!(load(&elf_with_segments(5000)).err(), Some("riscv_load_too_many_segments"));
    }

    #[test]
    fn load_rejects_bad_layout() {
        assert_eq!(build(0x1002, 0x1002, &[0x13, 0, 0, 0], vec![], 0x1006, true, true).err(), Some("riscv_load_code_misaligned"));
        assert_eq!(build(0x1000, 0x1002, &[0x13, 0, 0, 0], vec![], 0x1004, true, true).err(), Some("riscv_load_entry_outside_code_or_misaligned"));
        assert_eq!(build(0x1000, 0x1004, &[0x13, 0, 0, 0], vec![], 0x1004, true, true).err(), Some("riscv_load_entry_outside_code_or_misaligned"));
        assert_eq!(build(0x1000, 0x1000, &[0x13, 0, 0, 0], vec![], u64::MAX, true, true).err(), Some("riscv_load_code_outside_memory"));
        assert_eq!(build(0x1000, 0x1000, &[0x13, 0, 0, 0], vec![], 0x1002, true, true).err(), Some("riscv_load_code_outside_memory"));
        assert_eq!(build(0x1000, 0x1000, &[0x13, 0, 0, 0], vec![(0x2000, vec![0; 8])], 0x2004, true, true).err(), Some("riscv_load_segment_outside_memory"));
        assert_eq!(build(0x1000, 0x1000, &[0x13, 0, 0, 0], vec![(u64::MAX - 2, vec![0; 8])], 0x2004, true, true).err(), Some("riscv_load_segment_outside_memory"));
        assert_eq!(build(0x1000, 0x1000, &[0x13, 0, 0, 0], vec![(0x1000, vec![0; 4]); MAX_SEGMENTS + 1], 0x2000, true, true).err(), Some("riscv_load_too_much_segment_data"));
        assert!(load(&vec![0u8; MAX_ELF + 1]).is_err());
        assert!(load(b"\x7fELF garbage").is_err());
        assert!(load(&[]).is_err());
    }
}

pub fn describe(p: &Program, i: usize) -> String {
    let x = p.ins[i];
    format!("{:?} rd={} rs1={} rs2={} imm={} t={}", x.k, x.rd, x.rs1, x.rs2, x.imm, x.t)
}

fn fused(k: K) -> bool {
    matches!(k, K::AddiAddi | K::LdLd | K::SdSd | K::Li2 | K::Call | K::AddAdd | K::MulMulhu | K::LwLw | K::SwSw | K::AddiSb | K::LbuAddi
        | K::LbuLbu | K::XorXor | K::SrliXor | K::AddiAdd | K::LdAdd | K::RoriwRoriw | K::MulWide
        | K::AddiBeq | K::AddiBne | K::AddiBlt | K::AddiBge | K::AddiBltu | K::AddiBgeu)
}

fn ends_block(k: K) -> bool {
    matches!(k, K::Jal | K::Jalr | K::Beq | K::Bne | K::Blt | K::Bge | K::Bltu | K::Bgeu | K::Ecall | K::Invalid
        | K::Call | K::AddiBeq | K::AddiBne | K::AddiBlt | K::AddiBge | K::AddiBltu | K::AddiBgeu)
}

pub fn profile_report(p: &Program, hits: &[u64], trans: &std::collections::HashMap<(u32, u32), u64>, top: usize) -> String {
    use std::collections::HashMap;
    use std::fmt::Write;
    let ends = ends_block;
    let total: u64 = hits.iter().sum();
    let original: u64 = hits.iter().enumerate().map(|(i, h)| h * (1 + fused(p.ins[i].k) as u64)).sum();
    let mut kinds: HashMap<K, u64> = HashMap::new();
    let mut pairs: HashMap<(K, K, bool), u64> = HashMap::new();
    for (i, &h) in hits.iter().enumerate() {
        *kinds.entry(p.ins[i].k).or_default() += h;
    }
    for (&(x, y), &h) in trans {
        if x == u32::MAX {
            continue;
        }
        let (a, b) = (p.ins[x as usize], p.ins[y as usize]);
        if ends(a.k) || fused(a.k) || fused(b.k) || y != x + 1 {
            continue;
        }
        let dep = a.rd != ZERO_SINK && (a.rd == b.rs1 || a.rd == b.rs2);
        *pairs.entry((a.k, b.k, dep)).or_default() += h;
    }
    let mut out = String::new();
    let _ = writeln!(out, "dispatched {total}, original instructions {original}, block-terminating {:.1}%", 100.0 * hits.iter().enumerate().filter(|(i, _)| ends(p.ins[*i].k)).map(|(_, h)| *h).sum::<u64>() as f64 / total as f64);
    let mut kv: Vec<_> = kinds.into_iter().collect();
    kv.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, n) in kv.iter().take(top) {
        let _ = writeln!(out, "  {:<8?} {:>5.1}%", k, 100.0 * *n as f64 / total as f64);
    }
    let mut pv: Vec<_> = pairs.into_iter().collect();
    pv.sort_by(|a, b| b.1.cmp(&a.1));
    let _ = writeln!(out, "remaining fusable pairs, % of dispatches (dep = second reads first's result):");
    for ((a, b, dep), n) in pv.iter().take(top) {
        let _ = writeln!(out, "  {:<8?} -> {:<8?} {:<4} {:>5.1}%", a, b, if *dep { "dep" } else { "" }, 100.0 * *n as f64 / total as f64);
    }
    out
}
