//! rand — ChaCha20 CSPRNG seeded from RDRAND at boot.
//!
//! Linux shapes its RNG the same way: hardware entropy seeds a
//! stream cipher, and everything else (ISNs, XIDs, ASLR cookies)
//! draws from the cipher — never from rdtsc or a counter directly.
//!
//! Seed policy (per CVE-2024-35875's reasoning): RDRAND is the
//! preferred source under virtualization since the host can
//! influence nearly every other input. If RDRAND is absent we fall
//! back to rdtsc jitter — weak, and we say so loudly on the console.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static SEEDED: AtomicBool = AtomicBool::new(false);
static ISN_KEY0: AtomicU64 = AtomicU64::new(0);
static ISN_KEY1: AtomicU64 = AtomicU64::new(0);

struct Pool {
    state: [u32; 16],
    buf: [u8; 64],
    idx: usize,
}

static mut RNG: Pool = Pool {
    state: [0; 16],
    buf: [0; 64],
    idx: 64,
};

fn rng() -> &'static mut Pool {
    // SAFETY: single-CPU boot context, same contract as kalloc's
    // ALLOC. Not IRQ/reentrant-safe — callers are all boot-path.
    unsafe { &mut *core::ptr::addr_of_mut!(RNG) }
}

fn rdrand64() -> Option<u64> {
    let mut v = 0u64;
    // bounded retries: RDRAND legitimately fails under contention
    for _ in 0..16 {
        // SAFETY: guarded by CPUID check in init; result in CF.
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut v) } == 1 {
            return Some(v);
        }
    }
    None
}

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn block(out: &mut [u8; 64], st: &[u32; 16]) {
    let mut x = *st;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let w = x[i].wrapping_add(st[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// Seed the pool: 256 bits of RDRAND when available, rdtsc jitter
/// otherwise. Returns false when the seed is weak (no RDRAND).
pub fn init() -> bool {
    let have = core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0;
    let mut seed = [0u8; 32];
    if have {
        for c in seed.chunks_exact_mut(8) {
            let v = rdrand64().unwrap_or_else(|| unsafe {
                core::arch::x86_64::_rdtsc()
            });
            c.copy_from_slice(&v.to_le_bytes());
        }
    } else {
        // no hardware RNG: best-effort jitter seed
        for c in seed.chunks_exact_mut(8) {
            let t = unsafe { core::arch::x86_64::_rdtsc() };
            let j = t ^ (t >> 32);
            c.copy_from_slice(
                &j.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes(),
            );
        }
    }
    let rng = rng();
    // ChaCha20 state: constants | 256b key | counter | nonce
    rng.state[0] = 0x6170_7865;
    rng.state[1] = 0x3320_646e;
    rng.state[2] = 0x7962_2d32;
    rng.state[3] = 0x6b20_6574;
    for i in 0..8 {
        rng.state[4 + i] =
            u32::from_le_bytes(seed[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let t = unsafe { core::arch::x86_64::_rdtsc() };
    rng.state[12] = 0;
    rng.state[13] = 0;
    rng.state[14] = t as u32;
    rng.state[15] = (t >> 32) as u32;
    rng.idx = 64;
    // draw the per-boot ISN key once and keep it — connections
    // re-use it so their ISNs are a function of the 4-tuple,
    // the secure_tcp_seq property Linux guarantees.
    let mut b = [0u8; 64];
    block(&mut b, &rng.state);
    ISN_KEY0.store(
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        Ordering::Relaxed,
    );
    ISN_KEY1.store(
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
        Ordering::Relaxed,
    );
    rng.state[12] = 1; // burn block 0 for the key, stream from block 1
    SEEDED.store(true, Ordering::Relaxed);
    have
}

/// Mix fresh hardware entropy into the pool: bytes XOR-fold into
/// the ChaCha key words and nonce, so future output stays a
/// function of every seed ever fed — a weak or compromised new
/// source can only perturb, never wipe the established secret.
/// The stale block buffer is dropped so the next draw mints under
/// the updated key; the counter bumps to keep (key, counter)
/// pairs unique. Same boot-context contract as next_u64 — not
/// IRQ/reentrant-safe.
pub fn reseed(entropy: &[u8]) {
    if !SEEDED.load(Ordering::Relaxed) || entropy.is_empty() {
        return;
    }
    let rng = rng();
    for (i, &b) in entropy.iter().enumerate() {
        let w = 4 + (i / 4) % 8;
        rng.state[w] ^= (b as u32) << ((i % 4) * 8);
    }
    // A fresh rdtsc fold keeps the nonce moving even when entropy
    // arrives in bursts.
    let t = unsafe { core::arch::x86_64::_rdtsc() };
    rng.state[14] ^= t as u32;
    rng.state[15] ^= (t >> 32) as u32;
    rng.state[12] = rng.state[12].wrapping_add(1);
    rng.idx = 64;
}

/// Per-boot secret key for keyed-hash uses (TCP ISN, future cookies).
pub fn isn_key() -> (u64, u64) {
    (
        ISN_KEY0.load(Ordering::Relaxed),
        ISN_KEY1.load(Ordering::Relaxed),
    )
}

/// Next 64 bits of ChaCha20 output. Single-CPU boot context; not
/// IRQ/reentrant-safe yet — callers today are all in the boot path.
pub fn next_u64() -> u64 {
    assert!(
        SEEDED.load(Ordering::Relaxed),
        "rand used before rand::init"
    );
    let rng = rng();
    if rng.idx >= 64 {
        let mut b = [0u8; 64];
        block(&mut b, &rng.state);
        rng.buf = b;
        rng.state[12] = rng.state[12].wrapping_add(1);
        if rng.state[12] == 0 {
            rng.state[13] = rng.state[13].wrapping_add(1);
        }
        rng.idx = 0;
        b.fill(0);
    }
    let v = u64::from_le_bytes(
        rng.buf[rng.idx..rng.idx + 8].try_into().unwrap(),
    );
    rng.idx += 8;
    v
}
