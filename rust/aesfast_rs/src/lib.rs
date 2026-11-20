//! folded last-block pbkdf2-hmac-sha1 verifier for winzip AE-2/3 password
//! checks - the rust twin of zippass/aesfast.py, plus a 4-way multi-buffer
//! sse2 chain (sse2 is baseline on x86-64; the 4 lanes are 4 candidates,
//! since one candidate's 1000-iteration chain is inherently serial).
//!
//! the verifier is the last 2 bytes of pbkdf2(pw, salt, 1000, dklen); only
//! the last output block is ever compared and each block is independent:
//!   u1    = hmac(pw, salt || int_be(nb))
//!   u_k   = hmac(pw, u_{k-1})
//!   t_nb  = u1 ^ ... ^ u1000, checked at bytes [r-2, r-1]
//! with hmac state-folded: ipad/opad sha1 states depend only on the key,
//! and every post-key message is exactly 20 bytes, so each iteration is
//! two compressions over a fixed 16-word template.
//!
//! bit exactness against hashlib.pbkdf2_hmac is pinned by the python test
//! suite; the ffi layer returns negative codes on bad args or panic and
//! the python side falls back to the numba/openssl paths.

mod sha1;
mod sha1_avx2;
mod sha1_ni;
mod sha1_simd;

use sha1::{compress, key_block_words, INIT};
use std::slice;

const U32_MSG_TEMPLATE: (u32, u32) = (0x8000_0000, 672); // pad word, (64+20)*8

/// hmac key block + folded ipad/opad states + first chain link u1 for one
/// candidate - everything before the serial 999-iteration loop.
pub(crate) struct Setup {
    pub(crate) ia: [u32; 5],
    pub(crate) oa: [u32; 5],
    pub(crate) u1: [u32; 5],
}

pub(crate) fn setup(pwd: &[u8], salt_words: &[u32], nb: u32) -> Setup {
    let kw = key_block_words(pwd);
    let mut w = [0u32; 16];
    for j in 0..16 {
        w[j] = kw[j] ^ 0x3636_3636;
    }
    let mut ia = INIT;
    compress(&mut ia, &mut w);
    for j in 0..16 {
        w[j] = kw[j] ^ 0x5C5C_5C5C;
    }
    let mut oa = INIT;
    compress(&mut oa, &mut w);

    // u1 = hmac(pw, salt || int_be(nb)); m = salt bytes + 4 index bytes
    let m = salt_words.len() * 4 + 4;
    for j in 0..16 {
        let mut v = 0u32;
        for t in 0..4 {
            let idx = 4 * j + t;
            if idx < m - 4 {
                v = (v << 8) | ((salt_words[idx >> 2] >> (8 * (3 - (idx & 3)))) & 0xFF);
            } else if idx < m {
                v = (v << 8) | ((nb >> (8 * (3 - (idx - (m - 4))))) & 0xFF);
            } else if idx == m {
                v = (v << 8) | 0x80;
            } else {
                v <<= 8;
            }
        }
        w[j] = v;
    }
    w[14] = 0;
    w[15] = ((64 + m) * 8) as u32;
    let mut inner = ia;
    compress(&mut inner, &mut w);

    // outer: message = the 20 inner bytes -> state words are the message
    w[0] = inner[0];
    w[1] = inner[1];
    w[2] = inner[2];
    w[3] = inner[3];
    w[4] = inner[4];
    w[5] = U32_MSG_TEMPLATE.0;
    for j in 6..14 {
        w[j] = 0;
    }
    w[14] = 0;
    w[15] = U32_MSG_TEMPLATE.1;
    let mut u1 = oa;
    compress(&mut u1, &mut w);
    Setup { ia, oa, u1 }
}

/// the serial 999-iteration chain, scalar - also the reference for simd.
fn chain_scalar(s: &Setup) -> [u32; 5] {
    let mut w = [0u32; 16];
    let mut u = s.u1;
    let mut acc = u;
    for _ in 0..999 {
        w[0] = u[0];
        w[1] = u[1];
        w[2] = u[2];
        w[3] = u[3];
        w[4] = u[4];
        w[5] = U32_MSG_TEMPLATE.0;
        for j in 6..14 {
            w[j] = 0;
        }
        w[14] = 0;
        w[15] = U32_MSG_TEMPLATE.1;
        let mut inner = s.ia;
        compress(&mut inner, &mut w);
        w[0] = inner[0];
        w[1] = inner[1];
        w[2] = inner[2];
        w[3] = inner[3];
        w[4] = inner[4];
        w[5] = U32_MSG_TEMPLATE.0;
        for j in 6..14 {
            w[j] = 0;
        }
        w[14] = 0;
        w[15] = U32_MSG_TEMPLATE.1;
        let mut u2 = s.oa;
        compress(&mut u2, &mut w);
        u = u2;
        for j in 0..5 {
            acc[j] ^= u[j];
        }
    }
    acc
}

/// verifier = bytes [r-2, r-1] of t_nb (the accumulated state), big-endian.
pub(crate) fn gather(acc: &[u32; 5], r: usize) -> u16 {
    let bi = r - 2;
    let wj = bi >> 2;
    let off = bi & 3;
    let hw = acc[wj];
    let hi = (hw >> (8 * (3 - off))) & 0xFF;
    let lo = if off == 3 {
        acc[(wj + 1).min(4)] >> 24
    } else {
        (hw >> (8 * (2 - off))) & 0xFF
    };
    ((hi << 8) | lo) as u16
}

pub fn verify_one(pwd: &[u8], salt_words: &[u32], nb: u32, r: usize, pv: u16) -> bool {
    let s = setup(pwd, salt_words, nb);
    let acc = chain_scalar(&s);
    gather(&acc, r) == pv
}

/// spec shapes this kernel accepts; python validates the same bounds and
/// falls back to numba/openssl otherwise (salt > 48 would need a second
/// block for the u1 message, which neither kernel implements).
pub fn params_ok(salt_len: usize, dklen: u32) -> bool {
    salt_len > 0 && salt_len <= 48 && salt_len % 4 == 0 && dklen >= 2
}

/// verify `n` passwords (flat bytes + per-password lengths) against one
/// member's constants; writes verifier-pass indices into `hits` (capacity
/// `hits_cap`) and returns the total pass count, or a negative code:
/// -1 bad args, -2 panic. callers must guarantee pwds/lens describe n
/// passwords - this is an internal ffi boundary, not untrusted input.
#[no_mangle]
pub extern "C" fn zpv_batch(
    pwds: *const u8,
    lens: *const u32,
    n: usize,
    salt: *const u8,
    salt_len: usize,
    dklen: u32,
    pv: u16,
    hits: *mut u32,
    hits_cap: u32,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if pwds.is_null() || lens.is_null() || salt.is_null() || hits.is_null() {
            return -1;
        }
        if !params_ok(salt_len, dklen) {
            return -1;
        }
        let nb = (dklen + 19) / 20;
        let r = (dklen - 20 * (nb - 1)) as usize;
        if r < 2 {
            return -1;
        }
        let lens = unsafe { slice::from_raw_parts(lens, n) };
        // the caller guarantees pwds holds the n flat passwords; the sum
        // of the lengths is that span, so it bounds the slice honestly
        let mut total_len = 0usize;
        for l in lens.iter() {
            total_len = match total_len.checked_add(*l as usize) {
                Some(t) => t,
                None => return -1,
            };
        }
        let pwds = unsafe { slice::from_raw_parts(pwds, total_len) };
        let salt_bytes = unsafe { slice::from_raw_parts(salt, salt_len) };
        let mut salt_words = vec![0u32; salt_len / 4];
        for (i, sw) in salt_words.iter_mut().enumerate() {
            *sw = u32::from_be_bytes([
                salt_bytes[4 * i],
                salt_bytes[4 * i + 1],
                salt_bytes[4 * i + 2],
                salt_bytes[4 * i + 3],
            ]);
        }
        let hits = unsafe { slice::from_raw_parts_mut(hits, hits_cap as usize) };
        let mut out = HitSink {
            hits,
            written: 0,
            total: 0,
        };
        // backend: sha-ni hardware rounds when the cpu has them (this box
        // does), else the 8-way avx2 multi-buffer, else 4-way sse2, with a
        // scalar tail. ZIPPASS_RUST_MAXWIDTH forces ni/8/4/1 for a/b timing.
        #[cfg(target_arch = "x86_64")]
        let use_ni = match std::env::var("ZIPPASS_RUST_MAXWIDTH").as_deref() {
            Ok("ni") => true,
            Ok("8") | Ok("4") | Ok("1") => false,
            _ => std::is_x86_feature_detected!("sha"),
        };
        #[cfg(not(target_arch = "x86_64"))]
        let use_ni = false;
        #[cfg(target_arch = "x86_64")]
        let maxw: usize = match std::env::var("ZIPPASS_RUST_MAXWIDTH").as_deref() {
            Ok("4") => 4,
            Ok("1") => 1,
            _ => {
                if std::is_x86_feature_detected!("avx2") {
                    8
                } else {
                    4
                }
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        let maxw: usize = 1;

        let mut pos = 0usize;
        let mut i = 0usize;
        #[cfg(target_arch = "x86_64")]
        if use_ni {
            while i + 2 <= n {
                let la = lens[i] as usize;
                let lb = lens[i + 1] as usize;
                if la + lb > pwds.len() - pos {
                    return -1;
                }
                let (pa, rest) = pwds[pos..].split_at(la);
                let passes = sha1_ni::ni::verify2_ni(
                    pa, &rest[..lb], &salt_words, nb, r, pv);
                if passes[0] {
                    out.record(i as u32);
                }
                if passes[1] {
                    out.record((i + 1) as u32);
                }
                pos += la + lb;
                i += 2;
            }
            while i < n {
                let len = lens[i] as usize;
                if len > pwds.len() - pos {
                    return -1;
                }
                if sha1_ni::ni::verify_ni(&pwds[pos..pos + len], &salt_words, nb, r, pv) {
                    out.record(i as u32);
                }
                pos += len;
                i += 1;
            }
            return out.total.min(i32::MAX as u32) as i32;
        }
        #[cfg(target_arch = "x86_64")]
        if maxw >= 8 {
            while i + 8 <= n {
                let mut group_len = 0usize;
                for l in 0..8 {
                    group_len += lens[i + l] as usize;
                }
                if group_len > pwds.len() - pos {
                    return -1;
                }
                let passes = unsafe {
                    sha1_avx2::group8(
                        &pwds[pos..pos + group_len],
                        &lens[i..i + 8],
                        &salt_words,
                        nb,
                        r,
                        pv,
                    )
                };
                for (l, pass) in passes.iter().enumerate() {
                    if *pass {
                        out.record((i + l) as u32);
                    }
                }
                pos += group_len;
                i += 8;
            }
        }
        #[cfg(target_arch = "x86_64")]
        if maxw >= 4 {
            while i + 4 <= n {
                let mut group_len = 0usize;
                for l in 0..4 {
                    group_len += lens[i + l] as usize;
                }
                if group_len > pwds.len() - pos {
                    return -1;
                }
                let passes = unsafe {
                    sha1_simd::group4(
                        &pwds[pos..pos + group_len],
                        &lens[i..i + 4],
                        &salt_words,
                        nb,
                        r,
                        pv,
                    )
                };
                for (l, pass) in passes.iter().enumerate() {
                    if *pass {
                        out.record((i + l) as u32);
                    }
                }
                pos += group_len;
                i += 4;
            }
        }
        while i < n {
            let len = lens[i] as usize;
            if len > pwds.len() - pos {
                return -1;
            }
            if verify_one(&pwds[pos..pos + len], &salt_words, nb, r, pv) {
                out.record(i as u32);
            }
            pos += len;
            i += 1;
        }
        out.total.min(i32::MAX as u32) as i32
    });
    match result {
        Ok(code) => code,
        Err(_) => -2,
    }
}

struct HitSink<'a> {
    hits: &'a mut [u32],
    written: usize,
    total: u32,
}

impl<'a> HitSink<'a> {
    fn record(&mut self, idx: u32) {
        self.total += 1;
        if self.written < self.hits.len() {
            self.hits[self.written] = idx;
            self.written += 1;
        }
    }
}
