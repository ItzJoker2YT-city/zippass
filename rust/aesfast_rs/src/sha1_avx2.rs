//! 8-way multi-buffer avx2 sha1 for the folded pbkdf2 chain.
//!
//! mirrors sha1_simd's 4-way sse2 structure with __m256i: on Zen+ (no
//! sha-ni, 256-bit int ops decode as 2x128 uops) the sha1 round chain is
//! latency-bound, so doubling the lanes in flight nearly doubles the
//! candidates per chain without needing more cpu. only compiled avx2
//! intrinsics behind runtime detection (std::is_x86_feature_detected);
//! the per-candidate prefix stays scalar, same as the 4-way path.

#![allow(clippy::too_many_arguments)]

#[cfg(target_arch = "x86_64")]
mod eightway {
    use crate::{gather, setup, Setup};
    use std::arch::x86_64::*;

    #[inline]
    unsafe fn pack8(x: &[u32; 8]) -> __m256i {
        _mm256_set_epi32(
            x[7] as i32, x[6] as i32, x[5] as i32, x[4] as i32,
            x[3] as i32, x[2] as i32, x[1] as i32, x[0] as i32,
        )
    }

    #[inline]
    unsafe fn transpose_states(st: &[[u32; 5]; 8]) -> [__m256i; 5] {
        let mut v = [_mm256_setzero_si256(); 5];
        for (j, slot) in v.iter_mut().enumerate() {
            *slot = pack8(&[
                st[0][j], st[1][j], st[2][j], st[3][j],
                st[4][j], st[5][j], st[6][j], st[7][j],
            ]);
        }
        v
    }

    #[inline]
    unsafe fn unpack8(v: __m256i) -> [u32; 8] {
        let mut t = [0u32; 8];
        _mm256_storeu_si256(t.as_mut_ptr() as *mut __m256i, v);
        t
    }

    #[inline(always)]
    unsafe fn rol1(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 1), _mm256_srli_epi32(x, 31))
    }

    #[inline(always)]
    unsafe fn rol5(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 5), _mm256_srli_epi32(x, 27))
    }

    #[inline(always)]
    unsafe fn rol30(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_slli_epi32(x, 30), _mm256_srli_epi32(x, 2))
    }

    /// one 8-way compression over the fixed 20-byte-message template:
    /// w[0..4] = msg (per-lane state words), w[5] = 0x80000000,
    /// w[6..13] = 0, w[14] = 0, w[15] = 672.
    #[inline]
    unsafe fn compress20(st: &mut [__m256i; 5], msg: &[__m256i; 5]) {
        let zero = _mm256_setzero_si256();
        let pad = _mm256_set1_epi32(0x8000_0000u32 as i32);
        let len672 = _mm256_set1_epi32(672);
        let mut w = [zero; 16];
        w[0] = msg[0];
        w[1] = msg[1];
        w[2] = msg[2];
        w[3] = msg[3];
        w[4] = msg[4];
        w[5] = pad;
        w[15] = len672;

        let (mut a, mut b, mut c, mut d, mut e) = (st[0], st[1], st[2], st[3], st[4]);

        macro_rules! vround {
            ($i:expr) => {{
                if $i >= 16 {
                    w[$i & 15] = rol1(_mm256_xor_si256(
                        _mm256_xor_si256(w[($i + 13) & 15], w[($i + 8) & 15]),
                        _mm256_xor_si256(w[($i + 2) & 15], w[$i & 15]),
                    ));
                }
                let f = if $i < 20 {
                    _mm256_or_si256(
                        _mm256_and_si256(b, c),
                        _mm256_andnot_si256(b, d),
                    )
                } else if $i < 40 {
                    _mm256_xor_si256(_mm256_xor_si256(b, c), d)
                } else if $i < 60 {
                    _mm256_or_si256(
                        _mm256_or_si256(_mm256_and_si256(b, c), _mm256_and_si256(b, d)),
                        _mm256_and_si256(c, d),
                    )
                } else {
                    _mm256_xor_si256(_mm256_xor_si256(b, c), d)
                };
                let k = _mm256_set1_epi32(
                    (if $i < 20 {
                        0x5A82_7999u32
                    } else if $i < 40 {
                        0x6ED9_EBA1u32
                    } else if $i < 60 {
                        0x8F1B_BCDCu32
                    } else {
                        0xCA62_C1D6u32
                    }) as i32,
                );
                let t = _mm256_add_epi32(
                    w[$i & 15],
                    _mm256_add_epi32(
                        rol5(a),
                        _mm256_add_epi32(f, _mm256_add_epi32(e, k)),
                    ),
                );
                e = d;
                d = c;
                c = rol30(b);
                b = a;
                a = t;
            }};
        }

        macro_rules! vrounds8 {
            ($base:expr) => {
                vround!($base);
                vround!($base + 1);
                vround!($base + 2);
                vround!($base + 3);
                vround!($base + 4);
                vround!($base + 5);
                vround!($base + 6);
                vround!($base + 7);
            };
        }

        vrounds8!(0);
        vrounds8!(8);
        vrounds8!(16);
        vrounds8!(24);
        vrounds8!(32);
        vrounds8!(40);
        vrounds8!(48);
        vrounds8!(56);
        vrounds8!(64);
        vrounds8!(72);

        st[0] = _mm256_add_epi32(st[0], a);
        st[1] = _mm256_add_epi32(st[1], b);
        st[2] = _mm256_add_epi32(st[2], c);
        st[3] = _mm256_add_epi32(st[3], d);
        st[4] = _mm256_add_epi32(st[4], e);
    }

    /// the serial 999-iteration chain for eight lanes at once.
    unsafe fn chain8(
        ia: &[__m256i; 5],
        oa: &[__m256i; 5],
        u1: &[__m256i; 5],
    ) -> [__m256i; 5] {
        let mut u = *u1;
        let mut acc = *u1;
        for _ in 0..999 {
            let mut inner = *ia;
            compress20(&mut inner, &u);
            let mut outer = *oa;
            compress20(&mut outer, &inner);
            u = outer;
            for j in 0..5 {
                acc[j] = _mm256_xor_si256(acc[j], u[j]);
            }
        }
        acc
    }

    /// verify eight candidates (flat, in order) against one member;
    /// returns the pass flags in lane order = candidate order.
    pub unsafe fn group8(
        group: &[u8],
        lens: &[u32],
        salt_words: &[u32],
        nb: u32,
        r: usize,
        pv: u16,
    ) -> [bool; 8] {
        let mut offs = [0usize; 9];
        for l in 0..8 {
            offs[l + 1] = offs[l] + lens[l] as usize;
        }
        let mut st = [[0u32; 5]; 24]; // [0..8]=ia, [8..16]=oa, [16..24]=u1
        for l in 0..8 {
            let s: Setup = setup(&group[offs[l]..offs[l + 1]], salt_words, nb);
            st[l] = s.ia;
            st[8 + l] = s.oa;
            st[16 + l] = s.u1;
        }
        let ia = transpose_states(st[0..8].try_into().unwrap());
        let oa = transpose_states(st[8..16].try_into().unwrap());
        let u1 = transpose_states(st[16..24].try_into().unwrap());
        let acc_v = chain8(&ia, &oa, &u1);

        let mut acc = [[0u32; 5]; 8];
        for (j, v) in acc_v.iter().enumerate() {
            let t = unpack8(*v);
            for l in 0..8 {
                acc[l][j] = t[l];
            }
        }
        let mut passes = [false; 8];
        for (l, slot) in passes.iter_mut().enumerate() {
            *slot = gather(&acc[l], r) == pv;
        }
        passes
    }
}

#[cfg(target_arch = "x86_64")]
pub use eightway::group8;

#[cfg(not(target_arch = "x86_64"))]
pub fn group8_unavailable() {}
