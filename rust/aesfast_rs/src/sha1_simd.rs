//! 4-way multi-buffer sse2 sha1 for the folded pbkdf2 chain.
//!
//! one candidate's 1000-iteration hmac chain is inherently serial (u_k =
//! hmac(pw, u_{k-1})), so lanes hold four *different candidates*, each
//! running its own chain. sse2 is baseline on x86-64 - no runtime feature
//! detection anywhere. all four lanes share the fixed 20-byte message
//! template; only the five state words differ per lane, so the message
//! window is built from transposed state vectors. the per-candidate
//! prefix (key hashing, ipad/opad states, u1) stays scalar - four
//! compressions per candidate, noise next to the 1998 vector ones.

#![allow(clippy::too_many_arguments)]

#[cfg(target_arch = "x86_64")]
mod fourway {
    use crate::{gather, setup, Setup};
    use std::arch::x86_64::*;

    #[inline]
    unsafe fn pack4(x0: u32, x1: u32, x2: u32, x3: u32) -> __m128i {
        _mm_set_epi32(x3 as i32, x2 as i32, x1 as i32, x0 as i32)
    }

    #[inline]
    unsafe fn transpose_states(st: &[[u32; 5]; 4]) -> [__m128i; 5] {
        let mut v = [_mm_setzero_si128(); 5];
        for (j, slot) in v.iter_mut().enumerate() {
            *slot = pack4(st[0][j], st[1][j], st[2][j], st[3][j]);
        }
        v
    }

    #[inline]
    unsafe fn unpack4(v: __m128i) -> [u32; 4] {
        let mut t = [0u32; 4];
        _mm_storeu_si128(t.as_mut_ptr() as *mut __m128i, v);
        t
    }

    #[inline(always)]
    unsafe fn rol1(x: __m128i) -> __m128i {
        _mm_or_si128(_mm_slli_epi32(x, 1), _mm_srli_epi32(x, 31))
    }

    #[inline(always)]
    unsafe fn rol5(x: __m128i) -> __m128i {
        _mm_or_si128(_mm_slli_epi32(x, 5), _mm_srli_epi32(x, 27))
    }

    #[inline(always)]
    unsafe fn rol30(x: __m128i) -> __m128i {
        _mm_or_si128(_mm_slli_epi32(x, 30), _mm_srli_epi32(x, 2))
    }

    /// one 4-way compression over the fixed 20-byte-message template:
    /// w[0..4] = msg (per-lane state words), w[5] = 0x80000000,
    /// w[6..13] = 0, w[14] = 0, w[15] = 672.
    #[inline]
    unsafe fn compress20(st: &mut [__m128i; 5], msg: &[__m128i; 5]) {
        let zero = _mm_setzero_si128();
        let pad = _mm_set1_epi32(0x8000_0000u32 as i32);
        let len672 = _mm_set1_epi32(672);
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
                    w[$i & 15] = rol1(_mm_xor_si128(
                        _mm_xor_si128(w[($i + 13) & 15], w[($i + 8) & 15]),
                        _mm_xor_si128(w[($i + 2) & 15], w[$i & 15]),
                    ));
                }
                let f = if $i < 20 {
                    _mm_or_si128(
                        _mm_and_si128(b, c),
                        _mm_andnot_si128(b, d),
                    )
                } else if $i < 40 {
                    _mm_xor_si128(_mm_xor_si128(b, c), d)
                } else if $i < 60 {
                    _mm_or_si128(
                        _mm_or_si128(_mm_and_si128(b, c), _mm_and_si128(b, d)),
                        _mm_and_si128(c, d),
                    )
                } else {
                    _mm_xor_si128(_mm_xor_si128(b, c), d)
                };
                let k = _mm_set1_epi32(
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
                let t = _mm_add_epi32(
                    w[$i & 15],
                    _mm_add_epi32(
                        rol5(a),
                        _mm_add_epi32(f, _mm_add_epi32(e, k)),
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

        st[0] = _mm_add_epi32(st[0], a);
        st[1] = _mm_add_epi32(st[1], b);
        st[2] = _mm_add_epi32(st[2], c);
        st[3] = _mm_add_epi32(st[3], d);
        st[4] = _mm_add_epi32(st[4], e);
    }

    /// the serial 999-iteration chain for four lanes at once.
    unsafe fn chain4(
        ia: &[__m128i; 5],
        oa: &[__m128i; 5],
        u1: &[__m128i; 5],
    ) -> [__m128i; 5] {
        let mut u = *u1;
        let mut acc = *u1;
        for _ in 0..999 {
            let mut inner = *ia;
            compress20(&mut inner, &u);
            let mut outer = *oa;
            compress20(&mut outer, &inner);
            u = outer;
            for j in 0..5 {
                acc[j] = _mm_xor_si128(acc[j], u[j]);
            }
        }
        acc
    }

    /// verify four candidates (flat, in order) against one member;
    /// returns the pass flags in lane order = candidate order.
    pub unsafe fn group4(
        group: &[u8],
        lens: &[u32],
        salt_words: &[u32],
        nb: u32,
        r: usize,
        pv: u16,
    ) -> [bool; 4] {
        let mut offs = [0usize; 5];
        for l in 0..4 {
            offs[l + 1] = offs[l] + lens[l] as usize;
        }
        let mut st = [[0u32; 5]; 12]; // [0..4]=ia, [4..8]=oa, [8..12]=u1
        for l in 0..4 {
            let s: Setup = setup(&group[offs[l]..offs[l + 1]], salt_words, nb);
            st[l] = s.ia;
            st[4 + l] = s.oa;
            st[8 + l] = s.u1;
        }
        let ia = transpose_states(&st[0..4].try_into().unwrap());
        let oa = transpose_states(&st[4..8].try_into().unwrap());
        let u1 = transpose_states(&st[8..12].try_into().unwrap());
        let acc_v = chain4(&ia, &oa, &u1);

        let mut acc = [[0u32; 5]; 4];
        for (j, v) in acc_v.iter().enumerate() {
            let t = unpack4(*v);
            for l in 0..4 {
                acc[l][j] = t[l];
            }
        }
        let mut passes = [false; 4];
        for (l, slot) in passes.iter_mut().enumerate() {
            *slot = gather(&acc[l], r) == pv;
        }
        passes
    }
}

#[cfg(target_arch = "x86_64")]
pub use fourway::group4;

/// non-x86_64 builds run the scalar reference per candidate.
#[cfg(not(target_arch = "x86_64"))]
pub fn group4(
    group: &[u8],
    lens: &[u32],
    salt_words: &[u32],
    nb: u32,
    r: usize,
    pv: u16,
) -> [bool; 4] {
    let mut offs = [0usize; 5];
    for l in 0..4 {
        offs[l + 1] = offs[l] + lens[l] as usize;
    }
    let mut passes = [false; 4];
    for l in 0..4 {
        passes[l] = crate::verify_one(&group[offs[l]..offs[l + 1]], salt_words, nb, r, pv);
    }
    passes
}
