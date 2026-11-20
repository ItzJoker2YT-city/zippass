//! sha-ni backend (intel/amd sha extensions, e.g. this ryzen 3500u):
//! single-stream sha1 with hardware round instructions - sha1rnds4 does
//! four rounds per instruction and sha1msg1/msg2 expand the schedule, so
//! one compression costs ~20 instruction groups instead of 80 scalar
//! rounds. one candidate's pbkdf2 chain stays serial; the folded states
//! (ipad/opad/u1) reuse the scalar setup, only the 999-iteration chain
//! (1998 of the 2002 compressions per candidate) runs here.
//!
//! layouts (from the intel pseudocode): abcd = A in the high dword, D in
//! the low dword; message words W0 in the high dword after a full 16-byte
//! reversal shuffle. nexte's first operand is the state A from two groups
//! back, so a rolling `prev` copy is kept: at group g, prev = A_{4(g-1)}.
//! correctness is pinned by a known-answer test against the scalar core
//! (sha1::compress) and by the python hashlib equivalence suite on the
//! default dispatch path.

#[cfg(target_arch = "x86_64")]
pub(crate) mod ni {
    use crate::{gather, setup, Setup};
    use std::arch::x86_64::*;

    /// one sha1 compression over the 16 big-endian message words, folded
    /// into h (h = h + compress(msg)). the round/schedule sequence is a
    /// verbatim port of noloader's public-domain sha1-x86.c (intel sample).
    pub unsafe fn compress_ni(h: &mut [u32; 5], msg: &[u32; 16]) {
        let mut buf = [0u8; 64];
        for i in 0..16 {
            buf[4 * i..4 * i + 4].copy_from_slice(&msg[i].to_be_bytes());
        }
        let mask = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);
        let state = [h[0], h[1], h[2], h[3]];
        let mut abcd = _mm_shuffle_epi32(
            _mm_loadu_si128(state.as_ptr() as *const __m128i), 0x1B);
        let mut e0 = _mm_set_epi32(h[4] as i32, 0, 0, 0);
        let abcd_save = abcd;
        let e0_save = e0;
        let mut e1;

        // rounds 0-3
        let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(buf.as_ptr() as *const __m128i), mask);
        e0 = _mm_add_epi32(e0, m0);
        e1 = abcd;
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
        // rounds 4-7
        let mut m1 = _mm_shuffle_epi8(
            _mm_loadu_si128(buf.as_ptr().add(16) as *const __m128i), mask);
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        // rounds 8-11
        let mut m2 = _mm_shuffle_epi8(
            _mm_loadu_si128(buf.as_ptr().add(32) as *const __m128i), mask);
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);
        // rounds 12-15
        let mut m3 = _mm_shuffle_epi8(
            _mm_loadu_si128(buf.as_ptr().add(48) as *const __m128i), mask);
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);
        // rounds 16-19
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);
        // rounds 20-23
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        m3 = _mm_xor_si128(m3, m1);
        // rounds 24-27
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);
        // rounds 28-31
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);
        // rounds 32-35
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);
        // rounds 36-39
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        m3 = _mm_xor_si128(m3, m1);
        // rounds 40-43
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);
        // rounds 44-47
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);
        // rounds 48-51
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);
        // rounds 52-55
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        m3 = _mm_xor_si128(m3, m1);
        // rounds 56-59
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);
        // rounds 60-63
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);
        // rounds 64-67
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);
        // rounds 68-71
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
        m3 = _mm_xor_si128(m3, m1);
        // rounds 72-75
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
        // rounds 76-79
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);

        // combine state
        e0 = _mm_sha1nexte_epu32(e0, e0_save);
        abcd = _mm_add_epi32(abcd, abcd_save);
        abcd = _mm_shuffle_epi32(abcd, 0x1B);
        let mut out = [0u32; 4];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, abcd);
        h[0] = out[0];
        h[1] = out[1];
        h[2] = out[2];
        h[3] = out[3];
        h[4] = _mm_extract_epi32(e0, 3) as u32;
    }

    /// the serial 999-iteration chain on hardware rounds.
    pub(crate) unsafe fn chain_ni(s: &Setup) -> [u32; 5] {
        let mut w = [0u32; 16];
        let mut u = s.u1;
        let mut acc = u;
        for _ in 0..999 {
            w[0..5].copy_from_slice(&u);
            w[5] = 0x8000_0000;
            for j in 6..15 {
                w[j] = 0;
            }
            w[15] = 672;
            let mut inner = s.ia;
            compress_ni(&mut inner, &w);
            w[0..5].copy_from_slice(&inner);
            w[5] = 0x8000_0000;
            for j in 6..15 {
                w[j] = 0;
            }
            w[15] = 672;
            let mut u2 = s.oa;
            compress_ni(&mut u2, &w);
            u = u2;
            for j in 0..5 {
                acc[j] ^= u[j];
            }
        }
        acc
    }

    /// same verdict as crate::verify_one, on the sha-ni chain.
    pub fn verify_ni(pwd: &[u8], salt_words: &[u32], nb: u32, r: usize, pv: u16) -> bool {
        let s: Setup = setup(pwd, salt_words, nb);
        let acc = unsafe { chain_ni(&s) };
        gather(&acc, r) == pv
    }

    /// two candidates, one interleaved chain: the sha1rnds4/nexte latency
    /// of one lane is hidden under the other lane's independent ops -
    /// single-stream sha-ni is latency-bound, pairs are the throughput win.
    /// returns the two accumulated t_nb states for gather().
    pub unsafe fn chain2_ni(sa: &Setup, sb: &Setup) -> [[u32; 5]; 2] {
        let mut acc = [sa.u1, sb.u1];
        let mut u = [sa.u1, sb.u1];
        // per-iteration state: abcd/e0/e1 hold the *inner* stream's folded
        // start; after each inner+outer pair the next iteration restarts
        // from the folded ia/oa states, reloaded per lane below.
        let mask = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);
        for _ in 0..999 {
            // ---------------- inner compression (both lanes interleaved)
            let mut m0 = [_mm_setzero_si128(); 2];
            let mut m1 = [_mm_setzero_si128(); 2];
            let mut m2 = [_mm_setzero_si128(); 2];
            let mut m3 = [_mm_setzero_si128(); 2];
            let mut ia = [_mm_setzero_si128(); 2];
            let mut oa = [_mm_setzero_si128(); 2];
            let mut ie0 = [_mm_setzero_si128(); 2];
            let mut ie1 = [_mm_setzero_si128(); 2];
            let mut oe0 = [_mm_setzero_si128(); 2];
            let mut oe1 = [_mm_setzero_si128(); 2];
            let mut ia_save = [_mm_setzero_si128(); 2];
            let mut oa_save = [_mm_setzero_si128(); 2];
            let mut ie0_save = [_mm_setzero_si128(); 2];
            let mut oe0_save = [_mm_setzero_si128(); 2];
            let mut buf = [[0u8; 64]; 2];
            for l in 0..2 {
                let s = if l == 0 { sa } else { sb };
                ia[l] = _mm_shuffle_epi32(
                    _mm_loadu_si128(s.ia.as_ptr() as *const __m128i), 0x1B);
                ie0[l] = _mm_set_epi32(s.ia[4] as i32, 0, 0, 0);
                ie1[l] = ia[l];
                oa[l] = _mm_shuffle_epi32(
                    _mm_loadu_si128(s.oa.as_ptr() as *const __m128i), 0x1B);
                oe0[l] = _mm_set_epi32(s.oa[4] as i32, 0, 0, 0);
                oe1[l] = oa[l];
                ia_save[l] = ia[l];
                oa_save[l] = oa[l];
                ie0_save[l] = ie0[l];
                oe0_save[l] = oe0[l];
                for i in 0..16 {
                    let word = if i < 5 { u[l][i] } else if i == 5 { 0x8000_0000 }
                        else if i == 15 { 672 } else { 0 };
                    buf[l][4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
                }
            }
            // inner block (ia) for both lanes
            for l in 0..2 { m0[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr() as *const __m128i), mask); }
            for l in 0..2 { ie0[l] = _mm_add_epi32(ie0[l], m0[l]); }
            for l in 0..2 { ie1[l] = ia[l]; }
            for l in 0..2 { ia[l] = _mm_sha1rnds4_epu32(ia[l], ie0[l], 0); }
            for l in 0..2 { m1[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr().add(16) as *const __m128i), mask); }
            for l in 0..2 { ie1[l] = _mm_sha1nexte_epu32(ie1[l], m1[l]); }
            for l in 0..2 { ie0[l] = ia[l]; }
            for l in 0..2 { ia[l] = _mm_sha1rnds4_epu32(ia[l], ie1[l], 0); }
            for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); }
            for l in 0..2 { m2[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr().add(32) as *const __m128i), mask); }
            for l in 0..2 { ie0[l] = _mm_sha1nexte_epu32(ie0[l], m2[l]); }
            for l in 0..2 { ie1[l] = ia[l]; }
            for l in 0..2 { ia[l] = _mm_sha1rnds4_epu32(ia[l], ie0[l], 0); }
            for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); }
            for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); }
            for l in 0..2 { m3[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr().add(48) as *const __m128i), mask); }
            for l in 0..2 { ie1[l] = _mm_sha1nexte_epu32(ie1[l], m3[l]); }
            for l in 0..2 { ie0[l] = ia[l]; }
            for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); }
            for l in 0..2 { ia[l] = _mm_sha1rnds4_epu32(ia[l], ie1[l], 0); }
            for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); }
            for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); }
            // schedule ring for rounds 16..79 (same sequence as the sample)
            macro_rules! grp {
                ($e:ident, $o:ident, $mm:ident, $upd:expr, $f:expr) => {
                    for l in 0..2 { $e[l] = _mm_sha1nexte_epu32($e[l], $mm[l]); }
                    for l in 0..2 { $o[l] = ia[l]; }
                    $upd
                    for l in 0..2 { ia[l] = _mm_sha1rnds4_epu32(ia[l], $e[l], $f); }
                };
            }
            grp!(ie0, ie1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 0);
            grp!(ie1, ie0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 1);
            grp!(ie0, ie1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); } for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); } }, 1);
            grp!(ie1, ie0, m3, { for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); } for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); } for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); } }, 1);
            grp!(ie0, ie1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 1);
            grp!(ie1, ie0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 1);
            grp!(ie0, ie1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); } for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); } }, 2);
            grp!(ie1, ie0, m3, { for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); } for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); } for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); } }, 2);
            grp!(ie0, ie1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 2);
            grp!(ie1, ie0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 2);
            grp!(ie0, ie1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); } for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); } }, 2);
            grp!(ie1, ie0, m3, { for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); } for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); } for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); } }, 3);
            grp!(ie0, ie1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 3);
            grp!(ie1, ie0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 3);
            grp!(ie0, ie1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } }, 3);
            grp!(ie1, ie0, m3, {}, 3);
            // inner digest words per lane -> message of the outer block.
            // feed-forward FIRST: digest = working state + initial state.
            let mut inner_words = [[0u32; 5]; 2];
            for l in 0..2 {
                ia[l] = _mm_add_epi32(ia[l], ia_save[l]);
                let tmp = _mm_shuffle_epi32(ia[l], 0x1B);
                let mut out = [0u32; 4];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, tmp);
                // E of the inner digest: nexte(prev, initial E)
                ie0[l] = _mm_sha1nexte_epu32(ie0[l], ie0_save[l]);
                inner_words[l] = [out[0], out[1], out[2], out[3],
                                  _mm_extract_epi32(ie0[l], 3) as u32];
            }
            // ---------------- outer compression (oa), same round sequence
            for l in 0..2 {
                for i in 0..16 {
                    let word = if i < 5 { inner_words[l][i] } else if i == 5 { 0x8000_0000 }
                        else if i == 15 { 672 } else { 0 };
                    buf[l][4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
                }
            }
            for l in 0..2 { m0[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr() as *const __m128i), mask); }
            for l in 0..2 { oe0[l] = _mm_add_epi32(oe0[l], m0[l]); }
            for l in 0..2 { oe1[l] = oa[l]; }
            for l in 0..2 { oa[l] = _mm_sha1rnds4_epu32(oa[l], oe0[l], 0); }
            for l in 0..2 { m1[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr().add(16) as *const __m128i), mask); }
            for l in 0..2 { oe1[l] = _mm_sha1nexte_epu32(oe1[l], m1[l]); }
            for l in 0..2 { oe0[l] = oa[l]; }
            for l in 0..2 { oa[l] = _mm_sha1rnds4_epu32(oa[l], oe1[l], 0); }
            for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); }
            for l in 0..2 { m2[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr().add(32) as *const __m128i), mask); }
            for l in 0..2 { oe0[l] = _mm_sha1nexte_epu32(oe0[l], m2[l]); }
            for l in 0..2 { oe1[l] = oa[l]; }
            for l in 0..2 { oa[l] = _mm_sha1rnds4_epu32(oa[l], oe0[l], 0); }
            for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); }
            for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); }
            for l in 0..2 { m3[l] = _mm_shuffle_epi8(_mm_loadu_si128(buf[l].as_ptr().add(48) as *const __m128i), mask); }
            for l in 0..2 { oe1[l] = _mm_sha1nexte_epu32(oe1[l], m3[l]); }
            for l in 0..2 { oe0[l] = oa[l]; }
            for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); }
            for l in 0..2 { oa[l] = _mm_sha1rnds4_epu32(oa[l], oe1[l], 0); }
            for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); }
            for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); }
            macro_rules! grpo {
                ($e:ident, $o:ident, $mm:ident, $upd:expr, $f:expr) => {
                    for l in 0..2 { $e[l] = _mm_sha1nexte_epu32($e[l], $mm[l]); }
                    for l in 0..2 { $o[l] = oa[l]; }
                    $upd
                    for l in 0..2 { oa[l] = _mm_sha1rnds4_epu32(oa[l], $e[l], $f); }
                };
            }
            grpo!(oe0, oe1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 0);
            grpo!(oe1, oe0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 1);
            grpo!(oe0, oe1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); } for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); } }, 1);
            grpo!(oe1, oe0, m3, { for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); } for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); } for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); } }, 1);
            grpo!(oe0, oe1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 1);
            grpo!(oe1, oe0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 1);
            grpo!(oe0, oe1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); } for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); } }, 2);
            grpo!(oe1, oe0, m3, { for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); } for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); } for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); } }, 2);
            grpo!(oe0, oe1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 2);
            grpo!(oe1, oe0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m0[l] = _mm_sha1msg1_epu32(m0[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 2);
            grpo!(oe0, oe1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } for l in 0..2 { m1[l] = _mm_sha1msg1_epu32(m1[l], m2[l]); } for l in 0..2 { m0[l] = _mm_xor_si128(m0[l], m2[l]); } }, 2);
            grpo!(oe1, oe0, m3, { for l in 0..2 { m0[l] = _mm_sha1msg2_epu32(m0[l], m3[l]); } for l in 0..2 { m2[l] = _mm_sha1msg1_epu32(m2[l], m3[l]); } for l in 0..2 { m1[l] = _mm_xor_si128(m1[l], m3[l]); } }, 3);
            grpo!(oe0, oe1, m0, { for l in 0..2 { m1[l] = _mm_sha1msg2_epu32(m1[l], m0[l]); } for l in 0..2 { m3[l] = _mm_sha1msg1_epu32(m3[l], m0[l]); } for l in 0..2 { m2[l] = _mm_xor_si128(m2[l], m0[l]); } }, 3);
            grpo!(oe1, oe0, m1, { for l in 0..2 { m2[l] = _mm_sha1msg2_epu32(m2[l], m1[l]); } for l in 0..2 { m3[l] = _mm_xor_si128(m3[l], m1[l]); } }, 3);
            grpo!(oe0, oe1, m2, { for l in 0..2 { m3[l] = _mm_sha1msg2_epu32(m3[l], m2[l]); } }, 3);
            grpo!(oe1, oe0, m3, {}, 3);
            // u = outer digest; acc ^= u, per lane (feed-forward first)
            for l in 0..2 {
                oa[l] = _mm_add_epi32(oa[l], oa_save[l]);
                let tmp = _mm_shuffle_epi32(oa[l], 0x1B);
                let mut out = [0u32; 4];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, tmp);
                oe0[l] = _mm_sha1nexte_epu32(oe0[l], oe0_save[l]);
                let e_last = _mm_extract_epi32(oe0[l], 3) as u32;
                u[l] = [out[0], out[1], out[2], out[3], e_last];
                for j in 0..5 {
                    acc[l][j] ^= u[l][j];
                }
            }
        }
        acc
    }

    /// verify two candidates on the interleaved chain; flags in lane order.
    pub fn verify2_ni(
        pa: &[u8], pb: &[u8], salt_words: &[u32], nb: u32, r: usize, pv: u16,
    ) -> [bool; 2] {
        let sa = setup(pa, salt_words, nb);
        let sb = setup(pb, salt_words, nb);
        let acc = unsafe { chain2_ni(&sa, &sb) };
        [gather(&acc[0], r) == pv, gather(&acc[1], r) == pv]
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    #[test]
    fn debug_abc_block() {
        if !std::is_x86_feature_detected!("sha") {
            return;
        }
        let mut w = [0u32; 16];
        w[0] = 0x6162_6380;               // "abc" + pad
        w[15] = 24;
        let w_orig = w;                   // scalar compress mutates w in place
        let mut a = crate::sha1::INIT;
        let mut b = a;
        crate::sha1::compress(&mut a, &mut w);
        unsafe { super::ni::compress_ni(&mut b, &w_orig) };
        println!("scalar: {a:08X?}");
        println!("ni:     {b:08X?}");
        // expected: A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
    }

    #[test]
    fn ni_compression_matches_scalar_on_random_blocks() {
        if !std::is_x86_feature_detected!("sha") {
            return;
        }
        let mut seed = 0x1234_5678u32;
        for t in 0..64 {
            let mut w = [0u32; 16];
            for x in w.iter_mut() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *x = seed;
            }
            let mut a = crate::sha1::INIT;
            let mut b = a;
            let w_orig = w;               // scalar compress mutates w in place
            crate::sha1::compress(&mut a, &mut w);
            unsafe { super::ni::compress_ni(&mut b, &w_orig) };
            assert_eq!(a, b, "sha-ni vs scalar mismatch at vector {t}");
        }
    }

    #[test]
    fn chain2_matches_single_chain() {
        if !std::is_x86_feature_detected!("sha") {
            return;
        }
        let salt_words = [0x0001_0203u32, 0x0405_0607, 0x0809_0A0B, 0x0C0D_0E0F];
        let sa = crate::setup(b"mana", &salt_words, 4);
        let sb = crate::setup(b"q9z", &salt_words, 4);
        let acc2 = unsafe { super::ni::chain2_ni(&sa, &sb) };
        let acc_a = unsafe { super::ni::chain_ni(&sa) };
        let acc_b = unsafe { super::ni::chain_ni(&sb) };
        assert_eq!(acc2[0], acc_a, "pair lane 0 diverged from single chain");
        assert_eq!(acc2[1], acc_b, "pair lane 1 diverged from single chain");
    }
}
