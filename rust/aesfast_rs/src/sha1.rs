//! scalar sha1 primitives: one compression over a 16-word window, plus a
//! full digest for hmac keys longer than 64 bytes.

pub const INIT: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

/// one sha1 compression: `state += f(block)`; `w` holds the block's 16
/// big-endian message words and is clobbered by the in-window schedule.
#[inline(always)]
pub fn compress(state: &mut [u32; 5], w: &mut [u32; 16]) {
    let (mut a, mut b, mut c, mut d, mut e) =
        (state[0], state[1], state[2], state[3], state[4]);

    macro_rules! round {
        ($i:expr) => {{
            if $i >= 16 {
                w[$i & 15] = (w[($i + 13) & 15] ^ w[($i + 8) & 15]
                    ^ w[($i + 2) & 15] ^ w[$i & 15])
                    .rotate_left(1);
            }
            let f = if $i < 20 {
                (b & c) | (!b & d)
            } else if $i < 40 {
                b ^ c ^ d
            } else if $i < 60 {
                (b & c) | (b & d) | (c & d)
            } else {
                b ^ c ^ d
            };
            let k = if $i < 20 {
                0x5A82_7999u32
            } else if $i < 40 {
                0x6ED9_EBA1
            } else if $i < 60 {
                0x8F1B_BCDC
            } else {
                0xCA62_C1D6
            };
            let t = w[$i & 15]
                .wrapping_add(a.rotate_left(5))
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }};
    }

    macro_rules! rounds8 {
        ($base:expr) => {
            round!($base);
            round!($base + 1);
            round!($base + 2);
            round!($base + 3);
            round!($base + 4);
            round!($base + 5);
            round!($base + 6);
            round!($base + 7);
        };
    }

    rounds8!(0);
    rounds8!(8);
    rounds8!(16);
    rounds8!(24);
    rounds8!(32);
    rounds8!(40);
    rounds8!(48);
    rounds8!(56);
    rounds8!(64);
    rounds8!(72);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// `sha1(msg)` as its 5 state words (the digest, unpacked big-endian).
pub fn digest(msg: &[u8]) -> [u32; 5] {
    let n = msg.len();
    let nblk = (n + 9 + 63) / 64;
    let mut st = INIT;
    let mut w = [0u32; 16];
    for bi in 0..nblk {
        let off = bi * 64;
        for j in 0..16 {
            let mut v = 0u32;
            for t in 0..4 {
                let p = off + 4 * j + t;
                v = (v << 8) | (msg.get(p).copied().unwrap_or(0)) as u32;
            }
            w[j] = v;
        }
        if bi == nblk - 1 {
            // 8-byte length field in the final block
            w[14] = 0;
            w[15] = (n as u32) * 8;
        }
        // the 0x80 pad byte lives where message byte n would be - that
        // block may be nblk-2 when the last block holds 56..63 bytes
        if off <= n && n < off + 64 {
            let pos = n - off;
            w[pos >> 2] ^= 0x80u32 << (8 * (3 - (pos & 3)));
        }
        compress(&mut st, &mut w);
    }
    st
}

/// hmac key as the 16 big-endian words of the zero-padded 64-byte key
/// block; keys longer than 64 bytes hash down first.
pub fn key_block_words(pwd: &[u8]) -> [u32; 16] {
    let mut w = [0u32; 16];
    if pwd.len() > 64 {
        let d = digest(pwd);
        w[0..5].copy_from_slice(&d);
        return w;
    }
    for (j, chunk) in pwd.chunks(4).enumerate() {
        let mut v = 0u32;
        for (t, byte) in chunk.iter().enumerate() {
            v |= (*byte as u32) << (8 * (3 - t));
        }
        w[j] = v;
    }
    w
}
