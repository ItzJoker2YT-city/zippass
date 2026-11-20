// aescrack.goose - winzip aes (ae-1/ae-2) password verifier + brute forcer,
// written in goose. the hot algorithm is the same folded last-block pbkdf2
// as rust/aesfast_rs: only the last output block is ever compared and each
// block is independent, so one candidate costs 2*1000+2 sha1 compressions
// instead of openssl's full-dklen chain (aes-256: 2002 vs 16000 blocks).
//
// run self tests (no args, or fewer than the brute form needs):
//   goose aescrack.goose
// brute force:
//   goose aescrack.goose <salt_hex> <dklen> <pv_hex> <charset> <min> <max>
// e.g.
//   goose aescrack.goose 000102030405060708090a0b0c0d0e0f 66 47a1 abcdefghijklmnopqrstuvwxyz0123456789 1 3
//
// this is the scalar reference port - no simd yet. the selftest vectors
// were computed with python hashlib.pbkdf2_hmac (1000 iterations).

import std;
import os;

// ---------------------------------------------------------------- sha1 core

fn rol(x: u32, n: i32) -> u32 {
    return (x << n) | (x >> (32 - n));
}

// one compression over w[0..16] (big-endian message words); expands the
// schedule in place and folds the result into h[0..5]. the length asserts
// let the bounds-check eliminator drop the per-access checks in the loop.
fn sha_block(h: u32[:], w: u32[:]) {
    assert(h.len == 5 && w.len == 80);
    for i in 16..80 {
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    // four constant-K loops instead of per-round branches: the sha1 round
    // function and constant are fixed within each 20-round block
    for i in 20 {
        let t = rol(a, 5) + ((b & c) | (~b & d)) + e + 0x5A827999 + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    for i in 20..40 {
        let t = rol(a, 5) + (b ^ c ^ d) + e + 0x6ED9EBA1 + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    for i in 40..60 {
        let t = rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    for i in 60..80 {
        let t = rol(a, 5) + (b ^ c ^ d) + e + 0xCA62C1D6 + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

fn init_state(h: u32[:]) {
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;
}

fn cp5(src: u32[:], dst: u32[:]) {
    for i in 5 { dst[i] = src[i]; }
}

// general digest of an arbitrary byte string -> 5 big-endian state words.
// used only for >64-byte hmac keys and the selftest's reference checks.
fn sha_digest(msg: u8[:], out: u32[:]) {
    var h: u32[5] = [0; 5];
    init_state(h);
    var w: u32[80] = [0; 80];
    let total = msg.len;
    let nblk = (total + 9 + 63) / 64;
    for blk in nblk {
        for i in 16 { w[i] = 0; }
        for j in 64 {
            let idx = blk * 64 + j;
            var byte: u32 = 0;
            if idx < total { byte = msg[idx] as u32; }
            else if idx == total { byte = 0x80; }
            w[j / 4] |= byte << (24 - 8 * (j % 4));
        }
        if blk == nblk - 1 {
            let bits = total * 8;
            w[14] = (bits / 4294967296) as u32;
            w[15] = (bits % 4294967296) as u32;
        }
        sha_block(h, w);
    }
    cp5(h, out);
}

// ---------------------------------------------------------- hmac, folded

// precompute the post-ipad / post-opad sha1 states for one password.
fn hmac_setup(key: u8[:], ia: u32[:], oa: u32[:]) {
    var k: u8[64] = [0; 64];
    if key.len > 64 {
        var kh: u32[5] = [0; 5];
        sha_digest(key, kh);
        for i in 5 {
            k[i * 4] = (kh[i] >> 24) as u8;
            k[i * 4 + 1] = (kh[i] >> 16) as u8;
            k[i * 4 + 2] = (kh[i] >> 8) as u8;
            k[i * 4 + 3] = kh[i] as u8;
        }
    } else {
        for i in key.len { k[i] = key[i]; }
    }
    var w: u32[80] = [0; 80];
    for j in 64 {
        let b = (k[j] as u32) ^ 0x36;
        w[j / 4] |= b << (24 - 8 * (j % 4));
    }
    init_state(ia);
    sha_block(ia, w);
    for i in 16 { w[i] = 0; }
    for j in 64 {
        let b = (k[j] as u32) ^ 0x5C;
        w[j / 4] |= b << (24 - 8 * (j % 4));
    }
    init_state(oa);
    sha_block(oa, w);
}

// u1's message: salt || INT32_BE(block_index), one padded sha1 block.
// salt.len + 4 must be <= 55 (salt <= 48); real archives carry 8/12/16.
fn salt_msg(salt: u8[:], nb: i64, w: u32[:]) {
    for i in 16 { w[i] = 0; }
    let m = salt.len + 4;
    for j in m {
        var b: u32 = 0;
        if j < salt.len { b = salt[j] as u32; }
        else { b = ((nb as u32) >> (24 - 8 * (j - salt.len))) & 255; }
        w[j / 4] |= b << (24 - 8 * (j % 4));
    }
    w[m / 4] |= (0x80 as u32) << (24 - 8 * (m % 4));
    // the length field covers the implicit 64-byte ipad prefix too:
    // the inner message is ipad || salt || index, not salt || index alone
    w[15] = ((64 + m) * 8) as u32;
}

// the serial chain's fixed 20-byte message: five state words + padding.
fn chain_msg(u: u32[:], w: u32[:]) {
    for i in 16 { w[i] = 0; }
    for i in 5 { w[i] = u[i]; }
    w[5] = 0x80000000;
    w[15] = 672;                       // (64 + 20) * 8
}

// folded last-block pbkdf2-hmac-sha1 verifier for one candidate.
// returns true when the candidate's last-two-derived-bytes equal pv.
fn verify(pwd: u8[:], salt: u8[:], dklen: i64, pv: u32) -> bool {
    var ia: u32[5] = [0; 5];
    var oa: u32[5] = [0; 5];
    hmac_setup(pwd, ia, oa);
    let nb = (dklen + 19) / 20;
    let r = dklen - 20 * (nb - 1);
    var w: u32[80] = [0; 80];
    var inner: u32[5] = [0; 5];
    var u: u32[5] = [0; 5];
    var acc: u32[5] = [0; 5];

    salt_msg(salt, nb, w);             // u1 = hmac(pw, salt || int32(nb))
    cp5(ia, inner);
    sha_block(inner, w);
    chain_msg(inner, w);
    cp5(oa, u);
    sha_block(u, w);
    cp5(u, acc);

    var u2: u32[5] = [0; 5];
    for k in 999 {
        cp5(ia, inner);
        chain_msg(u, w);
        sha_block(inner, w);
        chain_msg(inner, w);
        cp5(oa, u2);
        sha_block(u2, w);
        cp5(u2, u);
        for j in 5 { acc[j] ^= u2[j]; }
    }

    // verifier = bytes [r-2, r-1] of the accumulated block, big-endian
    let off = r - 2;
    let wj = off / 4;
    let sh = 24 - 8 * (off % 4);
    let hi = (acc[wj] >> sh) & 255;
    let lo: u32 = if off % 4 == 3 { (acc[wj + 1] >> 24) & 255 }
                  else { (acc[wj] >> (sh - 8)) & 255 };
    return ((hi << 8) | lo) == pv;
}

// ---------------------------------------------------------------- helpers

fn hexval(c: u8) -> i32 {
    if c >= '0' && c <= '9' { return (c - '0') as i32; }
    if c >= 'a' && c <= 'f' { return (c - 'a') as i32 + 10; }
    if c >= 'A' && c <= 'F' { return (c - 'A') as i32 + 10; }
    return -1;
}

// decode up to out.len bytes of hex; returns bytes written, or -1 on junk.
fn unhex(s: u8[:], out: u8[:]) -> i32 {
    if s.len % 2 != 0 || s.len / 2 > out.len { return -1; }
    for i in s.len / 2 {
        let hi = hexval(s[i * 2]);
        let lo = hexval(s[i * 2 + 1]);
        if hi < 0 || lo < 0 { return -1; }
        out[i] = (hi * 16 + lo) as u8;
    }
    return (s.len / 2) as i32;
}

fn parse_dec(s: u8[:]) -> i64 {
    var v: i64 = 0;
    for c in s {
        if c < '0' || c > '9' { return -1; }
        v = v * 10 + (c - '0') as i64;
    }
    return v;
}

// ---------------------------------------------------------------- selftest

fn expect(label: u8[:], pwd: u8[:], salt_hex: u8[:], dklen: i64, pv: u32, fails: i32&) {
    var salt: u8[64] = [0; 64];
    let n = unhex(salt_hex, salt);
    if n < 0 { print("bad salt hex in test ", label); fails++; return; }
    let ok = verify(pwd, salt[..n], dklen, pv);
    if !ok { fails++; }
    print(if ok { "PASS " } else { "FAIL " }, label);
}

fn selftest() {
    var fails: i32 = 0;
    // first: the raw sha1 core against the classic known-answer vectors
    var d: u32[5] = [0; 5];
    sha_digest("abc", d);
    if d[0] == 0xA9993E36 && d[1] == 0x4706816A && d[2] == 0xBA3E2571
        && d[3] == 0x7850C26C && d[4] == 0x9CD0D89D { print("PASS sha1(abc)"); }
    else { fails++; print("FAIL sha1(abc): ", d); }
    sha_digest("", d);
    if d[0] == 0xDA39A3EE && d[1] == 0x5E6B4B0D && d[2] == 0x3255BFEF
        && d[3] == 0x95601890 && d[4] == 0xAFD80709 { print("PASS sha1(empty)"); }
    else { fails++; print("FAIL sha1(empty): ", d); }
    // vectors from hashlib.pbkdf2_hmac('sha1', pwd, salt, 1000, dklen)[-2:]
    expect("salt16/dklen66 mana", "mana",
           "000102030405060708090a0b0c0d0e0f", 66, 0x71e7, fails);
    expect("salt16/dklen66 q9z", "q9z",
           "000102030405060708090a0b0c0d0e0f", 66, 0x9d27, fails);
    expect("salt8/dklen34 key>64 (hashed down)", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
           "0001020304050607", 34, 0xaed8, fails);
    expect("salt12/dklen50 empty password", "",
           "000102030405060708090a0b", 50, 0x743d, fails);
    expect("salt16/dklen66 mz7", "mz7",
           "000102030405060708090a0b0c0d0e0f", 66, 0x47a1, fails);
    // negative control: the same case with a wrong pv must not verify
    var salt: u8[16] = [0; 16];
    for i in 16 { salt[i] = i as u8; }
    if verify("mana", salt, 66, 0x0000) { fails++; print("FAIL negative control"); }
    else { print("PASS negative control"); }
    if fails == 0 { print("selftest: all vectors match hashlib"); }
    else { print("selftest: ", fails, " FAILURES"); }
}

// ---------------------------------------------------------------- brute

fn brute(charset: u8[:], minl: i64, maxl: i64, salt: u8[:], dklen: i64, pv: u32) {
    let base = charset.len;
    var tried: i64 = 0;
    var hits: i64 = 0;
    let t0 = clock();
    for L in minl..maxl + 1 {
        var space: i64 = 1;
        for i in L { space *= base; }
        print("length ", L, ": ", space, " candidates");
        var pwd: u8[64] = [0; 64];
        for idx in space {
            var x = idx;
            for j in L { pwd[L - 1 - j] = charset[x % base]; x = x / base; }
            tried++;
            if verify(pwd[..L], salt, dklen, pv) {
                hits++;
                print("HIT index=", tried - 1, " pwd=", pwd[..L]);
            }
            if tried % 20000 == 0 {
                let el = clock() - t0;
                print("tried=", tried, " elapsed=", el, "s rate=",
                      (tried as f64) / el, "/s hits=", hits);
            }
        }
    }
    let el = clock() - t0;
    print("done: tried=", tried, " hits=", hits, " elapsed=", el,
          "s rate=", (tried as f64) / el, "/s");
}

fn main() {
    let argv = args();
    if argv.len < 7 {
        selftest();
        return;
    }
    var salt: u8[64] = [0; 64];
    let n = unhex(argv[1], salt);
    if n <= 0 || n > 48 || n % 4 != 0 {
        print("salt must be 4..48 bytes of hex, multiple of 4");
        return;
    }
    let dklen = parse_dec(argv[2]);
    var pvb: u8[2] = [0; 2];
    if unhex(argv[3], pvb) != 2 || dklen < 2 {
        print("bad dklen or pv");
        return;
    }
    let pv = (pvb[0] as u32) * 256 + (pvb[1] as u32);
    let minl = parse_dec(argv[5]);
    let maxl = parse_dec(argv[6]);
    if minl < 0 || maxl < minl || maxl > 64 || argv[4].len == 0 {
        print("bad charset/lengths (max 64)");
        return;
    }
    print("brute: dklen=", dklen, " charset=", argv[4].len,
          " chars, lengths ", minl, "..", maxl);
    brute(argv[4], minl, maxl, salt[..n], dklen, pv);
}
