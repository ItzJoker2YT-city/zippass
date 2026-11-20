// aescrack.goose - winzip aes (ae-1/ae-2) password verifier + brute forcer,
// written in goose, multithreaded (default 4 workers, one per core).
//
// the hot algorithm is the folded last-block pbkdf2 of rust/aesfast_rs:
// only the last output block is compared and each block is independent,
// so one candidate costs 2*1000+2 sha1 compressions instead of openssl's
// full-dklen chain (aes-256: 2002 vs 16000 blocks). the sha1 core uses a
// 16-word ring schedule and fixed-array references (no slice overhead in
// the round loop).
//
// threading model: the global candidate space (ascending length, last
// position fastest) is split into N contiguous shards; each worker is a
// separate goose program with its own memory, fed one flat Job through a
// typed queue. hits carry the exact global candidate index, so results
// are order-identical to a single-threaded scan.
//
//   selftest:            aescrack.exe
//   brute (4 threads):   aescrack.exe <salt_hex> <dklen> <pv_hex> <charset> <min> <max> [threads]
//
// selftest vectors computed with python hashlib.pbkdf2_hmac (1000 iters).

import std;
import os;

// ---------------------------------------------------------------- sha1 core

fn rol(x: u32, n: i32) -> u32 {
    return (x << n) | (x >> (32 - n));
}

// one compression over the ring w[0..16] (big-endian message words).
// fixed-array reference params: indices are statically in range, so the
// bounds-check eliminator has nothing left to charge the round loop for.
fn sha_block(h: u32[5]&, w: u32[16]&) {
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    // four constant-K loops; the schedule updates the ring in place
    for i in 20 {
        if i >= 16 {
            w[i & 15] = rol(w[(i + 13) & 15] ^ w[(i + 8) & 15]
                            ^ w[(i + 2) & 15] ^ w[i & 15], 1);
        }
        let t = rol(a, 5) + ((b & c) | (~b & d)) + e + 0x5A827999 + w[i & 15];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    for i in 20..40 {
        w[i & 15] = rol(w[(i + 13) & 15] ^ w[(i + 8) & 15]
                        ^ w[(i + 2) & 15] ^ w[i & 15], 1);
        let t = rol(a, 5) + (b ^ c ^ d) + e + 0x6ED9EBA1 + w[i & 15];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    for i in 40..60 {
        w[i & 15] = rol(w[(i + 13) & 15] ^ w[(i + 8) & 15]
                        ^ w[(i + 2) & 15] ^ w[i & 15], 1);
        let t = rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC + w[i & 15];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    for i in 60..80 {
        w[i & 15] = rol(w[(i + 13) & 15] ^ w[(i + 8) & 15]
                        ^ w[(i + 2) & 15] ^ w[i & 15], 1);
        let t = rol(a, 5) + (b ^ c ^ d) + e + 0xCA62C1D6 + w[i & 15];
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

fn init_state(h: u32[5]&) {
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;
}

fn cp5(src: u32[5]&, dst: u32[5]&) {
    for i in 5 { dst[i] = src[i]; }
}

// general digest of an arbitrary byte string -> 5 big-endian state words.
// used for >64-byte hmac keys and the selftest's known-answer checks.
fn sha_digest(msg: u8[:], out: u32[5]&) {
    var h: u32[5] = [0; 5];
    init_state(h);
    var w: u32[16] = [0; 16];
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
fn hmac_setup(key: u8[:], ia: u32[5]&, oa: u32[5]&) {
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
    var w: u32[16] = [0; 16];
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
fn salt_msg(salt: u8[:], nb: i64, w: u32[16]&) {
    for i in 16 { w[i] = 0; }
    let m = salt.len + 4;
    for j in m {
        var b: u32 = 0;
        if j < salt.len { b = salt[j] as u32; }
        else { b = ((nb as u32) >> (24 - 8 * (j - salt.len))) & 255; }
        w[j / 4] |= b << (24 - 8 * (j % 4));
    }
    w[m / 4] |= (0x80 as u32) << (24 - 8 * (m % 4));
    // the length field covers the implicit 64-byte ipad prefix too
    w[15] = ((64 + m) * 8) as u32;
}

// the serial chain's fixed 20-byte message: five state words + padding.
fn chain_msg(u: u32[5]&, w: u32[16]&) {
    for i in 16 { w[i] = 0; }
    for i in 5 { w[i] = u[i]; }
    w[5] = 0x80000000;
    w[15] = 672;                       // (64 + 20) * 8
}

// folded last-block pbkdf2-hmac-sha1 verifier for one candidate.
fn verify(pwd: u8[:], salt: u8[:], dklen: i64, pv: u32) -> bool {
    var ia: u32[5] = [0; 5];
    var oa: u32[5] = [0; 5];
    hmac_setup(pwd, ia, oa);
    let nb = (dklen + 19) / 20;
    let r = dklen - 20 * (nb - 1);
    var w: u32[16] = [0; 16];
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
    var salt: u8[16] = [0; 16];
    for i in 16 { salt[i] = i as u8; }
    if verify("mana", salt, 66, 0x0000) { fails++; print("FAIL negative control"); }
    else { print("PASS negative control"); }
    if fails == 0 { print("selftest: all vectors match hashlib"); }
    else { print("selftest: ", fails, " FAILURES"); }
}

// ---------------------------------------------------------------- threading

// flat values only: queues memcpy them between programs, so every field is
// fixed-size. a Job is one worker's whole shard; a Msg is a hit, a progress
// delta, or the worker's final delta (kind 1 / 0 / 2).
struct Job {
    salt: u8[64], salt_len: i64, dklen: i64, pv: u32,
    charset: u8[64], cs_len: i64, minl: i64, maxl: i64,
    start: i64, count: i64, shard: i32,
}
struct Msg {
    kind: i32 = 0, shard: i32 = 0, index: i64 = 0,
    tried: i64 = 0, pwd: u8[64] = [0; 64], pwd_len: i32 = 0,
}

fn imax(a: i64, b: i64) -> i64 { if a > b { a } else { b } }
fn imin(a: i64, b: i64) -> i64 { if a < b { a } else { b } }

thread_fn cracker() {
    let job = qget<Job>();
    var tried: i64 = 0;
    var reported: i64 = 0;
    var base_idx: i64 = 0;           // global index of the length segment start
    for L in job.minl..job.maxl + 1 {
        var space: i64 = 1;
        for i in L { space *= job.cs_len; }
        let lo = imax(job.start, base_idx);
        let hi = imin(job.start + job.count, base_idx + space);
        if hi > lo {
            var pwd: u8[64] = [0; 64];
            for gi in lo..hi {
                var x = gi - base_idx;
                for j in L { pwd[L - 1 - j] = job.charset[x % job.cs_len]; x = x / job.cs_len; }
                if verify(pwd[..L], job.salt[..job.salt_len], job.dklen, job.pv) {
                    qput(Msg { kind: 1, shard: job.shard, index: gi,
                               pwd: pwd, pwd_len: L as i32 });
                }
                tried++;
                if tried - reported >= 50000 {
                    qput(Msg { kind: 0, shard: job.shard, tried: tried - reported });
                    reported = tried;
                }
            }
        }
        base_idx += space;
    }
    qput(Msg { kind: 2, shard: job.shard, tried: tried - reported });
}

// total candidates in the whole space
fn space_total(cs: i64, minl: i64, maxl: i64) -> i64 {
    var total: i64 = 0;
    for L in minl..maxl + 1 {
        var space: i64 = 1;
        for i in L { space *= cs; }
        total += space;
    }
    return total;
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
    var cs: u8[64] = [0; 64];
    if minl < 0 || maxl < minl || maxl > 64 || argv[4].len == 0 || argv[4].len > 64 {
        print("bad charset/lengths (max 64)");
        return;
    }
    for i in argv[4].len { cs[i] = argv[4][i]; }
    let cs_len = argv[4].len;
    var nthreads: i64 = 4;
    if argv.len >= 8 { nthreads = parse_dec(argv[7]); }
    if nthreads < 1 || nthreads > 64 { nthreads = 4; }

    let total = space_total(cs_len, minl, maxl);
    let t0 = clock();
    print("brute: ", total, " candidates on ", nthreads, " threads");
    var ids: i64[>..] = [];
    let per = total / nthreads;
    let rem = total % nthreads;
    for t in nthreads {
        let start = t * per + imin(t, rem);
        let count = per + (if t < rem { 1 } else { 0 });
        qput(Job { salt: salt, salt_len: n, dklen: dklen, pv: pv,
                   charset: cs, cs_len: cs_len, minl: minl, maxl: maxl,
                   start: start, count: count, shard: t as i32 });
        ids.push(thread_spawn(cracker));
    }
    var tried_total: i64 = 0;
    var done: i64 = 0;
    var hits: i64 = 0;
    while done < nthreads {
        let m = qget<Msg>();
        tried_total += m.tried;
        if m.kind == 1 {
            hits++;
            print("HIT index=", m.index, " pwd=", m.pwd[..m.pwd_len],
                  " (shard ", m.shard, ")");
        } else if m.kind == 2 {
            done++;
            print("shard ", m.shard, " done");
        } else {
            let el = clock() - t0;
            print("tried=", tried_total, " elapsed=", el, "s rate=",
                  (tried_total as f64) / el, "/s hits=", hits);
        }
    }
    let el = clock() - t0;
    print("done: tried=", tried_total, " hits=", hits, " elapsed=", el,
          "s aggregate rate=", (tried_total as f64) / el, "/s");
}
