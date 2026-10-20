//! 卡密生成与校验。
//!
//! 形如 `PDBP-ABCD-EFGH-IJKM`。校验位由 HMAC-SHA256 截断而成，
//! HMAC 来自 `hmac` crate（RustCrypto）。
//!
//! # 设计
//!
//! * **字母表 32 字符**，去掉 `0/O/1/I/L` 等易混字符。32 = 2^5，
//!   每个字符恰好 5 比特，编码无取模偏差。
//! * **校验位**。最后 4 位是前 8 位的 HMAC 截断，输错一位立刻发现，
//!   不用查数据库。
//! * **熵由调用方提供**。`no_std` 环境熵源质量不一，本模块不假设，
//!   统一用 [`crate::keys::generate_with_os_entropy`] 或自行传入。

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// HMAC-SHA256 类型别名。
type HmacSha256 = Hmac<Sha256>;

/// 卡密字母表：32 个字符。
///
/// 从 0-9 + A-Z 共 36 个里去掉 `0`、`O`、`1`、`I` 四个易混字符。
/// 保留 `L`（它与 `1` 才会混，而 `1` 已被去掉）。
///
/// 32 = 2^5，每个字符恰好 5 比特，编码不需要取模偏差处理。
pub const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// 每组字符数。
pub const GROUP_LEN: usize = 4;
/// 数据组数。
pub const DATA_GROUPS: usize = 2;
/// 总组数（数据 + 校验）。
pub const TOTAL_GROUPS: usize = DATA_GROUPS + 1;
/// 裸卡密长度（不含前缀与连字符）。
pub const BODY_LEN: usize = GROUP_LEN * TOTAL_GROUPS;
/// 需要的熵字节数。
pub const ENTROPY_LEN: usize = GROUP_LEN * DATA_GROUPS;

/// 失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// 熵不足。
    NotEnoughEntropy,
    /// 输出缓冲太小。
    BufferTooSmall,
    /// 前缀含非大写字母。
    BadPrefix,
    /// 系统熵源失败。
    Entropy,
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyError::NotEnoughEntropy => write!(f, "熵不足"),
            KeyError::BufferTooSmall => write!(f, "输出缓冲区太小"),
            KeyError::BadPrefix => write!(f, "前缀只允许大写字母"),
            KeyError::Entropy => write!(f, "系统熵源失败"),
        }
    }
}

/// 计算校验组。
fn checksum(prefix: &[u8], data: &[u8], secret: &[u8], out: &mut [u8; GROUP_LEN]) {
    // new_from_slice 来自 KeyInit；HMAC 接受任意长度 key。
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret).expect("HMAC 接受任意长度 key");

    let mut msg = [0u8; 16];
    let mut len = 0;
    for &b in prefix.iter().chain(data.iter()) {
        if len < msg.len() {
            msg[len] = b;
            len += 1;
        }
    }
    mac.update(&msg[..len]);
    let tag = mac.finalize().into_bytes();

    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ALPHABET[(tag[i] as usize) & 31];
    }
}

/// 用给定熵生成裸卡密（无前缀无连字符）。
pub fn generate(
    prefix: &[u8],
    entropy: &[u8],
    secret: &[u8],
    out: &mut [u8],
) -> Result<usize, KeyError> {
    if prefix.iter().any(|c| !c.is_ascii_uppercase()) {
        return Err(KeyError::BadPrefix);
    }
    if entropy.len() < ENTROPY_LEN {
        return Err(KeyError::NotEnoughEntropy);
    }
    if out.len() < BODY_LEN {
        return Err(KeyError::BufferTooSmall);
    }

    let mut data = [0u8; ENTROPY_LEN];
    for i in 0..ENTROPY_LEN {
        data[i] = ALPHABET[(entropy[i] as usize) & 31];
    }

    let mut check = [0u8; GROUP_LEN];
    checksum(prefix, &data, secret, &mut check);

    out[..ENTROPY_LEN].copy_from_slice(&data);
    out[ENTROPY_LEN..BODY_LEN].copy_from_slice(&check);
    Ok(BODY_LEN)
}

/// 从系统熵源取随机数并生成卡密。
///
/// 需要 `os-rng` feature。裸机 target 没有 getrandom 后端，
/// 那种环境下请用 [`generate`] 自行传入熵。
#[cfg(feature = "os-rng")]
pub fn generate_with_os_entropy(
    prefix: &[u8],
    secret: &[u8],
    out: &mut [u8],
) -> Result<usize, KeyError> {
    let mut entropy = [0u8; ENTROPY_LEN];
    getrandom::fill(&mut entropy).map_err(|_| KeyError::Entropy)?;
    generate(prefix, &entropy, secret, out)
}

/// 格式化为 `PDBP-XXXX-XXXX-XXXX`。
pub fn format(prefix: &[u8], body: &[u8], out: &mut [u8]) -> Result<usize, KeyError> {
    if prefix.iter().any(|c| !c.is_ascii_uppercase()) {
        return Err(KeyError::BadPrefix);
    }
    if body.len() != BODY_LEN {
        return Err(KeyError::BufferTooSmall);
    }
    let total = prefix.len() + 1 + BODY_LEN + (TOTAL_GROUPS - 1);
    if out.len() < total {
        return Err(KeyError::BufferTooSmall);
    }

    let mut n = 0;
    for &c in prefix {
        out[n] = c;
        n += 1;
    }
    out[n] = b'-';
    n += 1;

    for (i, &c) in body.iter().enumerate() {
        if i > 0 && i % GROUP_LEN == 0 {
            out[n] = b'-';
            n += 1;
        }
        out[n] = c;
        n += 1;
    }
    Ok(n)
}

/// 校验格式与校验位。不查数据库。
pub fn verify(prefix: &[u8], key: &[u8], secret: &[u8]) -> bool {
    if prefix.iter().any(|c| !c.is_ascii_uppercase()) {
        return false;
    }

    // 去连字符
    let mut body = [0u8; BODY_LEN];
    let mut n = 0;
    for &c in key {
        if c == b'-' {
            continue;
        }
        if n >= BODY_LEN {
            return false;
        }
        body[n] = c;
        n += 1;
    }
    if n != BODY_LEN {
        return false;
    }

    // 前缀
    let mut i = 0;
    for &p in prefix {
        if i >= BODY_LEN || body[i] != p {
            return false;
        }
        i += 1;
    }

    let rest = &body[i..];
    if rest.len() != ENTROPY_LEN + GROUP_LEN {
        return false;
    }

    let mut expected = [0u8; GROUP_LEN];
    checksum(prefix, &rest[..ENTROPY_LEN], secret, &mut expected);

    crate::ct::eq(&expected, &rest[ENTROPY_LEN..])
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;

    const SECRET: &[u8] = b"test-secret-do-not-use-in-prod";

    fn make(prefix: &[u8], entropy: &[u8]) -> [u8; BODY_LEN] {
        let mut body = [0u8; BODY_LEN];
        generate(prefix, entropy, SECRET, &mut body).unwrap();
        body
    }

    #[test]
    fn shape_is_correct() {
        let body = make(b"PDBP", b"12345678");
        assert!(body.iter().all(|c| ALPHABET.contains(c)));
    }

    #[test]
    fn format_has_three_dashes() {
        let body = make(b"PDBP", b"12345678");
        let mut out = [0u8; 40];
        let n = format(b"PDBP", &body, &mut out).unwrap();
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert_eq!(s.matches('-').count(), 3);
        assert!(s.starts_with("PDBP-"));
        assert_eq!(s.len(), 19);
    }

    #[test]
    fn roundtrip() {
        let body = make(b"PDBP", b"12345678");
        assert!(verify(b"PDBP", &body, SECRET));

        let mut out = [0u8; 40];
        let n = format(b"PDBP", &body, &mut out).unwrap();
        assert!(verify(b"PDBP", &out[..n], SECRET));
    }

    #[test]
    fn rejects_tampered_checksum() {
        let mut body = make(b"PDBP", b"12345678");
        let last = body[BODY_LEN - 1];
        body[BODY_LEN - 1] = if last == b'Z' { b'Y' } else { b'Z' };
        assert!(!verify(b"PDBP", &body, SECRET));
    }

    #[test]
    fn rejects_tampered_data() {
        let mut body = make(b"PDBP", b"12345678");
        body[0] = if body[0] == b'Z' { b'Y' } else { b'Z' };
        assert!(!verify(b"PDBP", &body, SECRET));
    }

    #[test]
    fn rejects_wrong_secret() {
        let body = make(b"PDBP", b"12345678");
        assert!(!verify(b"PDBP", &body, b"other-secret"));
    }

    #[test]
    fn rejects_wrong_prefix() {
        let body = make(b"PDBP", b"12345678");
        assert!(!verify(b"ABCD", &body, SECRET));
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(!verify(b"PDBP", b"PDBP-2345-6789", SECRET));
        assert!(!verify(b"PDBP", b"PDBP-2345-6789-ABCD-EXTRA", SECRET));
        assert!(!verify(b"PDBP", b"", SECRET));
    }

    #[test]
    fn different_entropy_gives_different_key() {
        assert_ne!(make(b"PDBP", b"11111111"), make(b"PDBP", b"22222222"));
    }

    #[test]
    fn same_entropy_is_deterministic() {
        assert_eq!(make(b"PDBP", b"abcdefgh"), make(b"PDBP", b"abcdefgh"));
    }

    #[test]
    fn errors() {
        let mut out = [0u8; BODY_LEN];
        assert_eq!(
            generate(b"PDBP", b"123", SECRET, &mut out),
            Err(KeyError::NotEnoughEntropy)
        );
        let mut small = [0u8; 4];
        assert_eq!(
            generate(b"PDBP", b"12345678", SECRET, &mut small),
            Err(KeyError::BufferTooSmall)
        );
        assert_eq!(
            generate(b"pdbp", b"12345678", SECRET, &mut out),
            Err(KeyError::BadPrefix)
        );
        assert_eq!(
            generate(b"PD1P", b"12345678", SECRET, &mut out),
            Err(KeyError::BadPrefix)
        );
    }

    #[test]
    fn alphabet_excludes_confusables() {
        // 去掉 0/O/1/I 四个：0 与 O、1 与 I 手抄会混。
        // L 保留——它与 1 才会混，而 1 已去掉。
        for bad in [b'0', b'O', b'1', b'I'] {
            assert!(!ALPHABET.contains(&bad), "不该包含 {}", bad as char);
        }
        assert_eq!(ALPHABET.len(), 32);
        // 每个字符必须唯一，否则熵会损失。
        for i in 0..ALPHABET.len() {
            for j in (i + 1)..ALPHABET.len() {
                assert_ne!(ALPHABET[i], ALPHABET[j], "字母表有重复字符");
            }
        }
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn os_entropy_produces_valid_key() {
        let mut body = [0u8; BODY_LEN];
        generate_with_os_entropy(b"PDBP", SECRET, &mut body).unwrap();
        assert!(verify(b"PDBP", &body, SECRET));
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn os_entropy_is_not_repeating() {
        let mut a = [0u8; BODY_LEN];
        let mut b = [0u8; BODY_LEN];
        generate_with_os_entropy(b"PDBP", SECRET, &mut a).unwrap();
        generate_with_os_entropy(b"PDBP", SECRET, &mut b).unwrap();
        assert_ne!(a, b, "两次生成不应相同");
    }
}
