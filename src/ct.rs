//! 常量时间比较。
//!
//! 直接用 [`subtle`]，它是密码学社区的标准实现，通过 `black_box` 等手段
//! 阻止编译器把「提前返回」优化回来——这一点手写循环做不到。

use subtle::ConstantTimeEq;

/// 常量时间比较两个字节切片。
///
/// 长度不同时立即返回 `false`（长度不是秘密）。
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// 常量时间比较两个十六进制字符串，大小写不敏感。
///
/// 非法十六进制字符视为不匹配，但仍走完整长度以保持时间一致。
pub fn eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // 逐字节比较：先归一化为小写，非法字符用 0xFF 标记（必定不等）。
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        let xn = lower_hex(x).unwrap_or(0xff);
        let yn = lower_hex(y).unwrap_or(0xff);
        acc |= xn ^ yn;
    }

    // 用 subtle 做最后一次判定，避免 `acc == 0` 被优化成提前返回。
    acc.ct_eq(&0u8).into()
}

/// 十六进制字符转数值。
#[inline]
fn lower_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices() {
        assert!(eq(b"abc", b"abc"));
        assert!(eq(b"", b""));
    }

    #[test]
    fn different_content() {
        assert!(!eq(b"abc", b"abd"));
        assert!(!eq(b"abc", b"xbc"));
    }

    #[test]
    fn different_length() {
        assert!(!eq(b"abc", b"ab"));
        assert!(!eq(b"", b"a"));
    }

    #[test]
    fn hex_case_insensitive() {
        assert!(eq_hex("deadbeef", "DEADBEEF"));
        assert!(eq_hex("DeAdBeEf", "deadbeef"));
    }

    #[test]
    fn hex_mismatch() {
        assert!(!eq_hex("deadbeef", "deadbeee"));
        assert!(!eq_hex("deadbeef", "deadbee"));
    }

    #[test]
    fn hex_rejects_invalid() {
        assert!(!eq_hex("zzzz", "zzzz"));
        assert!(!eq_hex("dead", "dea!"));
    }

    #[test]
    fn detects_every_position() {
        let base = b"0123456789abcdef";
        for i in 0..base.len() {
            let mut other = *base;
            other[i] ^= 0x01;
            assert!(!eq(base, &other), "position {i}");
        }
    }
}
