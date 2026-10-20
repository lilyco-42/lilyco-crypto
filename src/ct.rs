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
/// 任一方含非法十六进制字符时返回 `false`，但仍走完整长度以保持时间一致。
pub fn eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut acc = 0u8;
    // 单独记录「出现过非法字符」。不能只靠 0xFF 标记——
    // 两边同为非法时 0xFF ^ 0xFF = 0，会被误判为相等。
    let mut bad = 0u8;

    for (x, y) in a.bytes().zip(b.bytes()) {
        match (lower_hex(x), lower_hex(y)) {
            (Some(xn), Some(yn)) => acc |= xn ^ yn,
            _ => bad = 1,
        }
    }

    // 用 subtle 判定，避免被优化成提前返回。
    let equal: bool = acc.ct_eq(&0u8).into();
    let clean: bool = bad.ct_eq(&0u8).into();
    equal & clean
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
        for (i, _) in base.iter().enumerate() {
            let mut other = *base;
            other[i] ^= 0x01;
            assert!(!eq(base, &other), "position {i}");
        }
    }
}
