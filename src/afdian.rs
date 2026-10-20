//! 爱发电开放接口签名。
//!
//! 算法：`sign = md5(token + "params" + params_json + "ts" + ts + "user_id" + user_id)`。
//!
//! MD5 来自 `md-5` crate（RustCrypto），本模块只负责拼接与十六进制编码。

use md5::{Digest, Md5};

/// 一次请求的签名材料。
#[derive(Debug, Clone, Copy)]
pub struct SigningInput<'a> {
    /// 爱发电后台 API token。
    pub token: &'a str,
    /// 创作者 user_id。
    pub user_id: &'a str,
    /// 紧凑 JSON（无空格，中文不转义）。
    pub params: &'a str,
    /// 秒级时间戳。
    pub ts: u64,
}

impl<'a> SigningInput<'a> {
    /// 拼出待签名原文。顺序必须与官方一致。
    pub fn payload(&self) -> alloc_or_array::Buf {
        let ts = self.ts;
        let mut buf = alloc_or_array::Buf::new();
        buf.push_str(self.token);
        buf.push_str("params");
        buf.push_str(self.params);
        buf.push_str("ts");
        buf.push_u64(ts);
        buf.push_str("user_id");
        buf.push_str(self.user_id);
        buf
    }

    /// 计算 `sign`，返回 32 字节小写十六进制。
    ///
    /// 返回固定长度数组，不分配。
    pub fn sign(&self) -> [u8; 32] {
        let payload = self.payload();
        let digest = Md5::digest(payload.as_slice());
        let mut out = [0u8; 32];
        for (i, byte) in digest.iter().enumerate() {
            out[i * 2] = hex_char(byte >> 4);
            out[i * 2 + 1] = hex_char(byte & 0x0f);
        }
        out
    }

    /// 计算 `sign`，返回 `&str` 视图（借用内部缓冲）。
    pub fn sign_str(&self) -> Hex32 {
        Hex32(self.sign())
    }
}

/// 十六进制字符。
#[inline]
fn hex_char(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

/// 32 字节十六进制字符串的 `Display` 包装。
#[derive(Clone, Copy)]
pub struct Hex32([u8; 32]);

impl Hex32 {
    /// 取字节视图。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for Hex32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{}", b as char)?;
        }
        Ok(())
    }
}

/// 定长缓冲：no_std 下不分配，超出容量则截断。
///
/// 爱发电的 payload 通常不到 2 KB，4 KB 足够；超长说明参数有问题，
/// 截断会让签名必然失败，这比静默分配更安全。
mod alloc_or_array {
    /// 缓冲容量。
    pub const CAP: usize = 4096;

    /// 定长字节缓冲。
    pub struct Buf {
        data: [u8; CAP],
        len: usize,
    }

    impl Buf {
        /// 新建空缓冲。
        pub const fn new() -> Self {
            Buf {
                data: [0u8; CAP],
                len: 0,
            }
        }

        /// 追加字符串，超出容量则截断。
        pub fn push_str(&mut self, s: &str) {
            let bytes = s.as_bytes();
            let room = CAP - self.len;
            let take = if bytes.len() < room { bytes.len() } else { room };
            self.data[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
        }

        /// 追加十进制无符号整数。
        pub fn push_u64(&mut self, mut n: u64) {
            if n == 0 {
                self.push_str("0");
                return;
            }
            let mut tmp = [0u8; 20];
            let mut i = tmp.len();
            while n > 0 {
                i -= 1;
                tmp[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            let s = core::str::from_utf8(&tmp[i..]).unwrap_or("");
            self.push_str(s);
        }

        /// 取已写入内容。
        pub fn as_slice(&self) -> &[u8] {
            &self.data[..self.len]
        }

        /// 已写入长度。
        pub fn len(&self) -> usize {
            self.len
        }

        /// 是否为空。
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;

    fn sign_hex(input: &SigningInput<'_>) -> String {
        let mut s = String::new();
        for b in input.sign() {
            s.push(b as char);
        }
        s
    }

    #[test]
    fn payload_order_is_fixed() {
        let s = SigningInput {
            token: "T",
            user_id: "U",
            params: "{}",
            ts: 1,
        };
        assert_eq!(s.payload().as_slice(), b"Tparams{}ts1user_idU");
    }

    #[test]
    fn sign_is_32_hex() {
        let s = SigningInput {
            token: "PLACEHOLDER_TOKEN",
            user_id: "PLACEHOLDER_USER_ID",
            params: "{}",
            ts: 1792510000,
        };
        let hex = sign_hex(&s);
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_matches_manual_md5() {
        // 用 md-5 直接算，验证拼接逻辑没引入偏差。
        let input = SigningInput {
            token: "tok",
            user_id: "uid",
            params: r#"{"page":1}"#,
            ts: 1700000000,
        };
        let payload = "tokparams{\"page\":1}ts1700000000user_iduid";
        let expect = Md5::digest(payload.as_bytes());
        let mut expect_hex = String::new();
        for b in expect.iter() {
            expect_hex.push_str(&std::format!("{b:02x}"));
        }
        assert_eq!(sign_hex(&input), expect_hex);
    }

    #[test]
    fn sign_depends_on_every_field() {
        let base = SigningInput {
            token: "t",
            user_id: "u",
            params: "{}",
            ts: 1,
        };
        let base_sig = base.sign();

        let other_token = SigningInput {
            token: "t2",
            ..base
        };
        let other_user = SigningInput { user_id: "u2", ..base };
        let other_params = SigningInput { params: "[]", ..base };
        let other_ts = SigningInput { ts: 2, ..base };

        assert_ne!(base_sig, other_token.sign());
        assert_ne!(base_sig, other_user.sign());
        assert_ne!(base_sig, other_params.sign());
        assert_ne!(base_sig, other_ts.sign());
    }

    #[test]
    fn cjk_params_are_utf8_bytes() {
        // 中文参数必须按 UTF-8 字节参与计算，不能转义成 \uXXXX。
        let input = SigningInput {
            token: "t",
            user_id: "u",
            params: r#"{"name":"中文"}"#,
            ts: 1,
        };
        let payload = input.payload();
        assert!(payload.as_slice().windows(3).any(|w| w == "中".as_bytes()));
        assert_eq!(sign_hex(&input).len(), 32);
    }

    #[test]
    fn buffer_truncates_instead_of_overflowing() {
        let long = "x".repeat(5000);
        let input = SigningInput {
            token: &long,
            user_id: "u",
            params: "{}",
            ts: 1,
        };
        let payload = input.payload();
        assert_eq!(payload.len(), alloc_or_array::CAP);
        // 截断后签名仍然产出合法形状，只是与官方不同。
        assert_eq!(sign_hex(&input).len(), 32);
    }

    #[test]
    fn display_matches_bytes() {
        let input = SigningInput {
            token: "t",
            user_id: "u",
            params: "{}",
            ts: 1,
        };
        let h = input.sign_str();
        let disp = std::format!("{h}");
        assert_eq!(disp.as_bytes(), h.as_bytes());
        assert_eq!(disp.len(), 32);
    }
}
