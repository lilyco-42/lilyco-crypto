//! `lilyco-crypto` —— 基于 RustCrypto 官方实现的 `no_std` 密码学工具箱。
//!
//! # 设计原则
//!
//! **不自己实现密码学。** MD5、SHA-256、HMAC 全部来自
//! [RustCrypto](https://github.com/RustCrypto)，这些 crate 经过审计、被数百万项目使用。
//! 本库只做三件事：
//!
//! 1. **提供爱发电签名**这类业务封装（[`afdian`]）。
//! 2. **常量时间比较**（[`ct`]），包装 `subtle`。
//! 3. **卡密生成与校验**（[`keys`]），组合 HMAC 与自定义编码。
//!
//! # 为什么依赖而不是自写
//!
//! 自己写哈希函数的风险不在「算得对不对」——标准向量能测出来；
//! 而在**侧信道**：内存访问模式、分支预测、编译器优化掉清零逻辑。
//! 这些不会体现在测试里，只会体现在被攻破时。
//!
//! # 安全边界
//!
//! 本库**不做**密钥管理、不防物理侧信道。熵由调用方提供，
//! 或通过 `os-rng` feature 从操作系统取得。

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod afdian;
pub mod ct;
pub mod keys;

/// 重新导出底层原语，方便调用方避免版本不一致。
pub use hmac;
pub use md5;
pub use sha2;
pub use subtle;

/// 本库版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
