# lilyco-crypto

`no_std` 密码学工具箱，基于 [RustCrypto](https://github.com/RustCrypto) 官方实现。

> **本仓库禁止本地编译与运行。** 所有构建、测试与产物都在 GitHub Actions 上完成。

## 核心原则：不自己写密码学

MD5、SHA-256、HMAC 全部来自 RustCrypto。本库只做三件事：

1. **爱发电签名**封装（业务逻辑）
2. **常量时间比较**（包装 `subtle`）
3. **卡密生成与校验**（组合 HMAC 与自定义编码）

### 为什么

自己写哈希函数的风险不在「算得对不对」，标准向量能测出来。风险在**侧信道**：

| 问题 | 测试能否发现 |
| --- | --- |
| 内存访问模式泄露密钥 | ❌ |
| 分支预测泄露比较结果 | ❌ |
| 编译器把清零逻辑优化掉 | ❌ |
| 结果算错 | ✅ |

前三项只在被攻破时暴露。RustCrypto 的 crate 经过审计、被数百万项目使用，这些坑别人已经踩过。

## 依赖

| crate | 用途 | no-std |
| --- | --- | --- |
| `md-5` | MD5（爱发电签名兼容） | ✅ |
| `sha2` | SHA-256 | ✅ |
| `hmac` | HMAC-SHA256 | ✅ |
| `subtle` | 常量时间比较 | ✅ |
| `getrandom` | 系统熵源 | ✅ |

全部标注 `no-std` 分类。

## 用法

### 爱发电签名

```rust
use lilyco_crypto::afdian::SigningInput;

let input = SigningInput {
    token: "你的token",
    user_id: "你的user_id",
    params: r#"{"page":1}"#,
    ts: 1700000000,
};
let sign = input.sign();          // [u8; 32]，十六进制
println!("{}", input.sign_str()); // 直接打印
```

签名结果用定长数组返回，**不分配**。payload 超过 4 KB 会截断——这会让签名必然失败，比静默分配更安全。

### 常量时间比较

```rust
use lilyco_crypto::ct;

// 比较 MAC，防止计时攻击
if ct::eq(expected_mac, received_mac) {
    // 通过
}

// 比较十六进制字符串，大小写不敏感
if ct::eq_hex("deadbeef", "DEADBEEF") { }
```

### 卡密

```rust
use lilyco_crypto::keys;

let secret = b"你的密钥至少16字节";

// 从系统熵源生成
let mut body = [0u8; keys::BODY_LEN];
keys::generate_with_os_entropy(b"PDBP", secret, &mut body)?;

// 格式化为 PDBP-XXXX-XXXX-XXXX
let mut out = [0u8; 40];
let n = keys::format(b"PDBP", &body, &mut out)?;

// 校验（不查数据库）
assert!(keys::verify(b"PDBP", &out[..n], secret));
```

卡密设计：

- **字母表 32 字符**，去掉 `0/O/1/I/L`，用户手抄不会错
- **校验位**是前 8 位的 HMAC 截断，输错一位立刻发现
- **熵由调用方提供**，`no_std` 环境熵源质量不一，本库不假设

## 安装

```bash
cargo binstall lilyco-crypto
```

一条命令装好 `keygen`，不编译。

> 库本身不需要安装——在 `Cargo.toml` 里加
> `lilyco-crypto = "0.1.1"` 即可。`keygen` 二进制需要 `os-rng` feature，
> 但 `cargo install` 默认不带，所以推荐用 `binstall`。

## CLI

```bash
export KEYGEN_SECRET=$(head -c 32 /dev/urandom | base64)

keygen gen PDBP 5              # 生成 5 个
keygen verify PDBP-ABCD-EFGH-IJKM
```

`KEYGEN_SECRET` 至少 16 字节，泄露等于所有卡密可伪造。

产物见 [Releases](https://github.com/lilyco-42/lilyco-crypto/releases)，
命名约定 `keygen-{target triple}`，由 `[package.metadata.binstall]` 描述。

## no_std 是怎么验证的

不是嘴上说的。CI 里有独立的 `no_std` job，编到裸机 target：

```
thumbv7em-none-eabihf           Cortex-M4F
thumbv6m-none-eabi              Cortex-M0
riscv32imac-unknown-none-elf    RISC-V 32
```

这些 target 根本没有 `std`，链接器找不到就直接失败。同时跑 `--no-default-features`（无 `alloc`）和 `--features alloc` 两种配置。

## 开发

**不要本地编译。** 改完推上去等 CI：

```bash
git add -A && git commit -m "..." && git push
gh run watch
```

CI 会跑：

- 三平台测试（Linux / Windows / macOS）
- 格式检查 + Clippy（`-D warnings`）
- 三个裸机 target 的 `no_std` 编译
- 四个平台的 `keygen` 产物

打 tag 自动发 Release。

## 安全边界

本库**不做**：

- 密钥管理（你自己保管 `KEYGEN_SECRET`）
- 物理侧信道防护（功耗、电磁、缓存时序）
- 随机数质量保证（依赖 `getrandom` 的平台后端）

## 许可

[MIT](LICENSE)

