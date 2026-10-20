# AGENTS.md

给在本仓库工作的 AI agent 和人类的硬性规则。

## 第一条：不自己写密码学

**禁止**手写任何密码学原语的实现：

```
❌ MD5 压缩函数
❌ SHA-256 轮函数
❌ HMAC 的 ipad/opad 构造
❌ 常量时间比较循环
❌ 随机数生成器
```

需要什么就从 RustCrypto 引什么：

| 需求 | 用 |
| --- | --- |
| MD5 | `md-5` |
| SHA-256 / SHA-512 | `sha2` |
| HMAC | `hmac` |
| 常量时间比较 | `subtle` |
| 随机数 | `getrandom` |
| AEAD | `aes-gcm` / `chacha20poly1305` |
| 公钥 | `ed25519-dalek` / `p256` |

### 为什么这条最重要

手写实现「能算对」不难——标准向量一测就知道。难的是：

- **内存访问模式**不泄露密钥
- **分支预测**不泄露比较结果
- **编译器优化**不会把清零逻辑删掉
- **侧信道**在共享 CPU 上不泄露

这些都不会体现在测试里。自己写的代码看起来过了测试，实际上可能是个计时攻击的靶子。

RustCrypto 的 crate 经过审计，被数百万项目使用。用它们不是偷懒，是**降低风险**。

### 唯一例外

业务封装可以自己写：

```
✅ 爱发电的 payload 拼接顺序
✅ 卡密的字母表与分组格式
✅ 十六进制编码
✅ 错误类型定义
```

这些是**协议逻辑**，不是密码学原语。

## 第二条：禁止本地编译与运行

**不要**在本机执行：

```bash
cargo build
cargo run
cargo test
cargo clippy
cargo fmt
```

原因：

1. 本机没有完整交叉编译环境，裸机 target 编不了
2. `cargo build` 会写几百 MB 到 `~/.cargo` 和 `target/`
3. 构建必须可复现，只有 CI 是权威

**允许的本地动作**：`read` / `grep` / `glob` 看代码，`edit` / `write` 改代码，`git` 提交推送。

## 第三条：验证走 CI

改完推上去，等 Actions 绿了再说「完成」。

```bash
git add -A && git commit -m "..." && git push
gh run watch
gh run view <id> --log-failed
```

CI 里 **`no_std` job 是硬门槛**：编到 `thumbv6m-none-eabi` 等裸机 target。这些 target 没有 `std`，链不上就失败。

## 第四条：依赖变更要说明理由

新增依赖时，在 `Cargo.toml` 里写注释说明为什么需要它。不要为了一个小功能引入大依赖树。

检查依赖树大小：

```bash
cargo tree --depth 1   # 在 CI 里跑，不在本地
```

## 第五条：测试要有意义

- 每个模块带 `#[cfg(test)] mod tests`
- 密码学相关测试用**标准测试向量**（RFC / FIPS），不要自己造期望值
- 边界条件必测：空输入、块边界（55/56/57/64 字节）、超长输入
- 不写「调用了不 panic」这种空测试

## 不要做的事

- 不要把密钥、token 写进仓库或 README 示例
- 不要为了「跑通」而 `#[ignore]` 测试或注释掉断言
- 不要在 `no_std` 模块里 `use std::`
- 不要用 `unsafe`（`#![forbid(unsafe_code)]` 会拦住你）
