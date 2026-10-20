//! 卡密生成与校验工具。
//!
//! 熵由 `getrandom` 从操作系统取得。密钥从环境变量读取——
//! **不要**放在命令行参数里，那会留在 shell history 和进程列表。

use std::process::ExitCode;

use lilyco_crypto::keys;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || matches!(args[0].as_str(), "help" | "-h" | "--help") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    match args[0].as_str() {
        "gen" => gen(&args[1..]),
        "verify" => verify(&args[1..]),
        other => {
            eprintln!("未知子命令：{other}\n");
            eprintln!("{HELP}");
            ExitCode::from(64)
        }
    }
}

const HELP: &str = "\
keygen — 卡密生成与校验

用法:
  keygen gen [前缀] [数量]     生成卡密（默认 PDBP，1 个）
  keygen verify <卡密> [前缀]   校验格式与校验位
  keygen help

环境变量:
  KEYGEN_SECRET   计算校验位的密钥，至少 16 字节。必填。

示例:
  export KEYGEN_SECRET=$(head -c 32 /dev/urandom | base64)
  keygen gen PDBP 5
  keygen verify PDBP-ABCD-EFGH-IJKM

注意:
  同一批卡密必须用同一个 KEYGEN_SECRET，否则校验失败。
  丢失密钥等于无法再生成可通过校验的卡密。
";

fn secret() -> Result<Vec<u8>, ExitCode> {
    match std::env::var("KEYGEN_SECRET") {
        Ok(s) if s.len() >= 16 => Ok(s.into_bytes()),
        Ok(_) => {
            eprintln!("KEYGEN_SECRET 太短，至少 16 字节");
            Err(ExitCode::from(2))
        }
        Err(_) => {
            eprintln!("未设置 KEYGEN_SECRET 环境变量");
            Err(ExitCode::from(2))
        }
    }
}

fn parse_prefix(raw: Option<&String>) -> Result<Vec<u8>, ExitCode> {
    let p = raw.map(String::as_str).unwrap_or("PDBP").to_ascii_uppercase();
    if !p.bytes().all(|c| c.is_ascii_uppercase()) {
        eprintln!("前缀只允许 A-Z");
        return Err(ExitCode::from(64));
    }
    Ok(p.into_bytes())
}

fn gen(args: &[String]) -> ExitCode {
    let prefix = match parse_prefix(args.first()) {
        Ok(p) => p,
        Err(c) => return c,
    };

    let count: usize = match args.get(1) {
        None => 1,
        Some(raw) => match raw.parse() {
            Ok(n) if n > 0 && n <= 10_000 => n,
            _ => {
                eprintln!("数量必须是 1..=10000 的整数，收到 {raw}");
                return ExitCode::from(64);
            }
        },
    };

    let secret = match secret() {
        Ok(s) => s,
        Err(c) => return c,
    };

    for _ in 0..count {
        let mut body = [0u8; keys::BODY_LEN];
        if let Err(e) = keys::generate_with_os_entropy(&prefix, &secret, &mut body) {
            eprintln!("生成失败：{e}");
            return ExitCode::from(1);
        }
        let mut out = [0u8; 40];
        match keys::format(&prefix, &body, &mut out) {
            Ok(n) => println!("{}", String::from_utf8_lossy(&out[..n])),
            Err(e) => {
                eprintln!("格式化失败：{e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

fn verify(args: &[String]) -> ExitCode {
    let Some(key) = args.first() else {
        eprintln!("用法：keygen verify <卡密> [前缀]");
        return ExitCode::from(64);
    };
    let prefix = match parse_prefix(args.get(1)) {
        Ok(p) => p,
        Err(c) => return c,
    };
    let secret = match secret() {
        Ok(s) => s,
        Err(c) => return c,
    };

    let upper = key.to_ascii_uppercase();
    if keys::verify(&prefix, upper.as_bytes(), &secret) {
        println!("有效");
        ExitCode::SUCCESS
    } else {
        println!("无效");
        ExitCode::from(1)
    }
}
