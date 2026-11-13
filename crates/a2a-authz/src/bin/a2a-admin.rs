//! The mesh administrator's tool: hold the root key, issue node tokens, narrow
//! and inspect them.
//!
//! ```text
//! a2a-admin root-keygen --out root.key                    # prints the root PUBLIC key
//! a2a-admin issue  --root root.key --node tablet-7 --node-dir ./tablet7 \
//!                  --inbox-to branch-1,hq --days 30 --out tablet-7.token
//! a2a-admin attenuate --root-pub <PUBKEY> --token tablet-7.token --inbox-to hq --minutes 60
//! a2a-admin inspect   --root-pub <PUBKEY> --token tablet-7.token
//! a2a-admin revoke    --root root.key --token tablet-7.token --reason "tablet lost" --out revoke.json
//!                     # then: curl -X POST --data @revoke.json http://<any node>/security/revocations
//! ```
//!
//! A revocation is signed by the root key and replicated through the mesh like any other
//! document, so every node learns of it when it next syncs, offline nodes included.
//!
//! Keep `root.key` offline. Nodes only ever need the root *public* key.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use a2a_authz::{attenuate, inspect, parse_public_key, Attenuation, Authority, Grant};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn opts(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut m = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let name = k.strip_prefix("--").ok_or_else(|| format!("unexpected argument '{k}'"))?;
        let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
        m.insert(name.to_string(), v.clone());
    }
    Ok(m)
}

fn need<'a>(o: &'a HashMap<String, String>, k: &str) -> Result<&'a String, String> {
    o.get(k).ok_or_else(|| format!("--{k} is required"))
}

/// A token given either as a file or inline.
fn read_token(v: &str) -> Result<String, String> {
    if Path::new(v).is_file() {
        Ok(std::fs::read_to_string(v).map_err(|e| format!("{v}: {e}"))?.trim().to_string())
    } else {
        Ok(v.trim().to_string())
    }
}

fn expiry(o: &HashMap<String, String>) -> Result<Option<SystemTime>, String> {
    let secs = match (o.get("days"), o.get("minutes")) {
        (Some(d), None) => Some(d.parse::<u64>().map_err(|e| format!("--days: {e}"))? * 86_400),
        (None, Some(m)) => Some(m.parse::<u64>().map_err(|e| format!("--minutes: {e}"))? * 60),
        (None, None) => None,
        _ => return Err("use --days or --minutes, not both".into()),
    };
    Ok(secs.map(|s| SystemTime::now() + Duration::from_secs(s)))
}

fn targets(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return Err("usage: a2a-admin root-keygen | issue | attenuate | inspect  (see the file header for options)".into());
    };
    let o = opts(&args[1..])?;
    match cmd.as_str() {
        "root-keygen" => {
            let out = need(&o, "out")?;
            if Path::new(out).exists() {
                return Err(format!("{out} already exists; refusing to overwrite a root key"));
            }
            let a = Authority::generate();
            std::fs::write(out, a.private_b64()).map_err(|e| format!("{out}: {e}"))?;
            println!("root private key written to {out}  (keep it offline)");
            println!("root public key: {}", a.public_b64());
        }
        "issue" => {
            let root = Authority::from_private_b64(
                &std::fs::read_to_string(need(&o, "root")?).map_err(|e| format!("--root: {e}"))?,
            )?;
            let key = match (o.get("key"), o.get("node-dir")) {
                (Some(k), None) => k.clone(),
                (None, Some(d)) => std::fs::read_to_string(Path::new(d).join("node.pub"))
                    .map_err(|e| format!("{d}/node.pub: {e} (start the node once, or run it with --print-pubkey)"))?
                    .trim()
                    .to_string(),
                _ => return Err("give the node's key with --key <base64> or --node-dir <its data dir>".into()),
            };
            let token = root.issue(&Grant {
                node: need(&o, "node")?.clone(),
                node_key_b64: key,
                inbox_targets: targets(o.get("inbox-to").map(String::as_str).unwrap_or("")),
                expires: expiry(&o)?,
            })?;
            match o.get("out") {
                Some(f) => {
                    std::fs::write(f, &token).map_err(|e| format!("{f}: {e}"))?;
                    println!("token written to {f}");
                }
                None => println!("{token}"),
            }
        }
        "attenuate" => {
            let root = parse_public_key(need(&o, "root-pub")?)?;
            let token = read_token(need(&o, "token")?)?;
            let new = attenuate(
                &token,
                &root,
                &Attenuation { expires: expiry(&o)?, inbox_targets: o.get("inbox-to").map(|v| targets(v)) },
            )?;
            println!("{new}");
        }
        "revoke" => {
            let root = Authority::from_private_b64(
                &std::fs::read_to_string(need(&o, "root")?).map_err(|e| format!("--root: {e}"))?,
            )?;
            let reason = o.get("reason").cloned().unwrap_or_default();
            let rev = match (o.get("token"), o.get("id")) {
                (Some(t), None) => root.revoke(&read_token(t)?, &reason)?,
                (None, Some(id)) => root.revoke_id(id, &reason)?,
                _ => return Err("give --token <file or string> or --id <hex revocation id>".into()),
            };
            let json = rev.to_json().to_string();
            match o.get("out") {
                Some(f) => {
                    std::fs::write(f, &json).map_err(|e| format!("{f}: {e}"))?;
                    println!("revocation written to {f}  (POST it to any node at /security/revocations)");
                }
                None => println!("{json}"),
            }
        }
        "inspect" => {
            let root = parse_public_key(need(&o, "root-pub")?)?;
            println!("{}", inspect(&read_token(need(&o, "token")?)?, &root)?);
        }
        other => return Err(format!("unknown command '{other}'")),
    }
    Ok(())
}
