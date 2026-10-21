// Q3: the spec/v1.0/fixtures/vectors/strictjson vectors through q3_json::check (UTF-8, BOM, visitor, trailing data). Set V=1 for every row.
use base64::{engine::general_purpose::STANDARD as B, Engine};
fn main() {
    let dir = format!("{}/spec/v1.0/fixtures/vectors/strictjson", std::env::var("REPO").unwrap());
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let (mut ok, mut bad) = (0, vec![]);
    for f in &files {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let input = v["input_text"].as_str().map(|s| s.as_bytes().to_vec()).unwrap_or_else(|| B.decode(v["input_b64"].as_str().unwrap()).unwrap());
        let (r, want) = (q3_json::check(&input), v["expect"].as_str().unwrap());
        let name = f.file_stem().unwrap().to_string_lossy().to_string();
        if r.is_ok() == (want == "accept") { ok += 1; } else { bad.push(format!("{name}: expected {want}, got {r:?}")); }
        if std::env::var("V").is_ok() { println!("{name:<48} {want:<7} {r:?}"); }
    }
    println!("{} vectors: {ok} agree with expect, {} disagree", files.len(), bad.len());
    bad.iter().for_each(|b| println!("  {b}"));
}
