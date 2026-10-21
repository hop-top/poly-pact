// Q3 (decode target): the strictjson vectors decoded into a serde struct (deny_unknown_fields) alone, then behind q3_json::check.
use base64::{engine::general_purpose::STANDARD as B, Engine};
use std::collections::BTreeMap;
#[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] #[allow(dead_code)]
struct OperationContext { operation_id: String, environment_id: String, principal_id: String, action: String, resources: Vec<String>, method: String, target_uri: String, body_digest: String, headers: BTreeMap<String, String>, extensions: Option<serde_json::Value> }
fn main() {
    let files = { let mut f: Vec<_> = std::fs::read_dir(format!("{}/spec/v1.0/fixtures/vectors/strictjson", std::env::var("REPO").unwrap())).unwrap().map(|e| e.unwrap().path()).collect(); f.sort(); f };
    let (mut alone, mut both) = (vec![], vec![]);
    for f in &files {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let input = v["input_text"].as_str().map(|s| s.as_bytes().to_vec()).unwrap_or_else(|| B.decode(v["input_b64"].as_str().unwrap()).unwrap());
        let (a, c, name) = (serde_json::from_slice::<OperationContext>(&input), q3_json::check(&input), f.file_stem().unwrap().to_string_lossy().to_string());
        let want = v["expect"] == "accept";
        if a.is_ok() != want { alone.push(format!("{name}: expected {}, decode alone {}", v["expect"].as_str().unwrap(), if a.is_ok() { "accepted" } else { "rejected" })); }
        if (a.is_ok() && c.is_ok()) != want { both.push(name); }
    }
    println!("{} vectors | struct decode alone disagrees on {}:", files.len(), alone.len());
    alone.iter().for_each(|b| println!("  {b}"));
    println!("check + struct decode disagrees on {}: {both:?}", both.len());
}
