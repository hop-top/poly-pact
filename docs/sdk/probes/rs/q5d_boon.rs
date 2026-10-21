// Q5 (boon 0.6.1): pact.schema.json, Draft 2020-12, local $ref only; Appendix C payload against Evidence and the root oneOf.
use boon::{Compiler, Draft, Schemas};
use serde_json::{json, Value};
fn errs(s: &Schemas, idx: boon::SchemaIndex, i: &Value) -> Vec<String> {
    match s.validate(i, idx) { Ok(()) => vec![], Err(e) => { let o = serde_json::to_value(e.basic_output()).unwrap(); o["errors"].as_array().unwrap().iter().map(|x| format!("{}@{}", x["keywordLocation"].as_str().unwrap().rsplit('/').next().unwrap(), x["instanceLocation"].as_str().unwrap())).collect() } }
}
fn main() {
    let r = std::env::var("REPO").unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(format!("{r}/spec/v1.0/schemas/pact.schema.json")).unwrap()).unwrap();
    let jws = std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws")).unwrap();
    let payload: Value = serde_json::from_slice(&base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, jws.trim().split('.').nth(1).unwrap()).unwrap()).unwrap();
    let id = schema["$id"].as_str().unwrap().to_string();
    let (mut c, mut s) = (Compiler::new(), Schemas::new());
    c.set_default_draft(Draft::V2020_12); c.add_resource(&id, schema.clone()).unwrap();
    let (ev, root) = (c.compile(&format!("{id}#/$defs/Evidence"), &mut s).unwrap(), c.compile(&id, &mut s).unwrap());
    let fixed = { let mut p = payload.clone(); p["pact_version"] = json!("0.1"); p };
    println!("Evidence wrapper without add_resource: {}", Compiler::new().compile(&format!("{id}#/$defs/Evidence"), &mut Schemas::new()).map(|_| "built".to_string()).unwrap_or_else(|e| format!("RAISED {e}")));
    println!("Appendix C payload as shipped: {:?}", errs(&s, ev, &payload));
    println!("pact_version 0.1: {:?} | root oneOf valid: {}", errs(&s, ev, &fixed), s.validate(&fixed, root).is_ok());
}
