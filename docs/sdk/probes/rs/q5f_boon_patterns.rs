// Q5 (boon patterns): the schema's anchored regexes on OperationContext, including a trailing newline that PCRE-style `$` would accept.
use boon::{Compiler, Draft, Schemas};
use serde_json::Value;
fn main() {
    let r = std::env::var("REPO").unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(format!("{r}/spec/v1.0/schemas/pact.schema.json")).unwrap()).unwrap();
    let ok: Value = serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/vectors/strictjson/accept-valid-object.json")).unwrap()).unwrap()["input_text"].as_str().map(|t| serde_json::from_str(t).unwrap()).unwrap();
    let id = schema["$id"].as_str().unwrap().to_string();
    let (mut c, mut s) = (Compiler::new(), Schemas::new());
    c.set_default_draft(Draft::V2020_12); c.add_resource(&id, schema.clone()).unwrap();
    let idx = c.compile(&format!("{id}#/$defs/OperationContext"), &mut s).unwrap();
    for (label, path, val) in [("as fixture", "/method", serde_json::json!("GET")), ("method GET+LF", "/method", "GET\n".into()), ("method get", "/method", "get".into()), ("method G-acute-T", "/method", "G\u{c9}T".into()), ("digest 43+LF", "/body_digest", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\n".into()), ("target http://", "/target_uri", "http://gateway.example/x".into()), ("resources duplicate", "/resources", serde_json::json!(["https://a.example/1", "https://a.example/1"])), ("header name upper", "/headers", serde_json::json!({"X-A": "1"})), ("header name a+LF", "/headers", serde_json::json!({"x-a\n": "1"}))] {
        let mut i = ok.clone(); *i.pointer_mut(path).unwrap() = val;
        let e: Vec<String> = match s.validate(&i, idx) { Ok(()) => vec![], Err(e) => serde_json::to_value(e.basic_output()).unwrap()["errors"].as_array().unwrap().iter().map(|x| format!("{}@{}", x["keywordLocation"].as_str().unwrap().rsplit('/').next().unwrap(), x["instanceLocation"].as_str().unwrap())).collect() };
        println!("{label:<20} {e:?}");
    }
}
