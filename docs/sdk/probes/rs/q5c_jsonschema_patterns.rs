// Q5 (patterns): the schema's anchored regexes on OperationContext, including a trailing newline that PCRE-style `$` would accept.
use jsonschema::{Registry, Resource};
use serde_json::{json, Value};
fn main() {
    let r = std::env::var("REPO").unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(format!("{r}/spec/v1.0/schemas/pact.schema.json")).unwrap()).unwrap();
    let ok: Value = serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/vectors/strictjson/accept-valid-object.json")).unwrap()).unwrap()["input_text"].as_str().map(|t| serde_json::from_str(t).unwrap()).unwrap();
    let id = schema["$id"].as_str().unwrap().to_string();
    let reg = Registry::new().add(&id, Resource::from_contents(schema.clone())).unwrap().prepare().unwrap();
    let v = jsonschema::options().with_registry(&reg).build(&json!({"$ref": format!("{id}#/$defs/OperationContext")})).unwrap();
    for (label, path, val) in [("as fixture", "/method", json!("GET")), ("method GET+LF", "/method", json!("GET\n")), ("method get", "/method", json!("get")), ("method G-acute-T", "/method", json!("G\u{c9}T")), ("digest 43+LF", "/body_digest", json!("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\n")), ("target http://", "/target_uri", json!("http://gateway.example/x")), ("resources duplicate", "/resources", json!(["https://a.example/1", "https://a.example/1"])), ("header name upper", "/headers", json!({"X-A": "1"})), ("header name a+LF", "/headers", json!({"x-a\n": "1"}))] {
        let mut i = ok.clone(); *i.pointer_mut(path).unwrap() = val;
        println!("{label:<20} {:?}", v.iter_errors(&i).map(|e| format!("{}@{}", format!("{:?}", e.kind()).split(|c| c == ' ' || c == '(').next().unwrap(), e.instance_path())).collect::<Vec<_>>());
    }
}
