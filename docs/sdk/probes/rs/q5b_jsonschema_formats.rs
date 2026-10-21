// Q5 (formats and integers): format "uri" asserted or not, iat at 2^53 and as 2.0, on the Evidence definition. Run under a network-denying sandbox in the record.
use jsonschema::{Registry, Resource};
use serde_json::{json, Value};
fn main() {
    let r = std::env::var("REPO").unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(format!("{r}/spec/v1.0/schemas/pact.schema.json")).unwrap()).unwrap();
    let jws = std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws")).unwrap();
    let mut ok: Value = serde_json::from_slice(&base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, jws.trim().split('.').nth(1).unwrap()).unwrap()).unwrap();
    ok["pact_version"] = json!("0.1");
    let id = schema["$id"].as_str().unwrap().to_string();
    let reg = Registry::new().add(&id, Resource::from_contents(schema.clone())).unwrap().prepare().unwrap();
    let wrapper = json!({"$ref": format!("{id}#/$defs/Evidence")});
    let (off, on) = (jsonschema::options().with_registry(&reg).build(&wrapper).unwrap(), jsonschema::options().with_registry(&reg).should_validate_formats(true).build(&wrapper).unwrap());
    let msgs = |v: &jsonschema::Validator, i: &Value| v.iter_errors(i).map(|e| format!("{}@{}", format!("{:?}", e.kind()).split(|c| c == ' ' || c == '(').next().unwrap(), e.instance_path())).collect::<Vec<_>>();
    for (label, path, val) in [("as fixed", "/jti", json!("7oJQ-3bglLNLRx8Tpz275Q")), ("iss not a uri", "/iss", json!("not a uri")), ("iss with space", "/iss", json!("http://a b/c d")), ("iss urn", "/iss", json!("urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60")), ("iss relative", "/iss", json!("foo/bar")), ("iss empty", "/iss", json!("")), ("iat 2^53", "/iat", json!(9007199254740992u64)), ("iat 2.0", "/iat", json!(2.0)), ("iat 1.5", "/iat", json!(1.5)), ("iat -1", "/iat", json!(-1))] {
        let mut i = ok.clone(); *i.pointer_mut(path).unwrap() = val;
        println!("{label:<15} format off {:?} | format on {:?}", msgs(&off, &i), msgs(&on, &i));
    }
}
