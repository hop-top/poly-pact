// Q5 (jsonschema 0.58.6, no default features): pact.schema.json, Draft 2020-12, local $ref only; Appendix C payload against Evidence and the root oneOf.
use jsonschema::{Registry, Resource};
use serde_json::{json, Value};
fn errs(v: &jsonschema::Validator, i: &Value) -> Vec<String> { v.iter_errors(i).map(|e| format!("{}@{}", format!("{:?}", e.kind()).split(|c| c == ' ' || c == '(').next().unwrap(), e.instance_path())).collect() }
fn main() {
    let r = std::env::var("REPO").unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(format!("{r}/spec/v1.0/schemas/pact.schema.json")).unwrap()).unwrap();
    let jws = std::fs::read_to_string(format!("{r}/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws")).unwrap();
    let payload: Value = serde_json::from_slice(&base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, jws.trim().split('.').nth(1).unwrap()).unwrap()).unwrap();
    let id = schema["$id"].as_str().unwrap().to_string();
    let wrapper = json!({"$ref": format!("{id}#/$defs/Evidence")});
    let reg = Registry::new().add(&id, Resource::from_contents(schema.clone())).unwrap().prepare().unwrap();
    let ev = jsonschema::options().with_registry(&reg).build(&wrapper).unwrap();
    println!("root schema compiles: {} | $id {id}", jsonschema::draft202012::new(&schema).is_ok());
    println!("Evidence wrapper without registry: {}", jsonschema::options().build(&wrapper).map(|_| "built".to_string()).unwrap_or_else(|e| format!("RAISED {e}")));
    println!("Appendix C payload as shipped: {:?}", errs(&ev, &payload));
    let fixed = { let mut p = payload.clone(); p["pact_version"] = json!("0.1"); p };
    println!("pact_version 0.1: {:?} | root oneOf valid: {}", errs(&ev, &fixed), jsonschema::draft202012::new(&schema).unwrap().is_valid(&fixed));
}
