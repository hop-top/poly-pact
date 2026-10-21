// Q4 (documents): RFC 8785 3.2.2-3.2.4 sample bytes, the 3.2.3 UTF-16 sorting sample, and the six input/output pairs in vectors/jcs.
use serde_json::Value;
fn main() {
    let j = |t: &str| serde_json::from_str::<Value>(&t.replace("@u", "\\u")).unwrap();
    let s = j(r#"{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "@u20ac$@u000F@u000aA'@u0042@u0022@u005c\\\"\/", "literals": [null, true, false]}"#);
    let o = j(r#"{"@u20ac": "Euro Sign", "\r": "Carriage Return", "@ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "@ud83d@ude00": "Emoji: Grinning Face", "@u0080": "Control", "@u00f6": "Latin Small Letter O With Diaeresis"}"#);
    let want = r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$@u000f\nA'B\"\\\\\"/"}"#.replace("@u", "\\u");
    let impls: [(&str, Box<dyn Fn(&Value) -> String>); 4] = [("in-house", Box::new(|v| q4_jcs::canonicalize(v).unwrap())), ("serde_jcs", Box::new(|v| serde_jcs::to_string(v).unwrap())), ("serde_json_canonicalizer", Box::new(|v| serde_json_canonicalizer::to_string(v).unwrap())), ("serde_json::to_string", Box::new(|v| serde_json::to_string(v).unwrap()))];
    let order = |t: &str| { let mut p: Vec<(usize, &str)> = ["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis", "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"].iter().map(|n| (t.find(n).unwrap(), *n)).collect(); p.sort(); p.iter().map(|x| x.1.split(' ').next().unwrap()).collect::<Vec<_>>().join(",") };
    let dir = format!("{}/spec/v1.0/fixtures/vectors/jcs", std::env::var("REPO").unwrap());
    for (name, f) in &impls {
        let pairs: Vec<bool> = ["arrays", "french", "structures", "unicode", "values", "weird"].iter().map(|n| f(&serde_json::from_str(&std::fs::read_to_string(format!("{dir}/input/{n}.json")).unwrap()).unwrap()) == std::fs::read_to_string(format!("{dir}/output/{n}.json")).unwrap()).collect();
        println!("{name:<25} 3.2.4 sample {} | sorting order {} | vector pairs {}/6 {pairs:?}", f(&s) == want, order(&f(&o)), pairs.iter().filter(|b| **b).count());
    }
}
