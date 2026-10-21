// Q3: parse the 10000 decimal strings of vectors/jcs/numbers.json back to doubles: std str::parse vs serde_json::from_str::<f64>/<Value>.
fn main() {
    let path = format!("{}/spec/v1.0/fixtures/vectors/jcs/numbers.json", std::env::var("REPO").unwrap());
    let rows: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut std_bad, mut json_bad, mut val_bad, mut shown) = (0, 0, 0, 0);
    for r in &rows {
        let (text, bits) = (r["expected"].as_str().unwrap(), u64::from_str_radix(r["ieee754_hex"].as_str().unwrap(), 16).unwrap());
        let (a, b, c) = (text.parse::<f64>().unwrap().to_bits(), serde_json::from_str::<f64>(text).unwrap().to_bits(), serde_json::from_str::<serde_json::Value>(text).unwrap().as_f64().unwrap().to_bits());
        let norm = |x: u64| if x == 1 << 63 { 0 } else { x }; // "-0" is written "0" in the file
        let (a, b, c, bits) = (norm(a), norm(b), norm(c), norm(bits));
        (std_bad, json_bad, val_bad) = (std_bad + (a != bits) as u32, json_bad + (b != bits) as u32, val_bad + (c != bits) as u32);
        if (b != bits || c != bits) && shown < 3 { shown += 1; println!("  e.g. {text} want bits {bits:016x} from_str::<f64> {b:016x} Value::as_f64 {c:016x}"); }
    }
    println!("{} rows, bits differ from ieee754_hex: std str::parse {std_bad} | serde_json::from_str::<f64> {json_bad} | serde_json Value::as_f64 {val_bad}", rows.len());
}
