// Q4: spec/v1.0/fixtures/vectors/jcs/numbers.json (10000 rows) through every formatter, then 500000 pseudo-random doubles, differential.
use q4_jcs::{es, es_ryu, formatters};
fn main() {
    let rows: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(format!("{}/spec/v1.0/fixtures/vectors/jcs/numbers.json", std::env::var("REPO").unwrap())).unwrap()).unwrap();
    let mut bad = std::collections::BTreeMap::<&str, usize>::new();
    for r in &rows {
        let x = f64::from_bits(u64::from_str_radix(r["ieee754_hex"].as_str().unwrap(), 16).unwrap());
        for (n, t) in formatters(x) { if t != r["expected"].as_str().unwrap() { *bad.entry(n).or_default() += 1; } }
    }
    println!("numbers.json rows {} mismatches per formatter: {bad:?}", rows.len());
    let (mut s, mut n, mut d, mut rt) = (0x9E3779B97F4A7C15u64, 0, [0usize; 3], 0);
    while n < 500_000 {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        let x = f64::from_bits(s);
        if !x.is_finite() { continue; } else { n += 1; }
        let (a, b, c, e) = (es(x), es_ryu(x), serde_jcs::to_string(&x).unwrap(), serde_json_canonicalizer::to_string(&x).unwrap());
        d[0] += (a != c) as usize; d[1] += (b != c) as usize; d[2] += (e != c) as usize; rt += (a.parse::<f64>().unwrap().to_bits() != x.to_bits()) as usize;
    }
    println!("random doubles {n}: es_json!=jcs {} | es_ryu!=jcs {} | sjc!=jcs {} | es_json text not parsing back to the same bits {rt}", d[0], d[1], d[2]);
}
