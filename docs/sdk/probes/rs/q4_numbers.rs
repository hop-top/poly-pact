// Q4: RFC 8785 Appendix B rows (by IEEE 754 bits) and the named literals through every candidate formatter; first differing text is shown.
use q4_jcs::formatters;
fn main() {
    let rows = [("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"), ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"), ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"), ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"), ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"), ("44b52d02c7e14af7", "1.0000000000000001e+23"), ("444b1ae4d6e2ef4e", "999999999999999700000"), ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"), ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"), ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"), ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"), ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"), ("43143ff3c1cb0959", "1424953923781206.2")];
    let lits = [(1e21, "1e+21"), (1e-7, "1e-7"), (-0.0, "0"), (4.5, "4.5"), (1e30, "1e+30"), (1.0, "1"), (100.0, "100"), (1e16, "10000000000000000")];
    let all: Vec<(String, f64, &str)> = rows.iter().map(|(h, w)| (h.to_string(), f64::from_bits(u64::from_str_radix(h, 16).unwrap()), *w)).chain(lits.iter().map(|(x, w)| ("literal".to_string(), *x, *w))).collect();
    let mut bad = std::collections::BTreeMap::<&str, usize>::new();
    for (h, x, want) in &all {
        let f = formatters(*x);
        let tags: Vec<String> = f.iter().map(|(n, t)| { if t != want { *bad.entry(n).or_default() += 1; format!("{n}={}", if t.len() > 40 { format!("{}...[{} chars]", &t[..30], t.len()) } else { t.clone() }) } else { format!("{n}:ok") } }).collect();
        println!("{h:<17} want={want:<26} {}", tags.join(" "));
    }
    println!("rows {} mismatches per formatter: {bad:?}", all.len());
}
