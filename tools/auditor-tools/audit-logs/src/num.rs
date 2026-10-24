//! Numbers as the recipes see them: exact integers (Python `int`), Python's
//! `repr` of a float (what `json.dumps` prints), and jq 1.7's canonical form of
//! a number literal (what `jq -r` and `tostring` print).

use std::cmp::Ordering;
use std::fmt;

/// The most digits a JSON integer literal may have (an RPC value has at most 20);
/// a longer one, or `-0`, makes its line malformed.
pub const MAX_INT_DIGITS: usize = 20;

/// Decimal digits held by one limb of a [`Big`].
const LIMB_DIGITS: usize = 9;
const LIMB_BASE: u64 = 1_000_000_000;

/// An exact integer: an `i128` while it fits, decimal limbs beyond that.
#[derive(Clone, Debug)]
pub enum Int {
    Small(i128),
    Big(Big),
}

/// Sign and magnitude, the magnitude in base 1e9 limbs, least significant first,
/// with no zero limb on top. Zero is never negative.
#[derive(Clone, Debug)]
pub struct Big {
    neg: bool,
    limbs: Vec<u32>,
}

impl Int {
    /// The value of a JSON integer literal (`-?(0|[1-9][0-9]*)`), or of a string
    /// of ASCII digits.
    pub fn parse(lit: &str) -> Option<Int> {
        let (neg, digits) = match lit.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, lit),
        };
        if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let digits = digits.trim_start_matches('0');
        if digits.len() <= 38 {
            let mut v: i128 = 0;
            for c in digits.bytes() {
                v = v * 10 + i128::from(c - b'0');
            }
            return Some(Int::Small(if neg { -v } else { v }));
        }
        let mut limbs = Vec::with_capacity(digits.len() / LIMB_DIGITS + 1);
        let bytes = digits.as_bytes();
        let mut end = bytes.len();
        while end > 0 {
            let start = end.saturating_sub(LIMB_DIGITS);
            let mut limb: u32 = 0;
            for &c in &bytes[start..end] {
                limb = limb * 10 + u32::from(c - b'0');
            }
            limbs.push(limb);
            end = start;
        }
        Some(Int::Big(Big { neg, limbs }).normalized())
    }

    pub fn zero() -> Int {
        Int::Small(0)
    }

    pub fn is_zero(&self) -> bool {
        match self {
            Int::Small(v) => *v == 0,
            Int::Big(b) => b.limbs.is_empty(),
        }
    }

    pub fn add(&self, other: &Int) -> Int {
        if let (Int::Small(a), Int::Small(b)) = (self, other) {
            if let Some(v) = a.checked_add(*b) {
                return Int::Small(v);
            }
        }
        Int::Big(Big::add(&self.to_big(), &other.to_big())).normalized()
    }

    pub fn sub(&self, other: &Int) -> Int {
        self.add(&other.neg())
    }

    fn neg(&self) -> Int {
        match self {
            Int::Small(v) => match v.checked_neg() {
                Some(n) => Int::Small(n),
                None => Int::Big(self.to_big().negated()),
            },
            Int::Big(b) => Int::Big(b.clone().negated()),
        }
    }

    fn to_big(&self) -> Big {
        match self {
            Int::Big(b) => b.clone(),
            Int::Small(v) => {
                let mut m = v.unsigned_abs();
                let mut limbs = Vec::new();
                while m > 0 {
                    limbs.push((m % u128::from(LIMB_BASE)) as u32);
                    m /= u128::from(LIMB_BASE);
                }
                Big { neg: *v < 0, limbs }
            }
        }
    }

    /// Back to `Small` when the value fits in 36 digits.
    fn normalized(self) -> Int {
        match self {
            Int::Big(b) if b.limbs.len() <= 4 => {
                let mut v: i128 = 0;
                for &limb in b.limbs.iter().rev() {
                    v = v * i128::from(LIMB_BASE) + i128::from(limb);
                }
                Int::Small(if b.neg { -v } else { v })
            }
            other => other,
        }
    }
}

impl Big {
    fn negated(mut self) -> Big {
        if !self.limbs.is_empty() {
            self.neg = !self.neg;
        }
        self
    }

    fn add(a: &Big, b: &Big) -> Big {
        if a.neg == b.neg {
            return Big {
                neg: a.neg,
                limbs: add_mag(&a.limbs, &b.limbs),
            };
        }
        match cmp_mag(&a.limbs, &b.limbs) {
            Ordering::Equal => Big {
                neg: false,
                limbs: Vec::new(),
            },
            Ordering::Greater => Big {
                neg: a.neg,
                limbs: sub_mag(&a.limbs, &b.limbs),
            },
            Ordering::Less => Big {
                neg: b.neg,
                limbs: sub_mag(&b.limbs, &a.limbs),
            },
        }
    }
}

fn add_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let s = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
        out.push((s % LIMB_BASE) as u32);
        carry = s / LIMB_BASE;
    }
    if carry > 0 {
        out.push(carry as u32);
    }
    out
}

/// `a - b` for magnitudes with `a > b`.
fn sub_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i64;
    for (i, &limb) in a.iter().enumerate() {
        let mut d = i64::from(limb) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
        borrow = 0;
        if d < 0 {
            d += LIMB_BASE as i64;
            borrow = 1;
        }
        out.push(d as u32);
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn cmp_mag(a: &[u32], b: &[u32]) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Int::Small(v) => write!(f, "{v}"),
            Int::Big(b) => {
                if b.neg {
                    f.write_str("-")?;
                }
                let mut limbs = b.limbs.iter().rev();
                match limbs.next() {
                    Some(top) => write!(f, "{top}")?,
                    None => return f.write_str("0"),
                }
                for limb in limbs {
                    write!(f, "{limb:09}")?;
                }
                Ok(())
            }
        }
    }
}

/// Compares two JSON integer literals by value: `-0` equals `0`.
pub fn cmp_int_literals(a: &str, b: &str) -> Ordering {
    fn split(s: &str) -> (bool, &str) {
        let (neg, digits) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let digits = digits.trim_start_matches('0');
        (neg && !digits.is_empty(), digits)
    }
    let (an, ad) = split(a);
    let (bn, bd) = split(b);
    let mag = ad.len().cmp(&bd.len()).then_with(|| ad.cmp(bd));
    match (an, bn) {
        (false, false) => mag,
        (true, true) => mag.reverse(),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
    }
}

/// Python's `repr()` of a finite float, which `json.dumps` prints: the shortest
/// digits that read back as the same float, in exponent form below 1e-4 and from
/// 1e16 up (`1e-05`, `1e+16`), and with `.0` on a whole number.
pub fn py_float_repr(x: f64) -> String {
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_string();
    }
    // `{:e}` gives the shortest digits that read back as `x`, as repr does; on an
    // exact tie between two such strings repr keeps the even last digit.
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i64 = exp.parse().unwrap_or(0);
    let digits = tie_to_even(
        x.abs(),
        mantissa.chars().filter(char::is_ascii_digit).collect(),
        exp,
    );
    let decpt = exp + 1;
    let mut out = String::new();
    if x < 0.0 {
        out.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let e = decpt - 1;
        out.push_str(&format!(
            "e{}{:02}",
            if e < 0 { '-' } else { '+' },
            e.unsigned_abs()
        ));
    } else if decpt <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat(decpt.unsigned_abs() as usize));
        out.push_str(&digits);
    } else {
        let point = decpt as usize;
        if digits.len() > point {
            out.push_str(&digits[..point]);
            out.push('.');
            out.push_str(&digits[point..]);
        } else {
            out.push_str(&digits);
            out.push_str(&"0".repeat(point - digits.len()));
            out.push_str(".0");
        }
    }
    out
}

/// Between two shortest digit strings equally close to `x`, Python's repr (David
/// Gay's dtoa) takes the one whose last digit is even, where Rust takes the upper
/// one. `digits` is Rust's choice, with `x ≈ d.ddd × 10^exp`.
fn tie_to_even(x: f64, digits: String, exp: i64) -> String {
    let n = digits.len();
    let last = digits.as_bytes()[n - 1];
    if matches!(last, b'0' | b'2' | b'4' | b'6' | b'8') || (n == 1 && last == b'1') {
        return digits;
    }
    let mut lower = digits.clone().into_bytes();
    lower[n - 1] -= 1;
    // x's exact decimal expansion has at most 767 significant digits.
    let exact = format!("{x:.800e}");
    let Some((m, e)) = exact.split_once('e') else {
        return digits;
    };
    let exact_digits: Vec<u8> = m.bytes().filter(u8::is_ascii_digit).collect();
    let halfway = e.parse::<i64>() == Ok(exp)
        && exact_digits[..n] == lower[..]
        && exact_digits[n] == b'5'
        && exact_digits[n + 1..].iter().all(|&c| c == b'0');
    let text = String::from_utf8(lower).unwrap_or_default();
    let reads_back = format!("{}.{}e{exp}", &text[..1], &text[1..]).parse::<f64>() == Ok(x);
    if halfway && reads_back {
        text
    } else {
        digits
    }
}

/// jq 1.7's decNumber context (jv.c): its precision, and the largest and smallest
/// exponents of a normal number.
const JQ_DIGITS: usize = 147_483_648;
const JQ_EMAX: i64 = 999_999_999;
const JQ_EMIN: i64 = -999_999_999;
/// The smallest exponent jq keeps; a smaller one is rounded to it.
const JQ_ETINY: i64 = JQ_EMIN - (JQ_DIGITS as i64 - 1);

/// The exponent of a literal as decNumber reads it: one of more than ten digits, or
/// of ten from 2000000000 up, is read as 1999999998, with its sign.
fn jq_exponent(text: &str) -> i64 {
    let (neg, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let digits = digits.trim_start_matches('0');
    let e = if digits.len() > 10 || (digits.len() == 10 && digits.as_bytes()[0] > b'1') {
        1_999_999_998
    } else {
        digits.parse::<i64>().unwrap_or(0)
    };
    if neg {
        -e
    } else {
        e
    }
}

/// Drops the last `drop` digits of a coefficient, rounding half up as jq's context
/// does: a carry may add a digit (`95` less one digit is `10`); all dropped is `0`.
fn round_off(coeff: &str, drop: usize) -> String {
    if drop > coeff.len() {
        return "0".to_string();
    }
    let keep = coeff.len() - drop;
    let up = coeff.as_bytes()[keep] >= b'5';
    let mut digits = coeff.as_bytes()[..keep].to_vec();
    if up {
        let mut i = digits.len();
        loop {
            if i == 0 {
                digits.insert(0, b'1');
                break;
            }
            i -= 1;
            if digits[i] == b'9' {
                digits[i] = b'0';
            } else {
                digits[i] += 1;
                break;
            }
        }
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    String::from_utf8(digits).unwrap_or_else(|_| "0".to_string())
}

/// jq 1.7's canonical text of a JSON number literal: its decNumber
/// to-scientific-string, which keeps trailing zeros (`1.50`), writes an
/// exponent as `E+2` / `E-7`, and keeps the sign of a zero (`-0`). The context's
/// limits apply: a zero's exponent is clamped to them, and a number below the
/// smallest exponent is rounded to it (`1e-1999999998` prints `0E-1147483646`).
pub fn jq_number(lit: &str) -> String {
    let (neg, rest) = match lit.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, lit),
    };
    let (mantissa, exp) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], jq_exponent(&rest[i + 1..])),
        None => (rest, 0),
    };
    let (int_part, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{int_part}{frac}");
    let mut coeff = all.trim_start_matches('0').to_string();
    if coeff.is_empty() {
        coeff.push('0');
    }
    let mut exponent = exp - frac.len() as i64;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if coeff == "0" {
        exponent = exponent.clamp(JQ_ETINY, JQ_EMAX);
    } else {
        if coeff.len() > JQ_DIGITS {
            let drop = coeff.len() - JQ_DIGITS;
            let rounded = round_off(&coeff, drop);
            exponent += drop as i64;
            if rounded.len() > JQ_DIGITS {
                exponent += 1;
                coeff = rounded[..JQ_DIGITS].to_string();
            } else {
                coeff = rounded;
            }
        }
        if exponent < JQ_ETINY {
            coeff = round_off(&coeff, (JQ_ETINY - exponent) as usize);
            exponent = JQ_ETINY;
        }
        if exponent + coeff.len() as i64 - 1 > JQ_EMAX {
            // Infinite in jq's context, which prints the largest double instead.
            out.push_str("1.7976931348623157e+308");
            return out;
        }
    }
    let n = coeff.len() as i64;
    let adjusted = exponent + n - 1;
    if exponent <= 0 && adjusted >= -6 {
        if exponent == 0 {
            out.push_str(&coeff);
        } else if n > -exponent {
            let point = (n + exponent) as usize;
            out.push_str(&coeff[..point]);
            out.push('.');
            out.push_str(&coeff[point..]);
        } else {
            out.push_str("0.");
            out.push_str(&"0".repeat((-exponent - n) as usize));
            out.push_str(&coeff);
        }
    } else {
        out.push_str(&coeff[..1]);
        if coeff.len() > 1 {
            out.push('.');
            out.push_str(&coeff[1..]);
        }
        out.push('E');
        out.push(if adjusted < 0 { '-' } else { '+' });
        out.push_str(&adjusted.unsigned_abs().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(s: &str) -> Int {
        Int::parse(s).unwrap()
    }

    #[test]
    fn exact_integers() {
        let a = int("18446744073709551616");
        let b = int("18446744073709551615");
        assert_eq!(a.sub(&b).to_string(), "1");
        let big = int(&"9".repeat(60));
        assert_eq!(
            big.add(&int("1")).to_string(),
            format!("1{}", "0".repeat(60))
        );
        assert_eq!(
            int(&format!("1{}", "0".repeat(60)))
                .sub(&int("1"))
                .to_string(),
            "9".repeat(60)
        );
        assert_eq!(big.sub(&big).to_string(), "0");
        assert!(big.sub(&big).is_zero());
        assert_eq!(int("-0").to_string(), "0");
        let neg = int(&format!("-{}", "1".repeat(45)));
        assert_eq!(neg.add(&int(&"1".repeat(45))).to_string(), "0");
        assert_eq!(neg.to_string(), format!("-{}", "1".repeat(45)));
        assert_eq!(
            int(&"1".repeat(45)).sub(&int(&"2".repeat(45))).to_string(),
            format!("-{}", "1".repeat(45))
        );
        let max = Int::Small(i128::MAX);
        assert_eq!(
            max.add(&int("1")).to_string(),
            "170141183460469231731687303715884105728"
        );
        assert_eq!(
            Int::Small(i128::MIN).sub(&int("1")).to_string(),
            "-170141183460469231731687303715884105729"
        );
    }

    #[test]
    fn integer_literal_order() {
        assert_eq!(cmp_int_literals("-0", "0"), Ordering::Equal);
        assert_eq!(cmp_int_literals("-5", "3"), Ordering::Less);
        assert_eq!(cmp_int_literals("-50", "-6"), Ordering::Less);
        assert_eq!(
            cmp_int_literals("100000000000000000000", "99999999999999999999"),
            Ordering::Greater
        );
    }

    #[test]
    fn python_float_repr() {
        for (lit, want) in [
            ("1e16", "1e+16"),
            ("1e15", "1000000000000000.0"),
            ("1e-7", "1e-07"),
            ("0.0001", "0.0001"),
            ("0.00001", "1e-05"),
            ("1.5", "1.5"),
            ("-2.0", "-2.0"),
            ("123456789012345678.0", "1.2345678901234568e+17"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("0.1", "0.1"),
            ("100.0", "100.0"),
            ("-0.0", "-0.0"),
            ("9007199254740993.0", "9007199254740992.0"),
            ("1365507272084322.25", "1365507272084322.2"),
            ("1365507272084322.75", "1365507272084322.8"),
            ("0.125", "0.125"),
        ] {
            assert_eq!(py_float_repr(lit.parse().unwrap()), want, "{lit}");
        }
    }

    #[test]
    fn jq_number_literals() {
        for (lit, want) in [
            ("100000000000000000001", "100000000000000000001"),
            ("1.0", "1.0"),
            ("1E2", "1E+2"),
            ("1e2", "1E+2"),
            ("-0", "-0"),
            ("0.0000001", "1E-7"),
            ("1.50", "1.50"),
            ("12e-1", "1.2"),
            (
                "123456789012345678901234567890.5e-3",
                "123456789012345678901234567.8905",
            ),
            ("0e5", "0E+5"),
            ("-0.0", "-0.0"),
            ("0.000001", "0.000001"),
            ("1.5e-7", "1.5E-7"),
            ("0", "0"),
        ] {
            assert_eq!(jq_number(lit), want, "{lit}");
        }
    }

    #[test]
    fn jq_number_limits() {
        // As jq 1.7.1 prints them: a zero's exponent clamped to -1147483646 and
        // 999999999, a smaller number rounded half up to the smallest exponent.
        for (lit, want) in [
            ("0e1000000000", "0E+999999999"),
            (
                "0e99999999999999999999999999999999999999999",
                "0E+999999999",
            ),
            ("-0e1000000000", "-0E+999999999"),
            ("0e-1000000000", "0E-1000000000"),
            ("0.0e-1999999998", "0E-1147483646"),
            ("-0.0e-1999999998", "-0E-1147483646"),
            ("0e00000000000000000000001", "0E+1"),
            ("1e-1999999998", "0E-1147483646"),
            ("1e-2000000000", "0E-1147483646"),
            ("1e-2147483648", "0E-1147483646"),
            ("1e-02000000000", "0E-1147483646"),
            ("1e-0000000001999999999", "0E-1147483646"),
            (
                "1e-99999999999999999999999999999999999999999",
                "0E-1147483646",
            ),
            ("1e-1000000000", "1E-1000000000"),
            ("10e-1000000000", "1.0E-999999999"),
            ("0.1e-999999999", "1E-1000000000"),
            ("1e-1147483646", "1E-1147483646"),
            ("12e-1147483647", "1E-1147483646"),
            ("4e-1147483647", "0E-1147483646"),
            ("5e-1147483647", "1E-1147483646"),
            ("-5e-1147483647", "-1E-1147483646"),
            ("15e-1147483648", "0E-1147483646"),
            ("95e-1147483647", "1.0E-1147483645"),
            ("999e-1147483648", "1.0E-1147483645"),
            ("123456e-1147483648", "1.235E-1147483643"),
        ] {
            assert_eq!(jq_number(lit), want, "{lit}");
        }
        assert_eq!(round_off("1234", 2), "12");
        assert_eq!(round_off("1250", 2), "13");
        assert_eq!(round_off("999", 1), "100");
        assert_eq!(round_off("4", 1), "0");
        assert_eq!(round_off("5", 1), "1");
        assert_eq!(round_off("9", 2), "0");
    }
}
