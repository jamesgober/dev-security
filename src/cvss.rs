//! CVSS base-score computation for RustSec advisories.
//!
//! `cargo-audit` and `cargo-deny` report an advisory's CVSS vector string
//! (for example `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) but no
//! numeric score or severity label. This module turns the vector into a
//! score so findings can be mapped onto [`dev_report::Severity`].
//!
//! - CVSS v3.0 and v3.1 use the base-score equations from the FIRST
//!   CVSS v3.1 specification, section 7.
//! - CVSS v4.0 uses the MacroVector lookup and interpolation from the
//!   FIRST reference calculator (`cvss_score.js`, `cvss_lookup.js`,
//!   `max_composed.js`, `max_severity.js`).
//!
//! Anything that is not a well-formed vector yields `None`; nothing in
//! here panics on bad input.

/// Base score (0.0 to 10.0) for a CVSS v3.0, v3.1 or v4.0 vector string.
pub(crate) fn score(vector: &str) -> Option<f64> {
    let vector = vector.trim();
    let rest = vector.strip_prefix("CVSS:")?;
    let (version, metrics) = rest.split_once('/')?;
    match version {
        "3.0" | "3.1" => v3_score(metrics),
        "4.0" => v4_score(metrics),
        _ => None,
    }
}

/// Split `AV:N/AC:L/...` into `(name, value)` pairs.
fn components(metrics: &str) -> Option<Vec<(&str, &str)>> {
    metrics
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|c| {
            let (k, v) = c.split_once(':')?;
            if k.is_empty() || v.is_empty() || v.contains(':') {
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

fn get<'a>(pairs: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    // Last occurrence wins, matching how the reference calculators
    // treat a repeated metric.
    pairs
        .iter()
        .rev()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
}

// ---------------------------------------------------------------------------
// CVSS v3.x
// ---------------------------------------------------------------------------

fn v3_score(metrics: &str) -> Option<f64> {
    let pairs = components(metrics)?;
    let scope_changed = match get(&pairs, "S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match get(&pairs, "AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match get(&pairs, "AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (get(&pairs, "PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match get(&pairs, "UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |name: &str| -> Option<f64> {
        match get(&pairs, name)? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(v3_roundup(raw.min(10.0)))
}

/// `Roundup` from CVSS v3.1 Appendix A: smallest one-decimal number that
/// is greater than or equal to the input, computed without the floating
/// point surprises of `ceil(x * 10) / 10`.
fn v3_roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

// ---------------------------------------------------------------------------
// CVSS v4.0
// ---------------------------------------------------------------------------

/// Effective metric values after applying modified (`M*`) metrics and the
/// worst-case defaults for unset threat / environmental metrics.
#[derive(Default, Clone, Copy)]
struct V4 {
    av: u8,
    ac: u8,
    at: u8,
    pr: u8,
    ui: u8,
    vc: u8,
    vi: u8,
    va: u8,
    sc: u8,
    si: u8,
    sa: u8,
    e: u8,
    cr: u8,
    ir: u8,
    ar: u8,
}

const V4_BASE: [&str; 11] = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

fn single(v: &str) -> Option<u8> {
    match v.as_bytes() {
        [b] => Some(*b),
        _ => None,
    }
}

fn v4_parse(metrics: &str) -> Option<V4> {
    let pairs = components(metrics)?;
    // Every base metric is mandatory.
    for name in V4_BASE {
        get(&pairs, name)?;
    }
    // `S` (safety) is only valid for the modified MSI / MSA metrics.
    if get(&pairs, "SI") == Some("S") || get(&pairs, "SA") == Some("S") {
        return None;
    }
    // Effective value: modified metric when set to something other than
    // `X`, otherwise the base metric.
    let merged = |name: &str| -> Option<u8> {
        let modified = format!("M{name}");
        match get(&pairs, &modified) {
            Some(v) if v != "X" => single(v),
            _ => single(get(&pairs, name)?),
        }
    };
    // Threat / environmental requirement metrics default to the worst
    // case when absent or `X`.
    let defaulted = |name: &str, worst: u8| -> Option<u8> {
        match get(&pairs, name) {
            None | Some("X") => Some(worst),
            Some(v) => single(v),
        }
    };
    let v = V4 {
        av: merged("AV")?,
        ac: merged("AC")?,
        at: merged("AT")?,
        pr: merged("PR")?,
        ui: merged("UI")?,
        vc: merged("VC")?,
        vi: merged("VI")?,
        va: merged("VA")?,
        sc: merged("SC")?,
        si: merged("SI")?,
        sa: merged("SA")?,
        e: defaulted("E", b'A')?,
        cr: defaulted("CR", b'H')?,
        ir: defaulted("IR", b'H')?,
        ar: defaulted("AR", b'H')?,
    };
    // Reject values the reference calculator does not know about.
    v.levels()?;
    if !matches!(v.e, b'A' | b'P' | b'U') {
        return None;
    }
    Some(v)
}

/// Per-metric severity levels used for the in-MacroVector distance.
struct Levels([f64; 14]);

impl V4 {
    fn levels(&self) -> Option<Levels> {
        let av = match self.av {
            b'N' => 0.0,
            b'A' => 0.1,
            b'L' => 0.2,
            b'P' => 0.3,
            _ => return None,
        };
        let pr = match self.pr {
            b'N' => 0.0,
            b'L' => 0.1,
            b'H' => 0.2,
            _ => return None,
        };
        let ui = match self.ui {
            b'N' => 0.0,
            b'P' => 0.1,
            b'A' => 0.2,
            _ => return None,
        };
        let ac = match self.ac {
            b'L' => 0.0,
            b'H' => 0.1,
            _ => return None,
        };
        let at = match self.at {
            b'N' => 0.0,
            b'P' => 0.1,
            _ => return None,
        };
        let vuln = |x: u8| match x {
            b'H' => Some(0.0),
            b'L' => Some(0.1),
            b'N' => Some(0.2),
            _ => None,
        };
        let sc = match self.sc {
            b'H' => 0.1,
            b'L' => 0.2,
            b'N' => 0.3,
            _ => return None,
        };
        let sub = |x: u8| match x {
            b'S' => Some(0.0),
            b'H' => Some(0.1),
            b'L' => Some(0.2),
            b'N' => Some(0.3),
            _ => None,
        };
        let req = |x: u8| match x {
            b'H' => Some(0.0),
            b'M' => Some(0.1),
            b'L' => Some(0.2),
            _ => None,
        };
        Some(Levels([
            av,
            pr,
            ui,
            ac,
            at,
            vuln(self.vc)?,
            vuln(self.vi)?,
            vuln(self.va)?,
            sc,
            sub(self.si)?,
            sub(self.sa)?,
            req(self.cr)?,
            req(self.ir)?,
            req(self.ar)?,
        ]))
    }

    fn eq1(&self) -> u8 {
        if self.av == b'N' && self.pr == b'N' && self.ui == b'N' {
            0
        } else if (self.av == b'N' || self.pr == b'N' || self.ui == b'N') && self.av != b'P' {
            1
        } else {
            2
        }
    }

    fn eq2(&self) -> u8 {
        if self.ac == b'L' && self.at == b'N' {
            0
        } else {
            1
        }
    }

    fn eq3(&self) -> u8 {
        if self.vc == b'H' && self.vi == b'H' {
            0
        } else if self.vc == b'H' || self.vi == b'H' || self.va == b'H' {
            1
        } else {
            2
        }
    }

    fn eq4(&self) -> u8 {
        if self.si == b'S' || self.sa == b'S' {
            0
        } else if self.sc == b'H' || self.si == b'H' || self.sa == b'H' {
            1
        } else {
            2
        }
    }

    fn eq5(&self) -> u8 {
        match self.e {
            b'A' => 0,
            b'P' => 1,
            _ => 2,
        }
    }

    fn eq6(&self) -> u8 {
        if (self.cr == b'H' && self.vc == b'H')
            || (self.ir == b'H' && self.vi == b'H')
            || (self.ar == b'H' && self.va == b'H')
        {
            0
        } else {
            1
        }
    }

    /// Overwrite the fields named in a `max_composed` fragment such as
    /// `AV:N/PR:N/UI:N/`.
    fn apply(&mut self, fragment: &str) {
        for part in fragment.split('/').filter(|p| !p.is_empty()) {
            let Some((k, v)) = part.split_once(':') else {
                continue;
            };
            let Some(v) = single(v) else {
                continue;
            };
            match k {
                "AV" => self.av = v,
                "AC" => self.ac = v,
                "AT" => self.at = v,
                "PR" => self.pr = v,
                "UI" => self.ui = v,
                "VC" => self.vc = v,
                "VI" => self.vi = v,
                "VA" => self.va = v,
                "SC" => self.sc = v,
                "SI" => self.si = v,
                "SA" => self.sa = v,
                "E" => self.e = v,
                "CR" => self.cr = v,
                "IR" => self.ir = v,
                "AR" => self.ar = v,
                _ => {}
            }
        }
    }
}

type MacroVector = [u8; 6];

fn lookup(mv: MacroVector) -> Option<f64> {
    let key: [u8; 6] = mv.map(|d| b'0' + d);
    V4_LOOKUP
        .binary_search_by(|(k, _)| k.as_bytes().cmp(&key[..]))
        .ok()
        .and_then(|i| V4_LOOKUP.get(i))
        .map(|(_, s)| *s)
}

fn bump(mut mv: MacroVector, idx: usize) -> MacroVector {
    mv[idx] = mv[idx].saturating_add(1);
    mv
}

fn max_composed_eq1(eq: u8) -> &'static [&'static str] {
    match eq {
        0 => &["AV:N/PR:N/UI:N/"],
        1 => &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        _ => &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    }
}

fn max_composed_eq2(eq: u8) -> &'static [&'static str] {
    match eq {
        0 => &["AC:L/AT:N/"],
        _ => &["AC:H/AT:N/", "AC:L/AT:P/"],
    }
}

fn max_composed_eq3_eq6(eq3: u8, eq6: u8) -> &'static [&'static str] {
    match (eq3, eq6) {
        (0, 0) => &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        (0, _) => &[
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
        ],
        (1, 0) => &[
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
        ],
        (1, _) => &[
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
        _ => &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
    }
}

fn max_composed_eq4(eq: u8) -> &'static [&'static str] {
    match eq {
        0 => &["SC:H/SI:S/SA:S/"],
        1 => &["SC:H/SI:H/SA:H/"],
        _ => &["SC:L/SI:L/SA:L/"],
    }
}

/// Depth of each MacroVector, in steps of 0.1 (`max_severity.js`).
fn max_severity_eq1(eq: u8) -> f64 {
    match eq {
        0 => 1.0,
        1 => 4.0,
        _ => 5.0,
    }
}

fn max_severity_eq2(eq: u8) -> f64 {
    match eq {
        0 => 1.0,
        _ => 2.0,
    }
}

fn max_severity_eq3_eq6(eq3: u8, eq6: u8) -> f64 {
    match (eq3, eq6) {
        (0, 0) => 7.0,
        (0, _) => 6.0,
        (1, _) => 8.0,
        _ => 10.0,
    }
}

fn max_severity_eq4(eq: u8) -> f64 {
    match eq {
        0 => 6.0,
        1 => 5.0,
        _ => 4.0,
    }
}

fn v4_score(metrics: &str) -> Option<f64> {
    let v = v4_parse(metrics)?;

    // No impact on either system: score is zero by definition.
    if [v.vc, v.vi, v.va, v.sc, v.si, v.sa]
        .iter()
        .all(|x| *x == b'N')
    {
        return Some(0.0);
    }

    let mv: MacroVector = [v.eq1(), v.eq2(), v.eq3(), v.eq4(), v.eq5(), v.eq6()];
    let value = lookup(mv)?;

    // Score of the next lower MacroVector along each EQ, when one exists.
    let lower_eq1 = lookup(bump(mv, 0));
    let lower_eq2 = lookup(bump(mv, 1));
    let lower_eq3_eq6 = match (mv[2], mv[5]) {
        (1, 1) | (0, 1) => lookup(bump(mv, 2)),
        (1, 0) => lookup(bump(mv, 5)),
        (0, 0) => {
            let left = lookup(bump(mv, 5));
            let right = lookup(bump(mv, 2));
            if left > right {
                left
            } else {
                right
            }
        }
        _ => lookup(bump(mv, 2)),
    };
    let lower_eq4 = lookup(bump(mv, 3));
    let lower_eq5 = lookup(bump(mv, 4));

    // Severity distance from the first highest-severity vector of this
    // MacroVector that is at least as severe in every metric.
    let own = v.levels()?;
    let mut dist = [0.0f64; 14];
    'outer: for a in max_composed_eq1(mv[0]) {
        for b in max_composed_eq2(mv[1]) {
            for c in max_composed_eq3_eq6(mv[2], mv[5]) {
                for d in max_composed_eq4(mv[3]) {
                    let mut max = V4::default();
                    max.apply(a);
                    max.apply(b);
                    max.apply(c);
                    max.apply(d);
                    let Some(max_levels) = max.levels() else {
                        continue;
                    };
                    for (slot, (o, m)) in dist.iter_mut().zip(own.0.iter().zip(max_levels.0.iter()))
                    {
                        *slot = o - m;
                    }
                    if dist.iter().all(|d| *d >= 0.0) {
                        break 'outer;
                    }
                }
            }
        }
    }
    let [d_av, d_pr, d_ui, d_ac, d_at, d_vc, d_vi, d_va, d_sc, d_si, d_sa, d_cr, d_ir, d_ar] = dist;
    let cur_eq1 = d_av + d_pr + d_ui;
    let cur_eq2 = d_ac + d_at;
    let cur_eq3_eq6 = d_vc + d_vi + d_va + d_cr + d_ir + d_ar;
    let cur_eq4 = d_sc + d_si + d_sa;

    let step = 0.1;
    let mut existing = 0u32;
    let mut total = 0.0;
    let mut add = |lower: Option<f64>, current: f64, depth: f64| {
        if let Some(l) = lower {
            existing += 1;
            total += (value - l) * (current / (depth * step));
        }
    };
    add(lower_eq1, cur_eq1, max_severity_eq1(mv[0]));
    add(lower_eq2, cur_eq2, max_severity_eq2(mv[1]));
    add(
        lower_eq3_eq6,
        cur_eq3_eq6,
        max_severity_eq3_eq6(mv[2], mv[5]),
    );
    add(lower_eq4, cur_eq4, max_severity_eq4(mv[3]));
    // EQ5 always contributes a zero proportion but still counts towards
    // the mean when a lower MacroVector exists.
    add(lower_eq5, 0.0, 1.0);

    let mean = if existing == 0 {
        0.0
    } else {
        total / f64::from(existing)
    };
    let score = (value - mean).clamp(0.0, 10.0);
    Some(((score + 1e-5) * 10.0).round() / 10.0)
}

/// MacroVector scores from the FIRST reference calculator
/// (`cvss_lookup.js`). Keys are `eq1 eq2 eq3 eq4 eq5 eq6`, sorted.
#[rustfmt::skip]
const V4_LOOKUP: [(&str, f64); 270] = [
    ("000000", 10.0), ("000001", 9.9), ("000010", 9.8), ("000011", 9.5), ("000020", 9.5),
    ("000021", 9.2), ("000100", 10.0), ("000101", 9.6), ("000110", 9.3), ("000111", 8.7),
    ("000120", 9.1), ("000121", 8.1), ("000200", 9.3), ("000201", 9.0), ("000210", 8.9),
    ("000211", 8.0), ("000220", 8.1), ("000221", 6.8), ("001000", 9.8), ("001001", 9.5),
    ("001010", 9.5), ("001011", 9.2), ("001020", 9.0), ("001021", 8.4), ("001100", 9.3),
    ("001101", 9.2), ("001110", 8.9), ("001111", 8.1), ("001120", 8.1), ("001121", 6.5),
    ("001200", 8.8), ("001201", 8.0), ("001210", 7.8), ("001211", 7.0), ("001220", 6.9),
    ("001221", 4.8), ("002001", 9.2), ("002011", 8.2), ("002021", 7.2), ("002101", 7.9),
    ("002111", 6.9), ("002121", 5.0), ("002201", 6.9), ("002211", 5.5), ("002221", 2.7),
    ("010000", 9.9), ("010001", 9.7), ("010010", 9.5), ("010011", 9.2), ("010020", 9.2),
    ("010021", 8.5), ("010100", 9.5), ("010101", 9.1), ("010110", 9.0), ("010111", 8.3),
    ("010120", 8.4), ("010121", 7.1), ("010200", 9.2), ("010201", 8.1), ("010210", 8.2),
    ("010211", 7.1), ("010220", 7.2), ("010221", 5.3), ("011000", 9.5), ("011001", 9.3),
    ("011010", 9.2), ("011011", 8.5), ("011020", 8.5), ("011021", 7.3), ("011100", 9.2),
    ("011101", 8.2), ("011110", 8.0), ("011111", 7.2), ("011120", 7.0), ("011121", 5.9),
    ("011200", 8.4), ("011201", 7.0), ("011210", 7.1), ("011211", 5.2), ("011220", 5.0),
    ("011221", 3.0), ("012001", 8.6), ("012011", 7.5), ("012021", 5.2), ("012101", 7.1),
    ("012111", 5.2), ("012121", 2.9), ("012201", 6.3), ("012211", 2.9), ("012221", 1.7),
    ("100000", 9.8), ("100001", 9.5), ("100010", 9.4), ("100011", 8.7), ("100020", 9.1),
    ("100021", 8.1), ("100100", 9.4), ("100101", 8.9), ("100110", 8.6), ("100111", 7.4),
    ("100120", 7.7), ("100121", 6.4), ("100200", 8.7), ("100201", 7.5), ("100210", 7.4),
    ("100211", 6.3), ("100220", 6.3), ("100221", 4.9), ("101000", 9.4), ("101001", 8.9),
    ("101010", 8.8), ("101011", 7.7), ("101020", 7.6), ("101021", 6.7), ("101100", 8.6),
    ("101101", 7.6), ("101110", 7.4), ("101111", 5.8), ("101120", 5.9), ("101121", 5.0),
    ("101200", 7.2), ("101201", 5.7), ("101210", 5.7), ("101211", 5.2), ("101220", 5.2),
    ("101221", 2.5), ("102001", 8.3), ("102011", 7.0), ("102021", 5.4), ("102101", 6.5),
    ("102111", 5.8), ("102121", 2.6), ("102201", 5.3), ("102211", 2.1), ("102221", 1.3),
    ("110000", 9.5), ("110001", 9.0), ("110010", 8.8), ("110011", 7.6), ("110020", 7.6),
    ("110021", 7.0), ("110100", 9.0), ("110101", 7.7), ("110110", 7.5), ("110111", 6.2),
    ("110120", 6.1), ("110121", 5.3), ("110200", 7.7), ("110201", 6.6), ("110210", 6.8),
    ("110211", 5.9), ("110220", 5.2), ("110221", 3.0), ("111000", 8.9), ("111001", 7.8),
    ("111010", 7.6), ("111011", 6.7), ("111020", 6.2), ("111021", 5.8), ("111100", 7.4),
    ("111101", 5.9), ("111110", 5.7), ("111111", 5.7), ("111120", 4.7), ("111121", 2.3),
    ("111200", 6.1), ("111201", 5.2), ("111210", 5.7), ("111211", 2.9), ("111220", 2.4),
    ("111221", 1.6), ("112001", 7.1), ("112011", 5.9), ("112021", 3.0), ("112101", 5.8),
    ("112111", 2.6), ("112121", 1.5), ("112201", 2.3), ("112211", 1.3), ("112221", 0.6),
    ("200000", 9.3), ("200001", 8.7), ("200010", 8.6), ("200011", 7.2), ("200020", 7.5),
    ("200021", 5.8), ("200100", 8.6), ("200101", 7.4), ("200110", 7.4), ("200111", 6.1),
    ("200120", 5.6), ("200121", 3.4), ("200200", 7.0), ("200201", 5.4), ("200210", 5.2),
    ("200211", 4.0), ("200220", 4.0), ("200221", 2.2), ("201000", 8.5), ("201001", 7.5),
    ("201010", 7.4), ("201011", 5.5), ("201020", 6.2), ("201021", 5.1), ("201100", 7.2),
    ("201101", 5.7), ("201110", 5.5), ("201111", 4.1), ("201120", 4.6), ("201121", 1.9),
    ("201200", 5.3), ("201201", 3.6), ("201210", 3.4), ("201211", 1.9), ("201220", 1.9),
    ("201221", 0.8), ("202001", 6.4), ("202011", 5.1), ("202021", 2.0), ("202101", 4.7),
    ("202111", 2.1), ("202121", 1.1), ("202201", 2.4), ("202211", 0.9), ("202221", 0.4),
    ("210000", 8.8), ("210001", 7.5), ("210010", 7.3), ("210011", 5.3), ("210020", 6.0),
    ("210021", 5.0), ("210100", 7.3), ("210101", 5.5), ("210110", 5.9), ("210111", 4.0),
    ("210120", 4.1), ("210121", 2.0), ("210200", 5.4), ("210201", 4.3), ("210210", 4.5),
    ("210211", 2.2), ("210220", 2.0), ("210221", 1.1), ("211000", 7.5), ("211001", 5.5),
    ("211010", 5.8), ("211011", 4.5), ("211020", 4.0), ("211021", 2.1), ("211100", 6.1),
    ("211101", 5.1), ("211110", 4.8), ("211111", 1.8), ("211120", 2.0), ("211121", 0.9),
    ("211200", 4.6), ("211201", 1.8), ("211210", 1.7), ("211211", 0.7), ("211220", 0.8),
    ("211221", 0.2), ("212001", 5.3), ("212011", 2.4), ("212021", 1.4), ("212101", 2.4),
    ("212111", 1.2), ("212121", 0.5), ("212201", 1.0), ("212211", 0.3), ("212221", 0.1),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_table_is_sorted_and_complete() {
        assert!(V4_LOOKUP.windows(2).all(|w| w[0].0 < w[1].0));
        // 3 * 2 * 3 * 3 * 3 * 2 combinations minus the 54 impossible
        // (eq3 = 2, eq6 = 0) ones.
        assert_eq!(V4_LOOKUP.len(), 324 - 54);
    }

    #[test]
    fn v3_known_scores() {
        // Expected values from the FIRST v3.1 calculator.
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ];
        for (v, want) in cases {
            assert_eq!(score(v), Some(want), "{v}");
        }
    }

    #[test]
    fn v3_ignores_temporal_and_environmental_metrics() {
        assert_eq!(
            score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U"),
            Some(9.8)
        );
    }

    #[test]
    fn v4_known_scores() {
        // Expected values from the FIRST v4.0 calculator.
        let cases = [
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                9.3,
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
                8.7,
            ),
            (
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                5.1,
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                10.0,
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                0.0,
            ),
            (
                "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                1.0,
            ),
        ];
        for (v, want) in cases {
            assert_eq!(score(v), Some(want), "{v}");
        }
    }

    #[test]
    fn v4_threat_and_environmental_metrics_apply() {
        let base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        // E:U (no known exploit) lowers the score.
        assert_eq!(score(&format!("{base}/E:U")), Some(8.1));
        // MSI:S pushes EQ4 to its worst bucket.
        let safety = format!("{base}/MSI:S");
        assert_eq!(score(&safety), Some(10.0));
        // X means "not defined": same as leaving the metric out.
        let x = format!("{base}/E:X/CR:X/MVC:X");
        assert_eq!(score(&x), Some(9.3));
    }

    #[test]
    fn malformed_vectors_yield_none() {
        for v in [
            "",
            "CVSS:3.1",
            "CVSS:3.1/",
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H:H",
            "CVSS:3.1/AV/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z",
            "CVSS:4.0/AV:NN/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:é/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        ] {
            assert_eq!(score(v), None, "{v:?}");
        }
    }

    #[test]
    fn every_v4_macrovector_scores_without_panicking() {
        let pick = |opts: &[&'static str], i: usize| opts[i % opts.len()];
        let mut n = 0usize;
        for i in 0..4usize.pow(6) {
            let v = format!(
                "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}/E:{}/CR:{}/MSI:{}",
                pick(&["N", "A", "L", "P"], i),
                pick(&["L", "H"], i / 4),
                pick(&["N", "P"], i / 8),
                pick(&["N", "L", "H"], i / 16),
                pick(&["N", "P", "A"], i / 48),
                pick(&["H", "L", "N"], i / 3),
                pick(&["H", "L", "N"], i / 9),
                pick(&["H", "L", "N"], i / 27),
                pick(&["H", "L", "N"], i / 81),
                pick(&["H", "L", "N"], i / 243),
                pick(&["H", "L", "N"], i / 729),
                pick(&["A", "P", "U", "X"], i / 7),
                pick(&["H", "M", "L", "X"], i / 11),
                pick(&["S", "H", "L", "N", "X"], i / 13),
            );
            let s = score(&v).unwrap_or_else(|| panic!("{v} did not score"));
            assert!((0.0..=10.0).contains(&s), "{v} -> {s}");
            n += 1;
        }
        assert_eq!(n, 4096);
    }
}
