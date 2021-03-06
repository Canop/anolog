use {
    fnv::FnvHashMap,
    lazy_regex::regex,
    rand::{
        rngs::StdRng,
        Rng,
        SeedableRng,
    },
    std::{
        net::Ipv6Addr,
        ops::Range,
        str::FromStr,
    },
};


#[derive(Debug, Default)]
pub struct ChangeStats {
    ip4: usize,
    ip6: usize,
    query_values: usize,
    lines: usize,
}

pub struct Transformer {
    repl: FnvHashMap<String, Box<[u8]>>,
    rng: StdRng,
    pub stats: ChangeStats,
}

impl Transformer {

    pub fn from_seed(seed: u64) -> Self {
        let mut t = Self {
            repl: Default::default(),
            rng: StdRng::seed_from_u64(seed),
            stats: ChangeStats::default(),
        };
        t.repl.insert("127.0.0.1".into(), "127.0.0.1".as_bytes().into());
        t
    }

    fn random_digit(&mut self, range: Range<u32>, radix: u32) -> u8 {
        let n = self.rng.gen_range(range);
        let c = std::char::from_digit(n, radix).unwrap();
        c as u8
    }

    pub fn anonymize_ip4(&mut self, src: &mut str) {
        if let Some(rip) = self.repl.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let ranges = regex!(r#"\d+"#)
                .find_iter(src)
                .map(|mat| mat.range())
                .collect::<Vec<Range<usize>>>();
            let original = src.to_string();
            let src = unsafe {
                src.as_bytes_mut()
            };
            for r in ranges {
                match r.end-r.start {
                    1 => {
                        src[r.start] = self.random_digit(0..10, 10);
                    }
                    2 => {
                        src[r.start] = self.random_digit(1..10, 10);
                        src[r.start + 1] = self.random_digit(0..10, 10);
                    }
                    3 => {
                        let new_val = self.rng.gen_range(100..256).to_string();
                        let new_val = new_val.as_bytes();
                        src[r.start] = new_val[0];
                        src[r.start + 1] = new_val[1];
                        src[r.start + 2] = new_val[2];
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
            self.repl.insert(original, (&*src).into());
        }
    }

    pub fn anonymize_ip6(&mut self, src: &mut str) {
        if let Some(rip) = self.repl.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let original = src.to_string();
            let src = unsafe {
                src.as_bytes_mut()
            };
            for i in (0..src.len()).rev() {
                if src[i] != b':' {
                    src[i] = self.random_digit(0..16, 16);
                }
            }
            self.repl.insert(original, (&*src).into());
        }
    }

    pub fn anonymize_query_value(&mut self, src: &mut str) {
        if let Some(rip) = self.repl.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let original = src.to_string();
            let src = unsafe {
                src.as_bytes_mut()
            };
            for i in src.iter_mut() {
                *i = self.random_digit(0..36, 36);
            }
            self.repl.insert(original, (&*src).into());
        }
    }

    pub fn transform_all_ip4(&mut self, line: &mut String) {
        let ranges = regex!(r#"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"#)
            .find_iter(line)
            .map(|mat| mat.range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            self.anonymize_ip4(&mut line[range]);
            self.stats.ip4 += 1;
        }
    }

    pub fn transform_all_ip6(&mut self, line: &mut String) {
        // IPv6 format is painful. A full regex not accepting unwanted strings
        // (for example dates) would be hard to write. So I combine a very
        // permissive and fast one with a filter parsing the matches
        let ranges = regex!(r#"[a-fA-F0-9:]{3,40}"#)
            .find_iter(line)
            .filter(|mat| Ipv6Addr::from_str(mat.as_str()).is_ok())
            .map(|mat| mat.range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            self.anonymize_ip6(&mut line[range]);
            self.stats.ip6 += 1;
        }
    }

    pub fn transform_all_queries(&mut self, line: &mut String) {
        let ranges = regex!(r#"(?:^|\s)/[^?\s"]*\?([^?\s"]+)"#)
            .captures_iter(line)
            .map(|capture| capture.get(1).unwrap().range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            let query = &mut line[range];
            // TODO we could have a whitelist of query name to not change
            let value_ranges = regex!(r#"(?:^|&)[^=&]+=([^&=]+)"#)
                .captures_iter(query)
                .map(|capture| capture.get(1).unwrap().range())
                .collect::<Vec<Range<usize>>>();
            for value_range in value_ranges {
                self.anonymize_query_value(&mut query[value_range]);
                self.stats.query_values += 1;
            }
        }
    }

    pub fn transform_line(&mut self, line: &mut String) {
        self.transform_all_ip6(line);
        self.transform_all_ip4(line);
        self.transform_all_queries(line);
        self.stats.lines += 1;
    }
}
