use {
    lazy_regex::regex,
    lazy_static::lazy_static,
    rand::{
        rngs::StdRng,
        Rng,
        SeedableRng,
    },
    std::{
        collections::HashMap,
        ops::Range,
    },
};


pub struct Transformer {
    repl: HashMap<String, Box<[u8]>>,
    rng: StdRng,
}

impl Transformer {

    pub fn from_seed(seed: u64) -> Self {
        let mut t = Self {
            repl: Default::default(),
            rng: StdRng::seed_from_u64(seed),
        };
        t.repl.insert("127.0.0.1".into(), "127.0.0.1".as_bytes().into());
        t
    }

    fn random_digit(&mut self, radix: u32) -> u8 {
        let n = self.rng.gen_range(0..radix);
        let c = std::char::from_digit(n, radix).unwrap();
        c as u8
    }

    pub fn anonymize_ip4(&mut self, src: &mut str) {
        if let Some(rip) = self.repl.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let mut digits_count = 0;
            let original = src.to_string();
            let src = unsafe {
                src.as_bytes_mut()
            };
            for i in (0..src.len()).rev() {
                if src[i] == b'.' {
                    digits_count = 0;
                } else if digits_count < 2 {
                    src[i] = self.random_digit(10);
                    digits_count += 1;
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
                    src[i] = self.random_digit(16);
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
            for i in 0..src.len() {
                src[i] = self.random_digit(36);
            }
            self.repl.insert(original, (&*src).into());
        }
    }

    pub fn transform_all_ip4(&mut self, line: &mut String) {
        let ranges = regex!(r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#)
            .find_iter(line)
            .map(|mat| mat.range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            self.anonymize_ip4(&mut line[range]);
        }
    }

    pub fn transform_all_ip6(&mut self, line: &mut String) {
        // I just invented this with only a few dozen cases...
        // I don't even know IPv6 well enough, so you might want to check...
        let ranges = regex!(r#"\b((([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})|(([a-fA-F0-9]{1,4}:){1,7}(:[a-fA-F0-9]{1,4}){1,7})|(([a-fA-F0-9]{1,4}:){6}:))"#)
            .find_iter(line)
            .map(|mat| mat.range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            self.anonymize_ip6(&mut line[range.clone()]);
        }
    }

    pub fn transform_all_queries(&mut self, line: &mut String) {
        let ranges = regex!(r#"(?:^|\s)/[^?\s"]*\?([^?\s"]+)"#)
            .captures_iter(line)
            .map(|capture| capture.get(1).unwrap().range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            let query = &mut line[range];
            let value_ranges = regex!(r#"(?:^|&)[^=&]+=([^&=]+)"#)
                .captures_iter(query)
                .map(|capture| capture.get(1).unwrap().range())
                .collect::<Vec<Range<usize>>>();
            for value_range in value_ranges {
                self.anonymize_query_value(&mut query[value_range]);
            }
        }
    }

    pub fn transform_line(&mut self, line: &mut String) {
        self.transform_all_ip6(line);
        self.transform_all_ip4(line);
        self.transform_all_queries(line);
    }
}
