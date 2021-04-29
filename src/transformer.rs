use {
    lazy_regex::regex,
    lazy_static::lazy_static,
    rand::{rngs::StdRng, Rng, SeedableRng},
    std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
        ops::Range,
        str::FromStr,
    },
};

pub struct Transformer {
    ipv4: HashMap<String, Box<[u8]>>,
    ipv6: HashMap<String, Box<[u8]>>,
    query: HashMap<String, Box<[u8]>>,
    rng: StdRng,
}

impl Transformer {
    pub fn from_seed(seed: u64) -> Self {
        let mut t = Self {
            ipv4: Default::default(),
            ipv6: Default::default(),
            query: Default::default(),
            rng: StdRng::seed_from_u64(seed),
        };
        // TODO this could be an optional multiple command argument
        t.ipv4
            .insert("127.0.0.1".into(), "127.0.0.1".as_bytes().into());
        t
    }

    fn random_digit(&mut self, radix: u32) -> u8 {
        let n = self.rng.gen_range(0..radix);
        let c = std::char::from_digit(n, radix).unwrap();
        c as u8
    }

    pub fn anonymize_ip4(&mut self, src: &mut str) {
        if let Some(rip) = self.ipv4.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let mut digits_count = 0;
            let original = src.to_string();
            let src = unsafe { src.as_bytes_mut() };
            for i in (0..src.len()).rev() {
                if src[i] == b'.' {
                    digits_count = 0;
                } else if digits_count < 2 {
                    src[i] = self.random_digit(10);
                    digits_count += 1;
                }
            }
            self.ipv4.insert(original, (&*src).into());
        }
    }

    // this doesn't do a good job on ip like 0000:0000:0000:0000:0000:ffff:192.168.100.228
    pub fn anonymize_ip6(&mut self, src: &mut str) {
        if let Some(rip) = self.ipv6.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let original = src.to_string();
            let src = unsafe { src.as_bytes_mut() };
            for i in (0..src.len()).rev() {
                if src[i] != b':' {
                    src[i] = self.random_digit(16);
                }
            }
            self.ipv6.insert(original, (&*src).into());
        }
    }

    pub fn anonymize_query_value(&mut self, src: &mut str) {
        if let Some(rip) = self.query.get(src) {
            unsafe {
                src.as_bytes_mut().copy_from_slice(rip);
            }
        } else {
            let original = src.to_string();
            let src = unsafe { src.as_bytes_mut() };
            for i in src.iter_mut() {
                *i = self.random_digit(36);
            }
            self.query.insert(original, (&*src).into());
        }
    }

    pub fn transform_all_ip(&mut self, line: &mut String) {
        let ranges = regex!(r#"[a-fA-F0-9:.]{3,46}"#)
            .find_iter(line)
            .map(|mat| mat.range())
            .collect::<Vec<Range<usize>>>();
        for range in ranges {
            if let Ok(_ipv6) = Ipv6Addr::from_str(&line[range.clone()]) {
//                eprint!("One ipv6 detected: {}", ipv6);
                self.anonymize_ip6(&mut line[range]);
            }
            else if let Ok(_ipv4) = Ipv4Addr::from_str(&line[range.clone()]) {
//                eprint!("One ipv4 detected: {}", ipv4);
                self.anonymize_ip4(&mut line[range]);
            }
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
        self.transform_all_ip(line);
        self.transform_all_queries(line);
    }
}
