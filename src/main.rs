mod transformer;

use {
    crate::transformer::*,
    rand::Rng,
    std::{
        fs::File,
        io::{self, BufRead, BufReader},
    },
};

fn main() -> io::Result<()> {
    let in_path = std::env::args()
        .skip(1)
        .next()
        .expect("path of the log file must be the first argument");
    let log_file = File::open(in_path)?;
    let mut reader = BufReader::new(log_file);
    let mut line = String::new();
    let seed: u64 = rand::thread_rng().gen(); // TODO optional command argument
    let mut transformer = Transformer::from_seed(seed);
    while reader.read_line(&mut line)? > 0 {
        transformer.transform_line(&mut line);
        print!("{}", line);
        line.clear();
    }
    eprintln!("Stats: {:#?}", transformer.stats);
    Ok(())
}
