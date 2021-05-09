#![feature(string_remove_matches)]

mod pe;

use std::{env, fs};

// TODO also refactor the header into an entire, PE loading/parsing function/module.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: {} FILE", args[0]);
        std::process::exit(1);
    }
    let input = fs::read(&args[1])?;

    let file = match pe::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };



    println!("{:#x?}", file);

    Ok(())
}
