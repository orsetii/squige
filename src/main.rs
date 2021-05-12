#![feature(string_remove_matches)]
#![feature(asm)]

mod pe;
use std::{env, fs, error::Error};

// TODO also refactor the header into an entire, PE loading/parsing function/module.

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage_and_exit();
    }
    let input_path = &args[1];
    let input = fs::read(input_path)?;

    let file = match pe::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };

    println!("{}", file);



    Ok(())
}


#[cfg(windows)]
#[allow(dead_code)]
const PAGE_EXECUTE_READ: u32 = 0x20;
#[cfg(windows)]
#[allow(dead_code)]
const PAGE_EXECUTE: u32 = 0x10;
#[cfg(windows)]
#[allow(dead_code)]
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
#[cfg(windows)]
#[allow(dead_code)]
const PAGE_READONLY: u32 = 0x02;
#[cfg(windows)]
#[allow(dead_code)]
const PAGE_READWRITE: u32 = 0x04;

fn usage_and_exit() {
    println!("usage: squige FILE");
    std::process::exit(1);
}