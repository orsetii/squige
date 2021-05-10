#![feature(string_remove_matches)]
#![feature(asm)]

mod pe;
mod bindings {
    windows::include_bindings!();
}

use std::{env, fs, error::Error};
use bindings::{
    Windows::Win32::SystemServices::VirtualProtect,
};
use std::convert::TryInto;
use crate::pe::util::{Addr, Addr32};

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
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;

#[cfg(windows)]
fn mem_protect<T>(perms: u32, addr: *const T, size: usize) {
    let mut memory_protections: u32 = perms;
    let ptr_mem_protections: *mut u32 = &mut memory_protections;
    use std::mem::transmute;
    unsafe {
        VirtualProtect(transmute(addr), size, memory_protections.try_into().unwrap(),
                       transmute(ptr_mem_protections));
    }
}




unsafe fn jmp<T>(addr: *const T) {
    let fn_ptr = std::mem::transmute::<*const T, fn()>(addr);
    let pfn: *const fn() = &fn_ptr;
    println!("addr: {:?} - fn_ptr: {:?}", addr, pfn);
    fn_ptr();
}

fn ndisasm(code: &[u8], origin: Addr32) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("0x{}", origin))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}


fn usage_and_exit() {
    println!("usage: squige FILE");
    std::process::exit(1);
}