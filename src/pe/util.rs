pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: Input) -> Result<Self> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };
                let parser = map_res($number_parser, |x| {
                    Self::try_from(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_enumflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: Input) -> Result<Self> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };
                let parser = map_res($number_parser, |x| {

                    // probably a nicer way to do this but oh well.
                    match Self::from_bits(x) {
                        Some(v) => Ok(v),
                        None => Err(ErrorKind::Alt),
                    }
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}

use derive_more::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HexDump<'a>(pub &'a [u8]);

use std::fmt;
impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}

impl<'a> From<&'a[u8]> for HexDump<'a> {
    fn from(s: &'a[u8]) -> Self {
        Self(s)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// This will come in handy when serializing
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

// This will come in handy when indexing / sub-slicing slices
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

// This will come in handy when parsing
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl From<Addr32> for Addr {
    fn from(x: Addr32) -> Self {

        Self(x.0 as u64)
    }
}

impl Addr {
    pub fn parse(i: Input) -> Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr32(pub u32);

impl fmt::Debug for Addr32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// This will come in handy when serializing
impl Into<u32> for Addr32 {
    fn into(self) -> u32 {
        self.0
    }
}

// This will come in handy when indexing / sub-slicing slices
impl Into<usize> for Addr32 {
    fn into(self) -> usize {
        self.0 as usize
    }
}

// This will come in handy when parsing
impl From<u32> for Addr32 {
    fn from(x: u32) -> Self {
        Self(x)
    }
}

impl Addr32 {
    pub fn parse(i: Input) -> Result<Self> {
        use nom::{combinator::map, number::complete::le_u32};
        map(le_u32, From::from)(i)
    }
}

/// SectionName is a simple type that allows nicer display
/// of section names, as the null-bytes required
/// in the 8-byte fixed field look ugly, in debug or normal formatting.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SectionName {
    name: String,
}

impl fmt::Debug for SectionName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:>08}", self.name)
    }
}

impl Into<String> for SectionName {
    fn into(self) -> String {
        self.name
    }
}

// This will come in handy when parsing
impl From<String> for SectionName {
    fn from(s: String) -> Self {
        let mut name = s;
        name.remove_matches("\0");
        Self{
            name
        }
    }
}
