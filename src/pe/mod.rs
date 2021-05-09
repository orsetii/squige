#[macro_use]
mod util;
mod sections;
mod header;

use util::*;
use sections::SectionHeader;
use header::PeHeader64;

#[derive(Debug)]
pub struct File {
    header: PeHeader64,
    sections: Vec<SectionHeader>
}


impl File {
    pub fn parse_or_print_error(i: Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                use nom::Offset;
                let offset = i.offset(i);
                for (input, err) in err.errors {
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }

    pub fn parse(i: Input) -> Result<Self> {
        use nom::{
            bytes::complete::take,
            error::context,
            sequence::tuple,
            number::complete::*,
            multi::count,
        };

        let full_input = i;


        // This need to be done in this ugly way so we can use the value from the header to determine
        // how many sections to parse.
        let (i, header) = context("Header", header::PeHeader64::parse)(i)?;

        let sec_count = header.number_of_sections() as usize;
        let image_base = header.optional_header.windows_header.image_base;

        let mut sections = Vec::new();
        for j in ..sec_count {
            let(_, sec) = sections::SectionHeader::parse(full_input, i)?;
            sections.push(sec);
        }



        Ok((i, Self {
                header,
                sections,
        }))

    }
}