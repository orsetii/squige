#[macro_use]
mod util;
mod sections;
mod header;

use util::*;
use sections::Section;
use header::PeHeader64;

#[derive(Debug)]
pub struct File {
    header: PeHeader64,
    sections: Vec<Section>
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
        let full_input = i;
        let mut buf = i;


        // This need to be done in this ugly way so we can use the value from the header to determine
        // how many sections to parse.
        let (i, header) = nom::error::context("Header", header::PeHeader64::parse)(i)?;

        let sec_count = header.number_of_sections() as usize;
        let _image_base = header.optional_header.windows_header.image_base;

        println!("Reading the {} section headers...", sec_count);
        // As we know the size of a section header (40 bytes), we can
        let slices = (&i).chunks(40);
        let mut sections = Vec::new();
        for slice in slices.take(sec_count) {
            println!("{:#x?}", slice);
            let(_, sec) = sections::Section::parse(full_input, slice)?;
            println!("{:#x?}", sec);
            sections.push(sec);
        }



        Ok((i, Self {
                header,
                sections,
        }))

    }
}