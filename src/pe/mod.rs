#[macro_use]
pub mod util;
mod header;
mod sections;

use header::PeHeader64;
use sections::Section;
use util::*;

/// Represents an entire PE64 file.
///
/// Note: currently does not `fmt::Display` all fields by default,
/// such as alignment numbers.
#[derive(Debug)]
pub struct File {
    pub header: PeHeader64,
    pub sections: Vec<Section>,
}

impl File {
    pub fn parse_or_print_error(i: Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                use nom::Offset;
                for (input, err) in err.errors {
                    let offset = i.offset(input);
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
        // This need to be done in this ugly way so we can use the value from the header to determine
        // how many sections to parse.
        let (i, header) = nom::error::context("Header", header::PeHeader64::parse)(i)?;

        let sec_count = header.number_of_sections() as usize;
        let _image_base = header.optional_header.windows_header.image_base;

        // As we know the size of a section header (40 bytes), we can
        let slices = (&i).chunks(40);
        let mut sections = Vec::new();
        for slice in slices.take(sec_count) {
            let (_, sec) = sections::Section::parse(full_input, slice)?;
            sections.push(sec);
        }

        Ok((i, Self { header, sections }))
    }
}


use std::fmt;

fn display_version<T: fmt::Display>(major: T, minor: T) -> String {
    format!("{}.{}", major, minor)
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {


        let coff_header = format!(
            "\
            Architecture: {:?}\n\
            No. of Sections: {}\n\
            Characteristics: {:?}\n",
            self.header.machine,
            self.header.number_of_sections,
            self.header.characteristics,
        );

        let oh = &self.header.optional_header;
        let wh = &oh.windows_header;
        let optional_header = format!(
        "\
        Linker Version: {}\n\
        Size of Code: {}KB\n\
        Size of Init. Data: {}KB\n\
        Size of Uninit. Data: {}KB\n\
        Entry Point: 0x{}\n\
        Base of Code: {}\n\
        Image Base: 0x{}\n\
        OS Version: {}\n\
        Image Version: {}\n\
        Subsystem: {:?} {}\n\
        Size of Image: {}KB\n\
        Size of Headers: {}KB\n\
        Checksum: {}\n\
        DLL Characteristics: {:#?}\n\
        Size of Stack Reverse/Commit: {}KB:{}KB\n\
        Size of Heap Reverse/Commit: {}KB:{}KB\n\
        Number of Data Directories: {}\n\


        \nSections: \n{:#?}\n\
        ",
        display_version(oh.major_linker_version,
                          oh.minor_linker_version),
            oh.size_of_code / 1024,
            oh.size_of_initialized_data / 1024,
            oh.size_of_uninitialized_data / 1024,
            oh.entry_point,
            oh.base_of_code,

            wh.image_base,
            display_version(wh.major_os_version, wh.minor_os_version),
            display_version(wh.major_image_version, wh.minor_image_version),
            wh.subsystem,
            display_version(wh.major_subsystem_version, wh.minor_subsystem_version),
            wh.size_of_image / 1024,
            wh.size_of_headers / 1024,
            wh.checksum,
            wh.dll_characteristics,
            wh.size_of_stack_reserve / 1024,
            wh.size_of_stack_commit / 1024,
            wh.size_of_heap_reserve / 1024,
            wh.size_of_heap_commit / 1024,
            wh.number_of_rva_and_sizes,
            self.sections,

        );

        write!(f, "{}{}", coff_header, optional_header)
    }
}