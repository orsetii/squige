use super::util::*;

#[derive(PartialEq, Debug)]
pub struct SectionHeader {

    /// 8-byte, null-padded UTF-8 encoded string.
    /// If the string is exactly 8 characters long,
    /// there is no terminating null.
    name: String,

    /// The total size of the section when loaded into memory
    /// If this value is greater than SizeOfRawData
    virtual_size: u32,

    /// For executables, this is the address of
    /// the first byte relative to the image base
    /// when loaded into memory.
    ///
    /// For object files, this is the address of the first byte before
    /// relocation is applied.
    virtual_address: u32,

    /// The size of the section (for object files)
    /// or the size of the initialized data on disk (for image files).
    ///
    /// For executable images, this must be a multiple of FileAlignment from the
    /// optional header.
    size_of_raw_data: u32,

    /// The file pointer to the first page of the section within the file.
    /// When a section contains only uninitialized data, this field should be zero.
    pointer_to_raw_data: u32,

    /// The file pointer to the beginning of relocation entries for the section.
    /// This is set to zero for executable images, or if there are no relocations.
    pointer_to_relocations: u32,

    /// The file pointer to the beginning of line-number entries for the section.
    /// This is set to zero if there are no COFF line numbers.
    /// Should be zero as COFF debugging information is deprecated.
    pointer_to_line_numbers: u32,

    /// The number of relocation entries for the section.
    number_of_relocations: u16,

    /// The number of line-number entries for the section.
    /// Should be zero as COFF debugging information is deprecated.
    number_of_line_numbers: u16,

    /// The flags that describe the characteristics of the section.
    characteristics: u32,

    pub data: Vec<u8>,

}

impl SectionHeader {
    pub fn parse<'a>(full_input: Input<'_>, i: Input<'a>) -> Result<'a, Self> {
        use nom::{
            bytes::complete::{ take, tag },
            error::context,
            sequence::tuple,
            number::complete::*,
        };

        let (i,(raw_name, virtual_size, virtual_address, size_of_raw_data,
        pointer_to_raw_data, pointer_to_relocations, pointer_to_line_numbers,
        number_of_relocations, number_of_line_numbers, characteristics)) = tuple((

            context("Name", take(8_usize)),
            context("VirtualSize", le_u32),
            context("VirtualAddress", le_u32),
            context("SizeOfRawData", le_u32),
            context("PointerToRawData", le_u32),
            context("PointerToRelocations", le_u32),
            context("PointerToLinenumbers", tag(&[0, 0, 0, 0])),
            context("NumberOfRelocations", le_u16),
            context("NumberOfLinenumbers", tag(&[0, 0])),
            context("Characteristics", le_u32),
            ))(i)?;
        let name = String::from_utf8_lossy(raw_name).trim().to_string();
        Ok((i, Self{
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_line_numbers,
            number_of_relocations,
            number_of_line_numbers,
            characteristics,
            data: i[pointer_to_raw_data..][..size_of_raw_data],
        }))
    }
}
