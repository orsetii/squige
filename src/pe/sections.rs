use super::util::*;
use bitflags::*;
use std::ops::Range;
use nom::error::ErrorKind;

bitflags! {
    #[allow(non_camel_case_types)]
    pub struct Characteristics: u32 {
        /// This flag is obsolete and replaced by `IMAGE_SCN_ALIGN_1BYTES`.
        const IMAGE_SCN_TYPE_NO_PAD  = 0x8;
        /// Contains executable code.
        const IMAGE_SCN_CNT_CODE = 0x20;
        /// Contains initialized data.
        const IMAGE_SCN_CNT_INITIALIZED_DATA  = 0x40;
        /// Contains uninitialized data.
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80;
        /// Contains comments or other information.
        /// The `.drectve` section has this type.
        const IMAGE_SCN_LNK_INFO = 0x200;
        /// Will not become part of the image
        const IMAGE_SCN_LNK_REMOVE = 0x800;
        /// Contains COMDAT data.
        const IMAGE_SCN_LNK_COMDAT = 0x1000;
        /// Contains data referenced through the global pointer (GP)
        const IMAGE_SCN_GPREL = 0x8000;
        /// Align data on a 1-byte boundary
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        /// Align data on a 2-byte boundary
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        /// Align data on a 4-byte boundary
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        /// Align data on a 8-byte boundary
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        /// Align data on a 16-byte boundary
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        /// Align data on a 32-byte boundary
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        /// Align data on a 64-byte boundary
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        /// Align data on a 128-byte boundary
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        /// Align data on a 256-byte boundary
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        /// Align data on a 512-byte boundary
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        /// Align data on a 1024-byte boundary
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        /// Align data on a 2048-byte boundary
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        /// Align data on a 512-byte boundary
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        /// Align data on a 1024-byte boundary
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;

        /// Contains extended relocations.
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        /// Can de discarded as needed.
        const IMAGE_SCN_MEM_DISCARDABLE  = 0x02000000;
        /// Cannot be cached.
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        /// Is not pageable.
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        /// Cannot be cached.
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        /// Can be executed as code.
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        /// Can be read.
        const IMAGE_SCN_MEM_READ = 0x40000000;
        /// Can be written to.
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}


impl_parse_for_enumflags!(Characteristics, le_u32);

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
    virtual_address: Addr32,

    /// The size of the section (for object files)
    /// or the size of the initialized data on disk (for image files).
    ///
    /// For executable images, this must be a multiple of FileAlignment from the
    /// optional header.
    size_of_raw_data: u32,

    /// The file pointer to the first page of the section within the file.
    /// When a section contains only uninitialized data, this field should be zero.
    pointer_to_raw_data: Addr32,

    /// The file pointer to the beginning of relocation entries for the section.
    /// This is set to zero for executable images, or if there are no relocations.
    pointer_to_relocations: Addr32,

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
    characteristics: Characteristics,

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
        pointer_to_raw_data, pointer_to_relocations, _,
        number_of_relocations, _, characteristics)) = tuple((

            context("Name", take(8_usize)),
            context("VirtualSize", le_u32),
            context("VirtualAddress", Addr32::parse),
            context("SizeOfRawData", le_u32),
            context("PointerToRawData", Addr32::parse),
            context("PointerToRelocations", Addr32::parse),
            context("PointerToLinenumbers", tag(&[0, 0, 0, 0])),
            context("NumberOfRelocations", le_u16),
            context("NumberOfLinenumbers", tag(&[0, 0])),
            context("Characteristics", Characteristics::parse),
            ))(i)?;
        let name = String::from_utf8_lossy(raw_name).trim().to_string();
        Ok((i, Self{
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_line_numbers: 0,
            number_of_relocations,
            number_of_line_numbers: 0,
            characteristics,
            data: i[pointer_to_raw_data as usize..][..size_of_raw_data as usize].to_vec(),
        }))
    }

    // Range where the segment is stored.
    //pub fn range(&self) -> Range<Addr> {Range{}}
}
