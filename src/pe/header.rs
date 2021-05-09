#[macro_use]
use super::util::*;
use std::convert::TryFrom;
use nom::Offset;
use super::sections::SectionHeader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Machine {
    Unknown = 0,
    AMD64 = 0x8664,
    IA64 = 0x200,
    I386 = 0x14C,
}

impl TryFrom<u16> for Machine {
    type Error = u16;

    fn try_from(n: u16) -> std::result::Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Unknown),
            0x8664 => Ok(Self::AMD64),
            0x200 => Ok(Self::IA64),
            0x14C => Ok(Self::I386),
            _ => Err(n),
        }
    }
}

impl_parse_for_enum!(Machine, le_u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Subsystem {
    Unknown = 0,
    /// Device drivers and native Windows processes
    Native = 1,
    /// Windows GUI subsystem
    WindowsGui = 2,
    /// Windows character subsystem
    WindowsCui = 3,
    /// OS/2 character subsystem
    Os2Cui = 5,
    PosixCui = 7,
    /// Native Win9x driver
    NativeWindows = 8,
    /// Windows CE
    WindowsCeGui = 9,
    /// EFI application
    EfiApplication = 10,
    /// EFI driver with boot services
    EfiBootServiceDriver = 11,
    /// EFI driver with runtime services
    EfiRuntimeDriver = 12,
    /// EFI ROM Image
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
}


impl TryFrom<u16> for Subsystem {
    type Error = u16;

    fn try_from(n: u16) -> std::result::Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Native),
            2 => Ok(Self::WindowsGui),
            3 => Ok(Self::WindowsCui),
            5 => Ok(Self::Os2Cui),
            7 => Ok(Self::PosixCui),
            8 => Ok(Self::NativeWindows),
            9 => Ok(Self::WindowsCeGui),
            10 => Ok(Self::EfiApplication),
            11 => Ok(Self::EfiBootServiceDriver),
            12 => Ok(Self::EfiRuntimeDriver),
            13 => Ok(Self::EfiRom),
            14 => Ok(Self::Xbox),
            16 => Ok(Self::WindowsBootApplication),
            _ => Err(n),
        }
    }
}

impl_parse_for_enum!(Subsystem, le_u16);


#[derive(Debug)]
pub struct PeHeader64 {

    /// the architecture of the machine, `0x8664`
    /// is AMD64 and `0x14C0` is i386.
    pub machine: Machine,

    /// _the number of sections, aka the size of the section table.
    pub number_of_sections: u16,

    // _the low 32 bits of the UNIX timestamp
    pub time_date_stamp: u32,

    /// _the file offset of the COFF symbol table,
    /// is zero if no COFF symbol table is present (it should be,
    /// since COFF debugging information support is deperecated).
    pub pointer_to_sym_table: u32,

    /// _the number of entries in the symbol table.
    /// Is zero if no COFF symbol table is presnet.
    pub number_of_symbols: u32,

    /// _the size of the optional header.
    /// _this value should be zero for an object file.
    pub size_of_optional_header: u16,

    /// Defines flags for various functionality in the executable.
    // _tODO parse this properly under a bitfield type.
    pub characteristics: u16,

    /// The optional header!
    pub optional_header: OptionalHeader64,
}

impl PeHeader64 {
    const MAGIC: &'static [u8] = &[0x50, 0x45, 0x00, 0x00];

    fn parse_from_pe_header(i: Input) -> Result<Self> {
        use nom::{
            bytes::complete::tag,
            error::context,
            sequence::tuple,
            number::complete::*,
        };

        // _tODO: parse all the below fields into u16, u64's etc.MAGIC
        // Do this via the blog post.

        let (
            i,
            (
                _,
                machine,
                number_of_sections,
                time_date_stamp,
                pointer_to_sym_table,
                number_of_symbols,
                size_of_optional_header,
                characteristics,
                optional_header,
            ),
        ) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Machine", Machine::parse),
            context("NumberOfSections", le_u16),
            context("_timeDateStamp", le_u32),
            context("Pointer_toSymbol_table", le_u32),
            context("NumberOfSymbols", le_u32),
            context("SizeOfOptionalHeader", le_u16),
            context("Characteristics", le_u16),
            context("OptionalHeader", OptionalHeader64::parse),
        ))(i)?;
        Ok((
            i,
            Self {
                machine,
                number_of_sections,
                time_date_stamp,
                pointer_to_sym_table,
                number_of_symbols,
                size_of_optional_header,
                characteristics,
                optional_header,
            },
        ))
    }

    /// _this parses assuming it has to skip over the MS-DOS header, and begins
    /// parsing at the offset contained in `0x3C`.
    pub fn parse(i: Input) -> Result<Self> {
        let offset= i[0x3c] as usize;
        Self::parse_from_pe_header(&i[offset..])
    }

    pub fn number_of_sections(&self) -> u16 {
        self.number_of_sections
    }

}

/// _the optional header for PE32 and PE64 are split
/// into three major parts:
///     
/// 0-28 (on 32-bit).
/// 0-24 (on 64-bit).
/// Standard fields, defined for all implementations of COFF.
///
///
/// 28-68 (on 32-bit).
/// 24-88 (on 64-bit).
/// Windows-Specific fields.
///
///
/// 96-Variable (on 32-bit).
/// 112-Variable (on 64-bit).
/// Data directories, address size pairs.
///
/// RVA in the headers refers to 'Relative Virtual Address'
#[derive(PartialEq, Debug)]
pub struct OptionalHeader64 {
    // ------ COFF ------

    pub major_linker_version: u8,

    pub minor_linker_version: u8,

    /// _the sum size of all code sections
    pub size_of_code: u32,

    pub size_of_initialized_data: u32,

    pub size_of_uninitialized_data: u32,

    /// _the address of the entry point relative to the
    /// image base when the executable is loaded into memory.
    pub address_of_entry_point: u32,

    /// _the address relative to the image base of the beginning-of-code section
    /// when it is loaded into memory.
    pub base_of_code: u32,

    // Note there is a `base_of_data` field present in PE32, not present here in the 64-bit version.

    // ------ COFF ------

    // Windows-specific Fields
    pub windows_header: WindowsFields,

    pub data_directories: DataDirectories,

}


// _tODO PE header bitflags and DLL Characteristics Bitflags aswell.


impl OptionalHeader64 {
    const MAGIC: &'static [u8] = &[0x0B, 0x02];

    fn parse(i: Input) -> Result<Self> {
        use nom::{
            bytes::complete::tag,
            error::context,
            sequence::tuple,
            number::complete::*,
        };
        // TODO as per the above parser
        let (i,(_, major_linker_version, minor_linker_version, size_of_code, size_of_initialized_data,
            size_of_uninitialized_data, address_of_entry_point, base_of_code,
            windows_header, data_directories)) = tuple((

            // COFF-standard
            context("Magic", tag(Self::MAGIC)),
            context("MajorLinkerVersion", le_u8),
            context("MinorLinkerVersion", le_u8),
            context("SizeOfCode", le_u32),
            context("SizeOfInitializedData", le_u32),
            context("SizeOfUninitializedData", le_u32),
            context("AddressOfEntryPoint", le_u32),
            context("BaseOfCode", le_u32),
            // Windows
            context("Windows", WindowsFields::parse),
            // Data Directories
            context("DataDirectories", DataDirectories::parse),


        ))(i)?;
        Ok((i, Self {
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            windows_header,
            data_directories,
        }))
    }
}

#[derive(PartialEq, Debug)]
pub struct WindowsFields {

    /// _the preferred address of the first byte
    /// of the image when loaded into memory
    pub image_base: u64,

    /// _the alignment of sections when they are loaded into memory.
    /// It must be greater than or equal to `file_alignment`.
    /// _the default is the page size for the arch, ex. `4096`.
    pub section_alignment: u32,

    /// _the alignment factor that is used to align
    /// the raw data of the sections in the image file.
    pub file_alignment: u32,

    pub major_os_version: u16,

    pub minor_os_version: u16,

    pub major_image_version: u16,

    pub minor_image_version: u16,

    pub major_subsystem_version: u16,

    pub minor_subsystem_version: u16,

    /// Reserved and **must** be zero.
    pub win32_version_value: u32,

    pub size_of_image: u32,

    pub size_of_headers: u32,

    /// _the image file checksum.
    /// _the algorithm for computing the checksum is incorporated into IMAGHELP.DLL
    pub checksum: u32,

    pub subsystem: Subsystem,

    pub dll_characteristics: u16,

    pub size_of_stack_reserve: u64,

    pub size_of_stack_commit: u64,

    pub size_of_heap_reserve: u64,

    pub size_of_heap_commit: u64,

    /// Reserved, **must** be zero.
    pub loader_flags: u32,

    /// _the number of data-directory entries in the remainder of the optional header.
    /// Each describes a location and size.
    pub number_of_rva_and_sizes: u32,
}

impl WindowsFields {
    fn parse(i: Input) -> Result<Self> {
        use nom::{
            error::context,
            sequence::tuple,
            number::complete::*,
        };

        let (i,(image_base, section_alignment, file_alignment, major_os_version, minor_os_version,
            major_image_version, minor_image_version, major_subsystem_version, minor_subsystem_version,
            win32_version_value, size_of_image, size_of_headers, checksum, subsystem,
            dll_characteristics, size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit, loader_flags,
            number_of_rva_and_sizes)) = tuple((
                context("ImageBase", le_u64),
                context("SectionAlignment", le_u32),
                context("FileAlignment", le_u32),
                context("MajorOperatingSystemVersion", le_u16),
                context("MinorOperatingSystemVersion", le_u16),
                context("MajorImageVersion", le_u16),
                context("MinorImageVersion", le_u16),
                context("MajorSubsystemVersion", le_u16),
                context("MinorSubsystemVersion", le_u16),
                context("Win32VersionValue", le_u32),
                context("SizeOfImage", le_u32),
                context("SizeOfHeaders", le_u32),
                context("CheckSum", le_u32),
                context("Subsystem", Subsystem::parse),
                context("DllCharacteristics", le_u16),
                context("SizeOfStackReserve", le_u64),
                context("SizeOfStackCommit", le_u64),
                context("SizeOfHeapReserve", le_u64),
                context("SizeOfHeapCommit", le_u64),
                context("LoaderFlags", le_u32),
                context("NumberOfRvaAndSizes", le_u32),
            ))(i)?;

        Ok((i, Self {
            image_base,
            section_alignment,
            file_alignment,
            major_os_version,
            minor_os_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes
        }))

    }
}

#[derive(PartialEq, Debug)]
pub struct DataDirectories {

    /// `.edata` - _the export table address and size.
    export_table: u64,

    /// `.idata` - _the import table address and size.
    import_table: u64,

    /// `.rsrc` - _the resource table address and size.
    resource_table: u64,

    /// `.pdata` - _the exception table address and size.
    exception_table: u64,

    /// _the certificate table address and size.
    certificate_table: u64,

    /// `.reloc` - _the base relocation table address and size.
    base_relocation_table: u64,

    /// `.debug` - _the debug data starting address and size.
    debug_data: u64,

    /// Reserved, **must** be zero.
    architecture: u64,

    /// _the RVA of the value to be stored in the global pointer register.
    global_ptr: u64,

    /// `.tls` - _the thread local storage (_tLS) table address and size.
    tls_table: u64,

    /// _the load configuration table address and size.
    load_config_table: u64,

    /// _the bound import table address and size.
    bound_import: u64,

    /// _the import address table and size.
    iat: u64,

    /// _the delay import descriptor address and size.
    delay_import_descriptor: u64,

    /// `.cormeta` (Object only) _the CLR runtime header address and size.
    clr_runtime_header: u64,

}

impl DataDirectories {
    fn parse(i: Input) -> Result<Self> {
        use nom::{
            error::context,
            sequence::tuple,
            number::complete::*,
        };

        let (i,(export_table, import_table, resource_table, exception_table, certificate_table,
                 base_relocation_table, debug_data, architecture, global_ptr, tls_table,
                 load_config_table, bound_import, iat, delay_import_descriptor,
                clr_runtime_header, _)) = tuple((
                context("ExportTable", le_u64),
                context("ImportTable", le_u64),
                context("ResourceTable", le_u64),
                context("ExceptionTable", le_u64),
                context("CertificateTable", le_u64),
                context("BaseRelocationTable", le_u64),
                context("Debug", le_u64),
                context("Architecture", le_u64),
                context("GlobalPtr", le_u64),
                context("TlsTable", le_u64),
                context("LoadConfigTable", le_u64),
                context("BoundImport", le_u64),
                context("IAT", le_u64),
                context("DelayImportDescriptor", le_u64),
                context("ClrRuntimeHeader", le_u64),
                context("Padding", nom::bytes::complete::tag(&[0, 0, 0, 0, 0, 0, 0, 0])), // NOTE: must be zero.
            ))(i)?;

        Ok((i, Self {
            export_table,
            import_table,
            resource_table,
            exception_table,
            certificate_table,
            base_relocation_table,
            debug_data,
            architecture,
            global_ptr,
            tls_table,
            load_config_table,
            bound_import,
            iat,
            delay_import_descriptor,
            clr_runtime_header,
        }))
    }
}






























#[cfg(test)]
mod tests {
    #[test]
    fn test_magic() {}
}
