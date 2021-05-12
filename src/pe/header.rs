use super::util::*;
use bitflags::*;
use std::convert::TryFrom;

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

#[derive(PartialEq, Debug)]
#[repr(C)]
pub struct DataDirectory {
    virtual_addr: Addr32,
    size: u32,
}

impl DataDirectory {
    pub fn parse(i: Input) -> Result<Self> {
        use nom::{error::context, number::complete::*, sequence::tuple};
        let (i, (virtual_addr, size)) = tuple((
            context("Virtual Address", Addr32::parse),
            context("Size", le_u32),
        ))(i)?;
        Ok((i, Self { virtual_addr, size }))
    }
}

bitflags! {
    #[allow(non_camel_case_types)]
    pub struct Characteristics: u16 {
        /// Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
        const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
        /// Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
        const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
        /// COFF line numbers have been removed. This flag is deprecated and should be zero.
        const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004;
        /// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008;
        /// Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        const IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010;
        // Application can handle > 2-GB addresses.
        const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
        /// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080;
        /// Machine is based on a 32-bit-word architecture.
        const IMAGE_FILE_32BIT_MACHINE = 0x0100;
        /// Debugging information is removed from the image file.
        const IMAGE_FILE_DEBUG_STRIPPED = 0x0200;
        /// If the image is on removable media, fully load it and copy it to the swap file.
        const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
        /// If the image is on network media, fully load it and copy it to the swap file.
        const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800;
        /// The image file is a system file, not a user program.
        const IMAGE_FILE_SYSTEM = 0x1000;
        /// The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        const IMAGE_FILE_DLL = 0x2000;
        /// The file should be run only on a uniprocessor machine.
        const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000;
        /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
        const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000;
        }
}

impl_parse_for_enumflags!(Characteristics, le_u16);

#[derive(Debug)]
pub struct PeHeader64 {
    /// the architecture of the machine, `0x8664`
    /// is AMD64 and `0x14C0` is i386.
    pub machine: Machine,

    /// The number of sections, aka the size of the section table.
    pub number_of_sections: u16,

    // The low 32 bits of the UNIX timestamp
    pub time_date_stamp: u32,

    /// The file offset of the COFF symbol table,
    /// is zero if no COFF symbol table is present (it should be,
    /// since COFF debugging information support is deprecated).
    pub pointer_to_sym_table: Addr32,

    /// The number of entries in the symbol table.
    /// Is zero if no COFF symbol table is present.
    pub number_of_symbols: u32,

    /// The size of the optional header.
    /// This value should be zero for an object file.
    pub size_of_optional_header: u16,

    /// Defines flags for various functionality in the executable.
    // TODO parse this properly under a bitfield type.
    pub characteristics: Characteristics,

    /// The optional header!
    pub optional_header: OptionalHeader64,
}

impl PeHeader64 {
    const MAGIC: &'static [u8] = &[0x50, 0x45, 0x00, 0x00];

    fn parse_from_pe_header(i: Input) -> Result<Self> {
        use nom::{bytes::complete::tag, error::context, number::complete::*, sequence::tuple};

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
            context("TimeDateStamp", le_u32),
            context("PointerToSymbolTable", Addr32::parse),
            context("NumberOfSymbols", le_u32),
            context("SizeOfOptionalHeader", le_u16),
            context("Characteristics", Characteristics::parse),
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
        let offset = i[0x3c] as usize;
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
    pub entry_point: Addr32,

    /// _the address relative to the image base of the beginning-of-code section
    /// when it is loaded into memory.
    pub base_of_code: u32,

    // Note there is a `base_of_data` field present in PE32, not present here in the 64-bit version.

    // ------ COFF ------

    // Windows-specific Fields
    pub windows_header: WindowsFields,

    pub data_directories: DataDirectories,
}

// TODO PE header bitflags and DLL Characteristics Bitflags aswell.

impl OptionalHeader64 {
    const MAGIC: &'static [u8] = &[0x0B, 0x02];

    fn parse(i: Input) -> Result<Self> {
        use nom::{bytes::complete::tag, error::context, number::complete::*, sequence::tuple};
        let (
            i,
            (
                _,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                entry_point,
                base_of_code,
                windows_header,
                data_directories,
            ),
        ) = tuple((
            // COFF-standard
            context("Magic", tag(Self::MAGIC)),
            context("MajorLinkerVersion", le_u8),
            context("MinorLinkerVersion", le_u8),
            context("SizeOfCode", le_u32),
            context("SizeOfInitializedData", le_u32),
            context("SizeOfUninitializedData", le_u32),
            context("AddressOfEntryPoint", Addr32::parse),
            context("BaseOfCode", le_u32),
            // Windows
            context("Windows", WindowsFields::parse),
            // Data Directories
            context("DataDirectories", DataDirectories::parse),
        ))(i)?;
        Ok((
            i,
            Self {
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                entry_point,
                base_of_code,
                windows_header,
                data_directories,
            },
        ))
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

    pub dll_characteristics: DllCharacteristics,

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

bitflags! {
    pub struct DllCharacteristics: u16 {
            /// Image can handle a high entropy 64-bit virtual address space.
            const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
            /// DLL can be relocated at load time.
            const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE =0x0040;
            /// Code Integrity checks are enforced.
            const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080;
            /// Image is NX compatible.
            const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;
            /// Isolation aware, but do not isolate the image.
            const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION =0x0200;
            /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
            const IMAGE_DLLCHARACTERISTICS_NO_SEH =0x0400;
            /// Do not bind the image.
            const IMAGE_DLLCHARACTERISTICS_NO_BIND =0x0800;
            /// Image must execute in an AppContainer.
            const IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000;
            /// A WDM driver.
            const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER =0x2000;
            /// Image supports Control Flow Guard.
            const IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000;
            /// Terminal Server aware.
            const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE =0x8000;
    }
}

impl_parse_for_enumflags!(DllCharacteristics, le_u16);

impl WindowsFields {
    fn parse(i: Input) -> Result<Self> {
        use nom::{error::context, number::complete::*, sequence::tuple};

        let (
            i,
            (
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
                number_of_rva_and_sizes,
            ),
        ) = tuple((
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
            context("DllCharacteristics", DllCharacteristics::parse),
            context("SizeOfStackReserve", le_u64),
            context("SizeOfStackCommit", le_u64),
            context("SizeOfHeapReserve", le_u64),
            context("SizeOfHeapCommit", le_u64),
            context("LoaderFlags", le_u32),
            context("NumberOfRvaAndSizes", le_u32),
        ))(i)?;

        Ok((
            i,
            Self {
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
                number_of_rva_and_sizes,
            },
        ))
    }
}

#[derive(PartialEq, Debug)]
pub struct DataDirectories {
    /// `.edata` - _the export table address and size.
    export_table: DataDirectory,

    /// `.idata` - _the import table address and size.
    import_table: DataDirectory,

    /// `.rsrc` - _the resource table address and size.
    resource_table: DataDirectory,

    /// `.pdata` - _the exception table address and size.
    exception_table: DataDirectory,

    /// _the certificate table address and size.
    certificate_table: DataDirectory,

    /// `.reloc` - _the base relocation table address and size.
    base_relocation_table: DataDirectory,

    /// `.debug` - _the debug data starting address and size.
    debug_data: DataDirectory,

    /// _the RVA of the value to be stored in the global pointer register.
    global_ptr: Addr,

    /// `.tls` - _the thread local storage (_tLS) table address and size.
    tls_table: DataDirectory,

    /// _the load configuration table address and size.
    load_config_table: DataDirectory,

    /// _the bound import table address and size.
    bound_import: DataDirectory,

    /// _the import address table and size.
    iat: DataDirectory,

    /// _the delay import descriptor address and size.
    delay_import_descriptor: DataDirectory,

    /// `.cormeta` (Object only) _the CLR runtime header address and size.
    clr_runtime_header: DataDirectory,
}

impl DataDirectories {
    fn parse(i: Input) -> Result<Self> {
        use nom::{error::context, sequence::tuple};

        let (
            i,
            (
                export_table,
                import_table,
                resource_table,
                exception_table,
                certificate_table,
                base_relocation_table,
                debug_data,
                _,
                global_ptr,
                tls_table,
                load_config_table,
                bound_import,
                iat,
                delay_import_descriptor,
                clr_runtime_header,
                _,
            ),
        ) = tuple((
            context("ExportTable", DataDirectory::parse),
            context("ImportTable", DataDirectory::parse),
            context("ResourceTable", DataDirectory::parse),
            context("ExceptionTable", DataDirectory::parse),
            context("CertificateTable", DataDirectory::parse),
            context("BaseRelocationTable", DataDirectory::parse),
            context("Debug", DataDirectory::parse),
            context(
                "Architecture",
                nom::bytes::complete::tag(&[0, 0, 0, 0, 0, 0, 0, 0]),
            ), // NOTE: must be zero.
            context("GlobalPtr", Addr::parse),
            context("TlsTable", DataDirectory::parse),
            context("LoadConfigTable", DataDirectory::parse),
            context("BoundImport", DataDirectory::parse),
            context("IAT", DataDirectory::parse),
            context("DelayImportDescriptor", DataDirectory::parse),
            context("ClrRuntimeHeader", DataDirectory::parse),
            context(
                "Padding",
                nom::bytes::complete::tag(&[0, 0, 0, 0, 0, 0, 0, 0]),
            ), // NOTE: must be zero.
        ))(i)?;

        Ok((
            i,
            Self {
                export_table,
                import_table,
                resource_table,
                exception_table,
                certificate_table,
                base_relocation_table,
                debug_data,
                global_ptr,
                tls_table,
                load_config_table,
                bound_import,
                iat,
                delay_import_descriptor,
                clr_runtime_header,
            },
        ))
    }
}
