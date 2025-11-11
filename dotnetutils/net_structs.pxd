#cython: language_level=3
#distutils: language=c++



from libc.stdint cimport uint16_t, uint32_t, uint8_t, uint64_t, int64_t
from libc.stddef cimport wchar_t


"""
Structures required to parse .NET metadata headers.
"""

ctypedef struct IMAGE_DOS_HEADER:
    uint16_t e_magic
    uint16_t e_cblp
    uint16_t e_cp
    uint16_t e_crlc
    uint16_t e_cparhdr
    uint16_t e_minalloc
    uint16_t e_maxalloc
    uint16_t e_ss
    uint16_t e_sp
    uint16_t e_csum
    uint16_t e_ip
    uint16_t e_cs
    uint16_t e_lfarlc
    uint16_t e_ovno
    uint16_t e_res[4]
    uint16_t e_oemid
    uint16_t e_oeminfo
    uint16_t e_res2[10]
    uint32_t e_lfanew

ctypedef struct IMAGE_FILE_HEADER:
    uint16_t Machine
    uint16_t NumberOfSections
    uint32_t TimeDateStamp
    uint32_t PointerToSymbolTable
    uint32_t NumberOfSymbols
    uint16_t SizeOfOptionalHeader
    uint16_t Characteristics

ctypedef struct IMAGE_DATA_DIRECTORY:
    uint32_t VirtualAddress
    uint32_t Size

ctypedef struct COR20_METADATA_TABLE_HEADER:
    uint32_t Reserved
    uint8_t MajorVersion
    uint8_t MinorVersion
    uint8_t HeapOffsetSizes
    uint8_t Reserved2
    uint64_t Valid
    uint64_t Sorted

ctypedef union COR20_ENTRYPOINT_UNION:
    uint32_t EntryPointToken
    uint32_t EntryPointRVA

ctypedef struct IMAGE_COR20_HEADER:
    uint32_t cb
    uint16_t MajorRuntimeVersion
    uint16_t MinorRuntimeVersion
    IMAGE_DATA_DIRECTORY MetaData
    uint32_t Flags
    COR20_ENTRYPOINT_UNION EntryPoint
    IMAGE_DATA_DIRECTORY Resources
    IMAGE_DATA_DIRECTORY StrongNameSignature
    IMAGE_DATA_DIRECTORY CodeManagerTable
    IMAGE_DATA_DIRECTORY VTableFixups
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps
    IMAGE_DATA_DIRECTORY ManagedNativeHeader

ctypedef struct IMAGE_EXPORT_DIRECTORY:
    uint32_t   Characteristics
    uint32_t   TimeDateStamp
    uint16_t    MajorVersion
    uint16_t    MinorVersion
    uint32_t   Name
    uint32_t   Base
    uint32_t   NumberOfFunctions
    uint32_t   NumberOfNames
    uint32_t   AddressOfFunctions
    uint32_t   AddressOfNames
    uint32_t   AddressOfNameOrdinals

cdef enum:
    IMAGE_NUMBEROF_DATA_DIRECTORY_ENTRIES = 16

ctypedef struct IMAGE_OPTIONAL_HEADER32:
    uint16_t Magic
    uint8_t MajorLinkerVersion
    uint8_t MinorLinkerVersion
    uint32_t SizeOfCode
    uint32_t SizeOfInitializedData
    uint32_t SizeOfUninitializedData
    uint32_t AddressOfEntryPoint
    uint32_t BaseOfCode
    uint32_t BaseOfData
    uint32_t ImageBase
    uint32_t SectionAlignment
    uint32_t FileAlignment
    uint16_t MajorOperatingSystemVersion
    uint16_t MinorOperatingSystemVersion
    uint16_t MajorImageVersion
    uint16_t MinorImageVersion
    uint16_t MajorSubsystemVersion
    uint16_t MinorSubsystemVersion
    uint32_t Win32VersionValue
    uint32_t SizeOfImage
    uint32_t SizeOfHeaders
    uint32_t CheckSum
    uint16_t SubSystem
    uint16_t DllCharacteristics
    uint32_t SizeOfStackReserve
    uint32_t SizeOfStackCommit
    uint32_t SizeOfHeapReserve
    uint32_t SizeOfHeapCommit
    uint32_t LoaderFlags
    uint32_t NumberOfRvaAndSizes
    IMAGE_DATA_DIRECTORY DataDirectory[16]

ctypedef struct IMAGE_OPTIONAL_HEADER64:
    uint16_t Magic
    uint8_t MajorLinkerVersion
    uint8_t MinorLinkerVersion
    uint32_t SizeOfCode
    uint32_t SizeOfInitializedData
    uint32_t SizeOfUninitializedData
    uint32_t AddressOfEntryPoint
    uint32_t BaseOfCode
    uint64_t ImageBase
    uint32_t SectionAlignment
    uint32_t FileAlignment
    uint16_t MajorOperatingSystemVersion
    uint16_t MinorOperatingSystemVersion
    uint16_t MajorImageVersion
    uint16_t MinorImageVersion
    uint16_t MajorSubsystemVersion
    uint16_t MinorSubsystemVersion
    uint32_t Win32VersionValue
    uint32_t SizeOfImage
    uint32_t SizeOfHeaders
    uint32_t CheckSum
    uint16_t SubSystem
    uint16_t DllCharacteristics
    uint64_t SizeOfStackReserve
    uint64_t SizeOfStackCommit
    uint64_t SizeOfHeapReserve
    uint64_t SizeOfHeapCommit
    uint32_t LoaderFlags
    uint32_t NumberOfRvaAndSizes
    IMAGE_DATA_DIRECTORY DataDirectory[16]

ctypedef union Misc_Union:
    uint32_t PhysicalAddress
    uint32_t VirtualSize

cdef enum:
    IMAGE_SIZEOF_SHORT_NAME = 8

ctypedef struct IMAGE_SECTION_HEADER:
    char Name[8]
    Misc_Union Misc
    uint32_t VirtualAddress
    uint32_t SizeOfRawData
    uint32_t PointerToRawData
    uint32_t PointerToRelocations
    uint32_t PointerToLineNumbers
    uint16_t NumberOfRelocations
    uint16_t NumberOfLinenumbers
    uint32_t Characteristics

ctypedef struct IMAGE_NT_HEADERS32:
    uint32_t Signature
    IMAGE_FILE_HEADER FileHeader
    IMAGE_OPTIONAL_HEADER32 OptionalHeader

ctypedef struct IMAGE_NT_HEADERS64:
    uint32_t Signature
    IMAGE_FILE_HEADER FileHeader
    IMAGE_OPTIONAL_HEADER64 OptionalHeader

cdef enum: 
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
    IMAGE_DIRECTORY_ENTRY_DEBUG = 6
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
    IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
    IMAGE_DIRECTORY_ENTRY_IAT = 12
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
    IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    IMAGE_DIRECTORY_ENTRY_TLS = 9

ctypedef struct IMAGE_BASE_RELOCATION:
    uint32_t VirtualAddress
    uint32_t BlockSize

ctypedef union DUMMYUNIONIAT:
    uint32_t Characteristics
    uint32_t OriginalFirstThunk

ctypedef struct IMAGE_IMPORT_DESCRIPTOR:
    DUMMYUNIONIAT DUMMYUNIONNAME1
    uint32_t TimeDateStamp
    uint32_t ForwarderChain
    uint32_t Name
    uint32_t FirstThunk

ctypedef union thunk_u1_32:
    uint32_t Function
    uint32_t Ordinal
    uint32_t AddressOfData
    uint32_t ForwarderString1

ctypedef union thunk_u1_64:
    uint64_t Function
    uint64_t Ordinal
    uint64_t AddressOfData
    uint64_t ForwarderString1

ctypedef struct IMAGE_THUNK_DATA32:
    thunk_u1_32 u1

ctypedef struct IMAGE_THUNK_DATA64:
    thunk_u1_64 u1

cdef uint64_t IMAGE_ORDINAL_FLAG32 = 0x80000000
cdef uint64_t IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
cdef enum:
    IMAGE_SCN_CNT_CODE = 0x20
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80

ctypedef struct IMAGE_RESOURCE_DIRECTORY:
    uint32_t Characteristics
    uint32_t TimeDateStamp
    uint16_t MajorVersion
    uint16_t MinorVersion
    uint16_t NumberOfNamedEntries
    uint16_t NumberOfIdEntries

cdef extern from *:
    """
    typedef struct NAMEOFFSET_STRUCT_T {
        uint32_t NameOffset: 31;
        uint32_t NameIsString: 1;
    } NAMEOFFSET_STRUCT;
    """
    ctypedef struct NAMEOFFSET_STRUCT:
        uint32_t NameOffset
        uint32_t NameIsString

ctypedef union NAME_RSRC:
    NAMEOFFSET_STRUCT NameOffset
    uint32_t Name
    uint16_t Id

cdef extern from *:
    """
    typedef struct DIRECTORYOFFSET_STRUCT_T {
        uint32_t OffsetToDirectory: 31;
        uint32_t DataIsDirectory: 1;
    } DIRECTORYOFFSET_STRUCT;
    """
    ctypedef struct DIRECTORYOFFSET_STRUCT:
        uint32_t OffsetToDirectory
        uint32_t DataIsDirectory

ctypedef union OFFSETTODATA_RSRC:
    uint32_t OffsetToData
    DIRECTORYOFFSET_STRUCT OffsetToDirectory

ctypedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY:
    NAME_RSRC Name
    OFFSETTODATA_RSRC OffsetToData

ctypedef struct IMAGE_RESOURCE_DATA_ENTRY:
    uint32_t OffsetToData
    uint32_t Size
    uint32_t CodePage
    uint32_t Reserved

ctypedef struct IMAGE_DEBUG_DIRECTORY:
    uint32_t Characteristics
    uint32_t TimeDateStamp
    uint16_t MajorVersion
    uint16_t MinorVersion
    uint32_t Type
    uint32_t SizeOfData
    uint32_t AddressOfRawData
    uint32_t PointerToRawData

cdef class DotNetDataReader:
    cdef int __data_len
    cdef bytes __data
    cdef int __current_pos

    cpdef bint is_end(self)
    cpdef void seek(self, int offset, int where)
    cpdef int tell(self)
    cpdef unsigned char read_byte(self)
    cpdef char read_sbyte(self)
    cpdef short read_int16(self)
    cpdef int64_t read_int64(self)
    cpdef unsigned short read_uint16(self)
    cpdef uint64_t read_uint64(self)
    cpdef list read_decimal(self)
    cpdef float read_single(self)
    cpdef double read_double(self)
    cpdef bint read_boolean(self)
    cpdef unsigned short read_char(self)
    cpdef str read_serialized_string(self, encoding=*)
    cpdef int read_int32(self)
    cpdef unsigned int read_uint32(self)
    cpdef unsigned int read_encoded_uint32(self)
    cpdef unsigned int read_compressed_uint(self)
    cpdef int read_encoded_int32(self)
    cpdef bytes read(self, int amt=*)
    cpdef bytes read_all(self)
    cpdef int read_single_byte(self)

cpdef enum IMAGE_OPTIONAL_MAGIC:
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

cpdef enum CorElementType:
    ELEMENT_TYPE_END = 0x0
    ELEMENT_TYPE_VOID = 0x1
    ELEMENT_TYPE_BOOLEAN = 0x2
    ELEMENT_TYPE_CHAR = 0x3
    ELEMENT_TYPE_I1 = 0x4
    ELEMENT_TYPE_U1 = 0x5
    ELEMENT_TYPE_I2 = 0x6
    ELEMENT_TYPE_U2 = 0x7
    ELEMENT_TYPE_I4 = 0x8
    ELEMENT_TYPE_U4 = 0x9
    ELEMENT_TYPE_I8 = 0xa
    ELEMENT_TYPE_U8 = 0xb
    ELEMENT_TYPE_R4 = 0xc
    ELEMENT_TYPE_R8 = 0xd
    ELEMENT_TYPE_STRING = 0xe
    ELEMENT_TYPE_PTR = 0xf
    ELEMENT_TYPE_BYREF = 0x10
    ELEMENT_TYPE_VALUETYPE = 0x11
    ELEMENT_TYPE_CLASS = 0x12
    ELEMENT_TYPE_VAR = 0x13
    ELEMENT_TYPE_ARRAY = 0x14
    ELEMENT_TYPE_GENERICINST = 0x15
    ELEMENT_TYPE_TYPEDBYREF = 0x16
    ELEMENT_TYPE_I = 0x18
    ELEMENT_TYPE_U = 0x19
    ELEMENT_TYPE_FNPTR = 0x1B
    ELEMENT_TYPE_OBJECT = 0x1C
    ELEMENT_TYPE_SZARRAY = 0x1D
    ELEMENT_TYPE_MVAR = 0x1e
    ELEMENT_TYPE_CMOD_REQD = 0x1F
    ELEMENT_TYPE_CMOD_OPT = 0x20
    ELEMENT_TYPE_INTERNAL = 0x21
    ELEMENT_TYPE_MAX = 0x22
    ELEMENT_TYPE_MODIFIER = 0x40
    ELEMENT_TYPE_SENTINEL = 0x01 | ELEMENT_TYPE_MODIFIER
    ELEMENT_TYPE_PINNED = 0x05 | ELEMENT_TYPE_MODIFIER
    ELEMENT_TYPE_R4_HFA = 0x06 | ELEMENT_TYPE_MODIFIER
    ELEMENT_TYPE_R8_HFA = 0x07 | ELEMENT_TYPE_MODIFIER

    ELEMENT_TYPE_MODULE = 0x3F
    ELEMENT_TYPE_VALUEARRAY = 0x17
    INVALID = -1

cpdef enum CorTypeAttr:
    tdVisibilityMask        =   0x00000007,
    tdNotPublic             =   0x00000000,     # Class is not public scope.
    tdPublic                =   0x00000001,     # Class is public scope.
    tdNestedPublic          =   0x00000002,     # Class is nested with public visibility.
    tdNestedPrivate         =   0x00000003,     # Class is nested with private visibility.
    tdNestedFamily          =   0x00000004,     # Class is nested with family visibility.
    tdNestedAssembly        =   0x00000005,     # Class is nested with assembly visibility.
    tdNestedFamANDAssem     =   0x00000006,     # Class is nested with family and assembly visibility.
    tdNestedFamORAssem      =   0x00000007,     # Class is nested with family or assembly visibility.

    # Use this mask to retrieve class layout information
    tdLayoutMask            =   0x00000018,
    tdAutoLayout            =   0x00000000,     # Class fields are auto-laid out
    tdSequentialLayout      =   0x00000008,     # Class fields are laid out sequentially
    tdExplicitLayout        =   0x00000010,     # Layout is supplied explicitly
    # end layout mask

    # Use this mask to retrieve class semantics information.
    tdClassSemanticsMask    =   0x00000060,
    tdClass                 =   0x00000000,     # Type is a class.
    tdInterface             =   0x00000020,     # Type is an interface.
    # end semantics mask

    # Special semantics in addition to class semantics.
    tdAbstract              =   0x00000080,     # Class is abstract
    tdSealed                =   0x00000100,     # Class is concrete and may not be extended
    tdSpecialName           =   0x00000400,     # Class name is special. Name describes how.

    # Implementation attributes.
    tdImport                =   0x00001000,     # Class / interface is imported
    tdSerializable          =   0x00002000,     # The class is Serializable.

    # Use tdStringFormatMask to retrieve string information for native interop
    tdStringFormatMask      =   0x00030000,
    tdAnsiClass             =   0x00000000,     # LPTSTR is interpreted as ANSI in this class
    tdUnicodeClass          =   0x00010000,     # LPTSTR is interpreted as UNICODE
    tdAutoClass             =   0x00020000,     # LPTSTR is interpreted automatically
    tdCustomFormatClass     =   0x00030000,     # A non-standard encoding specified by CustomFormatMask
    tdCustomFormatMask      =   0x00C00000,     # Use this mask to retrieve non-standard encoding information for native interop. The meaning of the values of these 2 bits is unspecified.

    # end string format mask

    tdBeforeFieldInit       =   0x00100000,     # Initialize the class any time before first static field access.
    tdForwarder             =   0x00200000,     # This ExportedType is a type forwarder.

    # Flags reserved for runtime use.
    tdReservedMask          =   0x00040800,
    tdRTSpecialName         =   0x00000800,     # Runtime should check name encoding.
    tdHasSecurity           =   0x00040000,     # Class has security associate with it.

cpdef enum CorMethodAttr:
    mdMemberAccessMask = 0x0007
    mdPrivateScope = 0x0000
    mdPrivate = 0x0001
    mdFamANDAssem = 0x0002
    mdAssem = 0x0003
    mdFamily = 0x0004
    mdFamORAssem = 0x0005
    mdPublic = 0x0006

    mdStatic = 0x0010
    mdFinal = 0x0020
    mdVirtual = 0x0040
    mdHideBySig = 0x0080

    mdVtableLayoutMask = 0x0100
    mdReuseSlot = 0x0000
    mdNewSlot = 0x0100

    mdCheckAccessOnOverride = 0x0200
    mdAbstract = 0x0400
    mdSpecialName = 0x0800

    mdPinvokeImpl = 0x2000
    mdUnmanagedExport = 0x0008

    mdReservedMask = 0xd000
    mdRTSpecialName = 0x1000
    mdHasSecurity = 0x4000
    mdRequireSecObject = 0x8000

cpdef enum CorCallingConvention:
    Default = 0x0
    C = 0x1
    StdCall = 0x2
    ThisCall = 0x3
    FastCall = 0x4
    VarArg = 0x5
    Field = 0x6
    LocalSig = 0x7
    Property = 0x8
    Unmanaged = 0x9
    GenericInst = 0xA
    NativeVarArg = 0xB
    Mask = 0x0F
    Generic = 0x10
    HasThis = 0x20
    ExplicitThis = 0x40
    ReservedByCLR = 0x80

cpdef enum CorFieldAttr:
    fdFieldAccessMask = 0x0007
    fdPrivateScope = 0x0000
    fdPrivate = 0x0001
    fdFamANDAssem = 0x0002
    fdAssembly = 0x0003
    fdFamily = 0x0004
    fdFamORAssem = 0x0005
    fdPublic = 0x0006

    fdStatic = 0x0010
    fdInitOnly = 0x0020
    fdLiteral = 0x0040
    fdNotSerialized = 0x0080

    fdSpecialName = 0x0200

    fdPinvokeImpl = 0x2000

    fdReservedMask = 0x9500
    fdRTSpecialName = 0x0400
    fdHasFieldMarshal = 0x1000
    fdHasDefault = 0x8000
    fdHasFieldRVA = 0x0100

cpdef enum CorMethodSemanticsAttr:
    msSetter    =   0x0001
    msGetter    =   0x0002
    msOther     =   0x0004
    msAddOn     =   0x0008
    msRemoveOn  =   0x0010
    msFire      =   0x0020

cpdef enum CorILMethod:
    FatFormat = 0x3
    TinyFormat = 0x2
    MoreSects = 0x8
    InitLocals = 0x10

    Sect_EHTable = 0x1
    Sect_OptILTable = 0x2
    Sect_FatFormat = 0x40
    Sect_MoreSects = 0x80

cpdef enum CorResourceTypeCode:
    Null = 0
    String = 1
    Boolean = 2
    Char = 3
    Byte = 4
    SByte = 5
    Int16 = 6
    UInt16 = 7
    Int32 = 8
    UInt32 = 9
    Int64 = 0x0A
    Uint64 = 0x0B
    Single = 0x0C
    Double = 0x0D
    Decimal = 0x0E
    DateTime = 0x0F
    TimeSpan = 0x10
    ByteArray = 0x20
    Stream = 0x21
    UserTypes = 0x40

cpdef enum CorRecordTypeEnumeration:
    SerializedStreamHeader = 0
    ClassWithId = 1
    SystemClassWithMembers = 2
    ClassWithMembers = 3
    SystemClassWithMembersAndTypes = 4
    ClassWithMembersAndTypes = 5
    BinaryObjectString = 6
    BinaryArray = 7
    MemberPrimitiveTyped = 8
    MemberReference = 9
    ObjectNull = 10
    MessageEnd = 11
    BinaryLibrary = 12
    ObjectNullMultiple256 = 13
    ObjectNullMultiple = 14
    ArraySinglePrimitive = 15
    ArraySingleObject = 16
    ArraySingleString = 17
    MethodCall = 21
    MethodReturn = 22

cpdef enum CorILExceptionClause:
    Exception = 0x0000
    Filter = 0x0001
    Finally = 0x0002
    Fault = 0x0004

cpdef enum CorHeapBitmask:
    BITMASK_STRINGS = 0x1
    BITMASK_GUID = 0x2
    BITMASK_BLOB = 0x4

cpdef enum COMIMAGE_FLAGS:
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010
    COMIMAGE_FLAGS_ILONLY = 0x00000001
    COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000

ctypedef struct VS_FIXEDFILEINFO:
    uint32_t dwSignature
    uint32_t dwStrucVersion
    uint32_t dwFileVersionMS
    uint32_t dwFileVersionLS
    uint32_t dwProductVersionMS
    uint32_t dwProductVersionLS
    uint32_t dwFileFlagsMask
    uint32_t dwFileFlags
    uint32_t dwFileOS
    uint32_t dwFileType
    uint32_t dwFileSubtype
    uint32_t dwFileDateMS
    uint32_t dwFileDateLS

ctypedef struct VS_VERSIONINFO:
    uint16_t wLength
    uint16_t wValueLength
    uint16_t wType