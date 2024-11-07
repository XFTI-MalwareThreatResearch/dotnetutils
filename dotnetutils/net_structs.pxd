#cython: language_level=3
cimport numpy

cdef class DotNetDataReader:
    cdef int __data_len
    cdef bytes __data
    cdef int __current_pos

    cpdef bint is_end(self)
    cpdef void seek(self, int offset, int where)
    cpdef int tell(self)
    cpdef numpy.uint8_t read_byte(self)
    cpdef numpy.int8_t read_sbyte(self)
    cpdef numpy.int16_t read_int16(self)
    cpdef numpy.int64_t read_int64(self)
    cpdef numpy.uint16_t read_uint16(self)
    cpdef numpy.uint64_t read_uint64(self)
    cpdef list read_decimal(self)
    cpdef numpy.float32_t read_single(self)
    cpdef numpy.float64_t read_double(self)
    cpdef bint read_boolean(self)
    cpdef numpy.uint16_t read_char(self)
    cpdef str read_serialized_string(self, encoding=*)
    cpdef numpy.int32_t read_int32(self)
    cpdef numpy.uint32_t read_uint32(self)
    cpdef numpy.uint32_t read_encoded_uint32(self)
    cpdef numpy.uint32_t read_compressed_uint(self)
    cpdef numpy.int32_t read_encoded_int32(self)
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
    COR_ILEXCEPTION_CLAUSE_EXCEPTION = 0x0000
    COR_ILEXCEPTION_CLAUSE_FILTER = 0x0001
    COR_ILEXCEPTION_CLAUSE_FINALLY = 0x0002
    COR_ILEXCPETION_CLAUSE_FAULT = 0x0004

cpdef enum CorHeapBitmask:
    BITMASK_STRINGS = 0x1
    BITMASK_GUID = 0x2
    BITMASK_BLOB = 0x4

cpdef enum COMIMAGE_FLAGS:
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010
    COMIMAGE_FLAGS_ILONLY = 0x00000001
    COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000