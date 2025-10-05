#cython: language_level=3
#distutils: language=c++

from dotnetutils cimport net_row_objects, net_sigs, dotnetpefile
from dotnetutils cimport net_emulator
from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from libc.stdint cimport int64_t, uint64_t
from dotnetutils.net_structs cimport CorElementType
from cpython.ref cimport PyObject
from libcpp.vector cimport vector

cdef str remove_generics_from_name(str name)

cdef void initialize_array_helper(DotNetArray arr, net_row_objects.RowObject runtime_handle) except *

cdef void blockcopy_helper(DotNetArray src, DotNetInt32 srcOffset, DotNetArray dst, DotNetInt32 dstOffset, DotNetInt32 count) except *
#TODO: Could maybe change this to a fused type with either dotnetobject or EmulatorAppDomain
ctypedef net_emulator.StackCell (*emu_func_type)(DotNetObject, net_emulator.StackCell * params, int nparams)

ctypedef net_emulator.StackCell (*static_func_type)(net_emulator.EmulatorAppDomain, net_emulator.StackCell * params, int nparams)

ctypedef DotNetObject (*newobj_func_type)(net_emulator.DotNetEmulator emulator_obj)

#NOTE: probably can remove cython sigs for all methods that arent in DotNetObject, its going to be called as a python object anyway.
cdef class DotNetObject:
    cdef net_emulator.DotNetEmulator __emulator_obj
    cdef unordered_map[int, net_emulator.StackCell] __fields
    cdef net_row_objects.TypeDefOrRef type_obj
    cdef net_sigs.TypeSig type_sig_obj
    cdef bint __initialized
    cdef unordered_map[string, emu_func_type] __functions

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef bint is_number(self)

    cdef bint has_function(self, bytes name)

    cdef bint is_null(self)

    cdef bint is_true(self)

    cdef bint is_false(self)

    cdef void flag_null(self)

    cdef void __clear_fields(self)

    cdef emu_func_type get_function(self, bytes name)

    cdef void add_function(self, bytes name, emu_func_type func)

    cpdef net_emulator.DotNetEmulator get_emulator_obj(self)

    cdef void set_field(self, int idno, net_emulator.StackCell val)

    cdef net_emulator.StackCell get_field(self, int idno)

    cpdef net_row_objects.TypeDefOrRef get_type_obj(self)

    cpdef void set_type_obj(self, net_row_objects.TypeDefOrRef type_obj)

    cpdef net_sigs.TypeSig get_type_sig_obj(self)

    cpdef void set_type_sig_obj(self, net_sigs.TypeSig type_sig_obj)

    cdef void _initialize_field(self, int field_rid)

    cpdef void initialize_type(self, net_row_objects.TypeDefOrRef type_obj)

    cpdef get_type(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject duplicate(self)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject ToString(self, net_emulator.StackCell * params, int nparams)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetNumber(DotNetObject):
    cdef unsigned char * _ptr
    cdef int __amt_bytes
    cdef CorElementType __num_type

    cdef bint ptr_check(self)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef CorElementType get_num_type(self)

    cdef bint is_number(self)

    cdef void reset(self)
    
    cdef DotNetObject duplicate(self)

    cpdef object as_python_obj(self)

    cpdef bytes as_bytes(self)

    cdef bint is_signed(self)
    
    cdef bint is_float(self)

    cdef bint val_is_zero(self)

    cdef void init_zero(self)

    cdef DotNetNumber convert_unsigned(self)

    cdef void from_long(self, int64_t num)

    cdef void from_int(self, int num)

    cdef void from_uchar(self, unsigned char num)

    cdef void from_uint(self, unsigned int num)
    
    cdef void from_ulong(self, uint64_t num)

    cdef void from_bool(self, bint num)

    cdef void from_char(self, char num)

    cdef void from_float(self, float num)

    cdef void from_double(self, double num)

    cdef void from_short(self, short num)

    cdef void from_ushort(self, unsigned short num)

    cdef void init_from_ptr(self, unsigned char * ptr, int ptr_size) except *
    
    cdef int __util_get_type_size(self, CorElementType cor_type)

    cdef bint __check_size(self, int amt_bytes, CorElementType num_type)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef unsigned char as_uchar(self)

    cdef unsigned short as_ushort(self)

    cdef unsigned int as_uint(self)

    cdef uint64_t as_ulong(self)

    cdef bint as_bool(self)

    cdef char as_char(self)

    cdef short as_short(self)

    cdef int as_int(self)

    cdef int64_t as_long(self)

    cdef float as_float(self)

    cdef double as_double(self)

    cdef DotNetObject ToString(self, net_emulator.StackCell * params, int nparams)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetIntPtr(DotNetNumber):

    @staticmethod
    cdef DotNetObject Zero(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetUIntPtr(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

    @staticmethod
    cdef DotNetObject op_Explicit(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetInt8(DotNetNumber):
    
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetInt16(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetInt32(DotNetNumber):
    cdef DotNetInt32 CompareTo(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetInt64(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetUInt8(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetUInt16(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetUInt32(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetUInt64(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetSingle(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetDouble(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

    cdef DotNetNumber add(self, DotNetNumber number)

    cdef DotNetNumber subtract(self, DotNetNumber number)

    cdef DotNetNumber multiply(self, DotNetNumber number)

    cdef DotNetNumber divide(self, DotNetNumber number)

    cdef DotNetNumber xor(self, DotNetNumber number)

    cdef DotNetNumber andop(self, DotNetNumber number)

    cdef DotNetNumber orop(self, DotNetNumber number)

    cdef DotNetNumber neg(self)

    cdef DotNetNumber notop(self)

    cdef DotNetNumber rem(self, DotNetNumber number)

    cdef DotNetNumber shl(self, DotNetNumber number)

    cdef DotNetNumber shr(self, DotNetNumber number)

    cdef bint equals(self, DotNetNumber other)

    cdef bint notequals(self, DotNetNumber other)

    cdef bint lessthanequals(self, DotNetNumber other)

    cdef bint lessthan(self, DotNetNumber other)

    cdef bint greaterthan(self, DotNetNumber other)

    cdef bint greaterthanequals(self, DotNetNumber other)

cdef class DotNetBoolean(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

cdef class DotNetVoid(DotNetNumber):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

cdef class DotNetChar(DotNetUInt16):
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetNumber cast(self, CorElementType new_type)

cdef class DotNetType(DotNetObject):
    cdef net_row_objects.RowObject type_handle
    cdef net_sigs.TypeSig sig_obj

    cdef DotNetObject get_IsValueType(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cpdef get_type_handle(self)

    cdef DotNetObject get_IsByRef(self, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject op_Equality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject op_Inequality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject GetTypeFromHandle(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Module(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetFields(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_MetadataToken(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Assembly(self, net_emulator.StackCell * params, int nparams)


cdef class DotNetMonitor(DotNetObject):

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    @staticmethod
    cdef DotNetObject Enter(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Exit(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetDictionary(DotNetObject):
    cdef dict __internal_dict

    cdef DotNetObject duplicate(self)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject TryGetValue(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Item(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Add(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ContainsKey(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Count(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetConcurrentDictionary(DotNetDictionary):
    
    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

cdef class DotNetStringBuilder(DotNetObject):
    cdef bytes char_array
    cdef bint is_wide

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject Append(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ToString(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetStream(DotNetObject):
    cdef DotNetArray _internal
    cdef int64_t _position

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetArray get_internal_array(self)

    cdef DotNetObject ReadBytes(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Read(self, net_emulator.StackCell * params, int nparams)
    
    cdef DotNetObject set_Position(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Position(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ReadByte(self, net_emulator.StackCell * params, int nparams)
    
    cdef DotNetObject get_Length(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Write(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Close(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetMemoryStream(DotNetStream):

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject ToArray(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetAssemblyName(DotNetObject):
    cdef bytes name
    cdef DotNetAssembly assembly

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject GetPublicKeyToken(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject get_Name(self, net_emulator.StackCell * params, int nparams)


cdef class DotNetManifestModule(DotNetObject):
    cdef DotNetAssembly dnassembly

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)
    
    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

cdef class DotNetAssembly(DotNetObject):
    """
    This class is meant to fool checks to ensure that
    Deobfuscation methods are being executed by their assembly.
    """
    cdef net_row_objects.RowObject module

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cpdef get_module(self)

    cdef DotNetObject get_ManifestModule(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject get_EntryPoint(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject get_FullName(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Location(self, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject GetExecutingAssembly(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject GetCallingAssembly(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetManifestResourceStream(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject GetManifestResourceNames(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject GetName(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject GetModules(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject Equals(self, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject op_Inequality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Load(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetList(DotNetObject):
    cdef list internal

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject AddRange(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Add(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Count(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Count(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Item(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Item(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Sort(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetArray(DotNetObject):
    cdef net_emulator.StackCell * __internal_array
    cdef uint64_t __size

    cdef net_emulator.StackCell _get_item(self, uint64_t index)

    cdef net_emulator.StackCell * _get_item_ptr(self, uint64_t index)

    cdef bint _set_item(self, uint64_t index, net_emulator.StackCell cell)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cpdef bytes as_bytes(self)

    cdef void setup_default_value(self, uint64_t index, uint64_t size, bint init)

    cdef void reverse_internal(self, int start, int end)
    
    @staticmethod
    cdef DotNetObject Copy(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject Clear(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Reverse(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetStackTrace(DotNetObject):
    cdef DotNetInt32 skipFrames
    cdef DotNetBoolean fNeedFileInfo

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetFrame(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetStackFrame(DotNetObject):
    cdef net_emulator.DotNetEmulator current_emulator
    cdef DotNetInt32 skip_frames

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetMethod(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetMemberInfo(DotNetObject):
    cdef net_row_objects.RowObject internal_method

    cdef DotNetObject get_DeclaringType(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetConsole(DotNetObject):
    
    @staticmethod
    cdef DotNetObject WriteLine(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Write(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)


cdef class DotNetThread(DotNetObject):
    cdef DotNetInt32 __identifier
    cdef DotNetThreadStart __thread_start
    cdef object __internal_thread

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cpdef void set_identifier(self, int identifier)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject Start(self, net_emulator.StackCell * params, int nparams)
    cdef DotNetObject Join(self, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject get_CurrentThread(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Sleep(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_ManagedThreadId(self, net_emulator.StackCell * params, int nparams)


cdef class DotNetRuntimeHelpers(DotNetObject):
    
    @staticmethod
    cdef DotNetObject InitializeArray(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetMath(DotNetObject):
    
    @staticmethod
    cdef DotNetObject Max(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Abs(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Exp(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Cos(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Sin(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Tan(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Log(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)


cdef class DotNetBitConverter(DotNetObject):
    @staticmethod
    cdef DotNetObject IsLittleEndian(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject ToInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject GetBytes(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetBuffer(DotNetObject):
    @staticmethod
    cdef DotNetObject BlockCopy(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetAppDomain(DotNetObject):

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)
    
    @staticmethod
    cdef DotNetObject get_CurrentDomain(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject add_AssemblyResolve(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject add_ResourceResolve(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetResolveEventHandler(DotNetObject):
    cdef DotNetRuntimeMethodHandle __method_object
    
    cpdef net_row_objects.MethodDefOrRef get_method_obj(self)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetEncoding(DotNetObject):
    cdef str name

    @staticmethod
    cdef DotNetObject get_UTF8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject get_Unicode(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetString(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetBytes(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetString(DotNetObject):
    cdef list str_data
    cdef str str_encoding

    cdef void add_string_internal(self, DotNetString other)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cpdef list get_str_data(self)

    cdef list __sanitize_data(self, str_data)

    cpdef bytes get_str_data_as_bytes(self)

    cpdef str get_str_encoding(self)

    cpdef bint is_encoding_wide(self)

    cdef DotNetObject IndexOf(self, net_emulator.StackCell * params, int nparams)

    cpdef str get_str_data_as_str(self)

    @staticmethod
    cdef DotNetObject Empty(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Intern(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Concat(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject IndexOf(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject StartsWith(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Replace(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Length(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject EndsWith(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Chars(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Substring(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Split(self, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject op_Equality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ToString(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetModule(DotNetObject):
    cdef net_row_objects.RowObject internal_module

    cdef DotNetObject get_ModuleHandle(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ResolveType(self, net_emulator.StackCell * params, int nparams)
    
    cdef DotNetObject ResolveMethod(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ResolveField(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetModuleHandle(DotNetObject):
    cdef net_row_objects.RowObject internal_module

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject ResolveTypeHandle(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ResolveMethodHandle(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetRuntimeTypeHandleFromMetadataToken(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetRuntimeTypeHandle(DotNetObject):
    cdef net_row_objects.RowObject internal_typedef

    cpdef get_internal_typedef(self)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetRuntimeMethodHandle(DotNetObject):
    cdef net_row_objects.RowObject internal_method

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetRuntimeFieldHandle(DotNetObject):
    cdef net_row_objects.Field internal_field

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetFieldInfo(DotNetObject):
    cdef net_row_objects.Field internal_field

    cdef DotNetObject get_FieldType(self, net_emulator.StackCell * params, int nparams)
    
    cdef DotNetObject SetValue(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Name(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetMethodBase(DotNetMemberInfo):

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)
    
    @staticmethod
    cdef DotNetObject GetMethodFromHandle(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_IsStatic(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject GetParameters(self, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject op_Equality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject op_Inequality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)


cdef class DotNetMethodInfo(DotNetMethodBase):

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)
    
    cdef DotNetObject get_ReturnType(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetParameterInfo(DotNetObject):
    cdef net_sigs.TypeSig internal_param

    cdef DotNetObject get_ParameterType(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetDelegate(DotNetObject):
    cdef DotNetObject dn_type
    cdef DotNetRuntimeMethodHandle dn_methodinfo

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject CreateDelegate(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Invoke(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetMulticastDelegate(DotNetDelegate):
    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

cdef class DotNetConvert(DotNetObject):
    
    @staticmethod
    cdef DotNetObject ToInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject FromBase64String(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject ToChar(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject ToString(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cpdef enum DotNetStackBehaviour:
    Pop0 = 0
    Pop1 = 1
    Pop1_pop1 = 2
    Popi = 3
    Popi_pop1 = 4
    Popi_popi = 5
    Popi_popi8 = 6
    Popi_popi_popi = 7
    Popi_popr4 = 8
    Popi_popr8 = 9
    Popref = 10
    Popref_pop1 = 11
    Popref_popi = 12
    Popref_popi_popi = 13
    Popref_popi_popi8 = 14
    Popref_popi_popr4 = 15
    Popref_popi_popr8 = 16
    Popref_popi_popref = 17
    Push0 = 18
    Push1 = 19
    Push1_push1 = 20
    Pushi = 21
    Pushi8 = 22
    Pushr4 = 23
    Pushr8 = 24
    Pushref = 25
    Varpop = 26
    Varpush = 27
    Popref_popi_pop1 = 28

cpdef enum DotNetOperandType:
    InlineBrTarget = 0
    InlineField = 1
    InlineI = 2
    InlineI8 = 3
    InlineMethod = 4
    InlineNone = 5
    InlinePhi = 6
    InlineR = 7
    InlineSig = 9
    InlineString = 10
    InlineSwitch = 11
    InlineTok = 12
    InlineType = 13
    InlineVar = 14
    ShortInlineBrTarget = 15
    ShortInlineI = 16
    ShortInlineR = 17
    ShortInlineVar = 18

cpdef enum DotNetOpCodeType:
    Annotation = 0
    Macro = 1
    Nternal = 2
    Objmodel = 3
    Prefix = 4
    Primitive = 5


cpdef enum DotNetFlowControl:
    Branch = 0
    Break = 1
    Call = 2
    Cond_Branch = 3
    Meta = 4
    Next = 5
    Phi = 6
    Return = 7
    Throw = 8

"""
cdef class DotNetOpCode(DotNetObject):
    cdef str stringname
    cdef DotNetStackBehaviour pop
    cdef DotNetStackBehaviour push
    cdef DotNetOperandType operand
    cdef DotNetOpCodeType op_type
    cdef int size
    cdef int s1
    cdef int s2
    cdef DotNetFlowControl ctrl
    cdef bint endsjmpblk
    cdef int stack

    cpdef get_net_cil_equiv(self)

    cpdef _get_opcode(self)


cdef class DotNetOpCodes(DotNetObject):
    @staticmethod
    cdef DotNetObject Nop(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Break(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarg_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarg_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarg_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarg_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloc_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloc_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloc_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloc_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stloc_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stloc_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stloc_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stloc_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarg_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarga_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Starg_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloc_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloca_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stloc_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldnull(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_M1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_5(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_6(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_7(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldc_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Dup(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Pop(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Jmp(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Call(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Calli(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ret(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Br_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject BrFalse_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject BrTrue_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Beq_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bge_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bgt_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ble_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Blt_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bne_Un_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bge_Un_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bgt_Un_s(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ble_Un_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Blt_Un_s(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Br(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject BrFalse(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject BrTrue(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Beq(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bge(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bgt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ble(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Blt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bne_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bge_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Bgt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ble_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Blt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Switch(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldind_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Add(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Sub(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Mul(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Div(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Div_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Rem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Rem_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject And(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Or(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Xor(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Shl(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Shr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Shr_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Neg(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Not(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_U8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Callvirt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Cpobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldstr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Newobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Castclass(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject IsInst(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_R_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Unbox(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Throw(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldflda(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldsfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldsflda(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stsfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I1_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I2_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I4_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I8_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U1_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U2_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U4_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U8_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Box(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Newarr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldlen(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelema(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldelem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stelem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Unbox_Any(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Refanyval(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ckfinite(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Mkrefany(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldtoken(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Add_Ovf(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Add_Ovf_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Mul_Ovf(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Mul_Ovf_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Sub_Ovf(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Sub_Ovf_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Endfinally(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Leave(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Leave_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stind_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Conv_U(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix7(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix6(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix5(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefix1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Prefixref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Arglist(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ceq(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Cgt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Cgt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Clt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Clt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldftn(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldvirtftn(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarg(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldarga(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Starg(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Ldloca(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Stloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Localloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Endfilter(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Unaligned(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Volatile(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Tailcall(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Initobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Constrained(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Cpblk(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Initblk(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Rethrow(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Sizeof(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Refanytype(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Readonly(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject TakesSingleByteArgument(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)


cdef class DotNetILGenerator(DotNetObject):
    cdef bytes method_body

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

    cdef __internal_emit_noargs(self, DotNetOpCode opcode)

    cdef __internal_emit_call(self, DotNetOpCode opcode, DotNetMethodInfo method_obj)

    cdef DotNetObject Emit(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetDynamicMethod(DotNetObject):
    cdef str name
    cdef net_row_objects.RowObject return_type
    cdef list parameter_types
    cdef bint skip_visibility
    cdef DotNetILGenerator il_generator
    cdef net_row_objects.RowObject parent_type
    cdef net_sigs.MethodSig sig_obj
    cdef bint static

    cpdef get_dotnetpe(self)

    cpdef get_method_data(self)

    cpdef get_method_signature(self)

    cpdef method_has_this(self)

    cpdef is_static(self)

    cpdef has_return_value(self)

"""

cdef class DotNetSortedList(DotNetList):
    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result)

"""
cdef class DotNetHashTable(DotNetConcurrentDictionary):
    pass

"""

cdef class DotNetRSACryptoServiceProvider(DotNetObject):
    @staticmethod
    cdef DotNetObject set_UseMachineKeyStore(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetBinaryReader(DotNetObject):
    cdef DotNetStream stream

    cdef DotNetObject get_BaseStream(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ReadBytes(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject ReadByte(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Close(self, net_emulator.StackCell * params, int nparams)

"""

cdef class DotNetMarshal(DotNetObject):
    
    @staticmethod
    cdef DotNetObject ReadIntPtr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject ReadInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject ReadInt64(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject WriteIntPtr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
    
    @staticmethod
    cdef DotNetObject WriteInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)
        
    @staticmethod
    cdef DotNetObject WriteInt64(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetWaitCallback(DotNetObject):
    cdef net_row_objects.MethodDef __method_object
    cdef object __object

cdef class DotNetFunc(DotNetObject):
    cdef net_row_objects.MethodDef __method_object
    cdef object __object

    cdef DotNetObject Invoke(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetThreadPool(DotNetObject):
    
    @staticmethod
    cdef DotNetObject QueueUserWorkItem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

"""
cdef class DotNetThreadStart(DotNetObject):
    cdef object __object
    cdef net_row_objects.MethodDef __method_object

    cpdef get_method_object(self)

"""

cdef class DotNetDebugger(DotNetObject):
    
    @staticmethod
    cdef DotNetObject get_IsAttached(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)



"""
cdef class DotNetGC(DotNetObject):
    
    @staticmethod
    cdef DotNetObject Collect(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetPath(DotNetObject):
    
    @staticmethod
    cdef DotNetObject GetTempPath(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject Combine(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetEnvironment(DotNetObject):
    
    @staticmethod
    cdef DotNetObject GetFolderPath(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

    @staticmethod
    cdef DotNetObject get_Version(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetResolveEventArgs(DotNetObject):
    cdef DotNetString __name

    cdef DotNetObject get_Name(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetComparison(DotNetObject):
    cdef DotNetObject __object
    cdef DotNetRuntimeMethodHandle __method_object

    cpdef net_row_objects.MethodDef get_method_object(self)

"""

cdef class DotNetDeflateStream(DotNetObject):
    cdef bint __decompress
    cdef Py_ssize_t position
    cdef bytes decompressed_buffer

    cdef DotNetObject Read(self, net_emulator.StackCell * params, int nparams)
"""

cdef class DotNetSymmetricAlgorithm(DotNetObject):
    cdef DotNetArray __key
    cdef DotNetArray __iv
    cdef DotNetInt32 __mode
    cdef DotNetInt32 __padding

    cdef DotNetObject get_Key(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Key(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_IV(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_IV(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Padding(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Padding(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Mode(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Mode(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetICryptoTransform(DotNetObject):
    cdef DotNetSymmetricAlgorithm provider
"""
cdef class DotNetDESDecryptor(DotNetICryptoTransform):
    cdef object des_object
    cdef DotNet3DESCryptoServiceProvider provider

    cdef DotNetObject get_InputBlockSize(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_OutputBlockSize(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject TransformBlock(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject TransformFinalBlock(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetDESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    
    cdef DotNetObject set_IV(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Key(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_IV(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Key(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject CreateDecryptor(self, net_emulator.StackCell * params, int nparams)
"""
cdef class DotNetApplication(DotNetObject):
    
    @staticmethod
    cdef DotNetObject get_ProductVersion(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetHashAlgorithm(DotNetObject):
    
    cdef DotNetObject Clear(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetMD5CryptoServiceProvider(DotNetHashAlgorithm):
    cdef DotNetObject ComputeHash(self, net_emulator.StackCell * params, int nparams)

cdef class DotNet3DESDecryptor(DotNetICryptoTransform):
    cdef object des_object

    cdef DotNetObject get_InputBlockSize(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_OutputBlockSize(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject TransformBlock(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject TransformFinalBlock(self, net_emulator.StackCell * params, int nparams)
    
cdef class DotNet3DESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    
    cdef DotNetObject set_IV(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Key(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_IV(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Key(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject set_Padding(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Padding(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject get_Mode(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject CreateDecryptor(self, net_emulator.StackCell * params, int nparams)

    cdef DotNetObject Clear(self, net_emulator.StackCell * params, int nparams)

cdef class DotNetGCHandle(DotNetObject):
    cdef DotNetObject __target
    cdef DotNetInt32 __type

    cdef DotNetObject get_Target(self, net_emulator.StackCell * params, int nparams)

    cdef void duplicate_into(self, DotNetObject obj)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef)

    cdef DotNetObject duplicate(self)

    @staticmethod
    cdef DotNetObject Alloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams)

cdef class DotNetVersion(DotNetObject):
    cdef DotNetInt32 __major_version

    cdef DotNetObject get_Major(self, net_emulator.StackCell * params, int nparams)

cdef struct NewobjFuncMapping:
    const char * name
    newobj_func_type func_ptr

cdef struct EmuFuncMapping:
    const char * name
    static_func_type func_ptr


cdef const int AMT_OF_STATIC_FUNCTIONS = 40
cdef const int AMT_OF_TYPES = 19

cdef NewobjFuncMapping NET_EMULATE_TYPE_REGISTRATIONS[19]
cdef EmuFuncMapping NET_EMULATE_STATIC_FUNC_REGISTRATIONS[40]

cdef DotNetObject New_ConcurrentDictionary(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_Dictionary(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_SortedList(net_emulator.DotNetEmulator emulator_obj)

#TODO: make sure this constructor fits.
cdef DotNetObject New_String(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_StringBuilder(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_List(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_StackTrace(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_Stream(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_Thread(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_MemoryStream(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_Object(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_MD5CryptoServiceProvider(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_TripleDESCryptoServiceProvider(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_MulticastDelegate(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_BinaryReader(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_StackFrame(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_ResolveEventHandler(net_emulator.DotNetEmulator emulator_obj)

cdef DotNetObject New_Comparison(net_emulator.DotNetEmulator emulator_obj)