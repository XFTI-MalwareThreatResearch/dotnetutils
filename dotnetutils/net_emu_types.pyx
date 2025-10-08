#cython: language_level=3
#distutils: language=c++

import cython
import sys
import base64
import hashlib
import threading
import binascii
import functools
import ntpath
import zlib
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import unpad
from dotnetutils import net_exceptions
from dotnetutils cimport net_row_objects, net_table_objects
from dotnetutils cimport net_sigs, net_opcodes, net_cil_disas
from dotnetutils cimport net_structs

from dotnetutils cimport dotnetpefile

from dotnetutils cimport net_emulator
from libc.math cimport exp, cos, sin, tan, log, fmod
from libc.stdlib cimport malloc, free, div, div_t, lldiv, lldiv_t
from libc.string cimport memcmp, memset, memcpy
from libc.stdint cimport uint64_t, int64_t #ensure we avoid any Windows / Linux based quirks
from libc.limits cimport INT_MIN, LLONG_MIN
from libcpp.utility cimport pair
from libcpp.algorithm cimport sort
from cpython.ref cimport PyObject, Py_INCREF, Py_XDECREF

"""
This file contains python versions of various .NET classes
All classes should extend DotNetObject with the exception of ArrayAddress
"""

cdef str remove_generics_from_name(str name):
    if name.count('`') != 1:
        return name
    actual_name, num = name.split('`')
    if not num.isdigit():
        return name

    return actual_name

"""
Used for the implementations of rem in relation to DotNetNumber.
Ensures rem follows C# spec.
"""
cdef int rem_i4(int one, int two):
    if two == 0:
        raise Exception()
    if one == INT_MIN and two == -1:
        return 0
    cdef div_t qr = div(one, two)
    return qr.rem

cdef unsigned int rem_u4(unsigned int one, unsigned int two):
    if two == 0:
        raise Exception()
    return one % two

cdef int64_t rem_i8(int64_t one, int64_t two):
    if two == 0:
        raise Exception()
    if one == LLONG_MIN and two == -1:
        return 0
    cdef lldiv_t qr = lldiv(one, two)
    return qr.rem

cdef uint64_t rem_u8(uint64_t one, uint64_t two):
    if two == 0:
        raise Exception()
    return one % two

cdef class DotNetObject:
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        if emulator_obj is None:
            raise net_exceptions.EmulatorExecutionException(None, 'Invalid DotNetObject: NoneType emulator_obj')
        self.__initialized = False
        self.__emulator_obj = emulator_obj
        self.type_obj = None
        self.type_sig_obj = None
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint equals(self, DotNetNumber other):
        raise net_exceptions.FeatureNotImplementedException()

    cdef bint notequals(self, DotNetNumber other):
        raise net_exceptions.FeatureNotImplementedException()

    cdef bint lessthanequals(self, DotNetNumber other):
        raise net_exceptions.FeatureNotImplementedException()

    cdef bint lessthan(self, DotNetNumber other):
        raise net_exceptions.FeatureNotImplementedException()

    cdef bint greaterthan(self, DotNetNumber other):
        raise net_exceptions.FeatureNotImplementedException()

    cdef bint greaterthanequals(self, DotNetNumber other):
        raise net_exceptions.FeatureNotImplementedException()

    def __dealloc__(self):
        self.__clear_fields()

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        if tdef.get_full_name() == b'System.Object':
            return True
        return False

    cdef bint is_number(self):
        return False

    #This is the Constructor method within the context of .NET emulator.
    #The actual init method can be used for utility constructors i guess.
    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(self)

    cdef bint is_null(self):
        return self.__is_null

    cdef bint is_true(self):
        cdef DotNetNumber num = None
        if self.is_number():
            num = <DotNetNumber>self
            return not num.val_is_zero()
        else:
            return not self.is_null()

    cdef bint is_false(self):
        return not self.is_true()

    cdef void flag_null(self):
        self.__is_null = True

    cdef bint has_function(self, bytes name):
        return self.__functions.count(name) == 1
            
    cdef emu_func_type get_function(self, bytes name):
        return self.__functions[name]

    cdef void add_function(self, bytes name, emu_func_type func):
        self.__functions[name] = func

    cpdef net_emulator.DotNetEmulator get_emulator_obj(self):
        return self.__emulator_obj

    cdef void set_field(self, int idno, net_emulator.StackCell val):
        cdef net_emulator.StackCell old_val
        if self.__fields.find(idno) != self.__fields.end():
            old_val = self.__fields[idno]
            #get rid of both the field incref and the cell incref
            self.get_emulator_obj().dealloc_cell(old_val)
        self.fields[idno] = val
        if val.tag == CorElementType.ELEMENT_TYPE_OBJECT or val.tag == CorElementType.ELEMENT_TYPE_STRING:
            if val.item.ref != NULL:
                Py_INCREF(val.item.ref)

    cdef void __clear_fields(self):
        cdef pair[int, net_emulator.StackCell] kv
        for kv in self.__fields:
            self.get_emulator_obj().dealloc_cell(kv.second)
        self.__fields.clear()

    cdef net_emulator.StackCell get_field(self, int idno):
        if self.__fields.find(idno) == self.__fields.end():
            self._initialize_field(idno)
        return self.__fields[idno]

    cpdef net_row_objects.TypeDefOrRef get_type_obj(self):
        return self.type_obj

    cpdef void set_type_obj(self, net_row_objects.TypeDefOrRef type_obj):
        self.type_obj = type_obj

    cpdef net_sigs.TypeSig get_type_sig_obj(self):
        return self.type_sig_obj

    cpdef void set_type_sig_obj(self, net_sigs.TypeSig type_sig_obj):
        self.type_sig_obj = type_sig_obj

    cdef void _initialize_field(self, int field_rid):
        cdef net_emulator.StackCell result
        cdef net_row_objects.Field field_obj = self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Field').get(field_rid)
        cdef net_sigs.FieldSig field_sig = field_obj.get_field_signature()
        cdef net_sigs.TypeSig type_sig = field_sig.get_type_sig()
        cdef net_sigs.TypeDefOrRefSig ref_sig = None
        cdef net_row_objects.TypeDefOrRef type_def = None
        if isinstance(type_sig, net_sigs.CorLibTypeSig):
            if type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I:
                result = self.get_emulator_obj().pack_i(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I1:
                result = self.get_emulator_obj().pack_i4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I2:
                result = self.get_emulator_obj().pack_i4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I4:
                result = self.get_emulator_obj().pack_i4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I8:
                result = self.get_emulator_obj().pack_i8(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U:
                result = self.get_emulator_obj().pack_u(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U1:
                result = self.get_emulator_obj().pack_u4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U2:
                result = self.get_emulator_obj().pack_u4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U4:
                result = self.get_emulator_obj().pack_u4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_U8:
                result = self.get_emulator_obj().pack_u8(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_R4:
                result = self.get_emulator_obj().pack_r4(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_R8:
                result = self.get_emulator_obj().pack_r8(0)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_STRING:
                result = self.pack_object(DotNetString.Empty(self.get_emulator_obj().get_appdomain(), []))
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_BOOLEAN:
                result = self.get_emulator_obj().pack_bool(False)
            elif type_sig.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
                result = self.get_emulator_obj().pack_null()
            else:
                raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'unknown corlibtype for initialize_field: {}'.format(type_sig.get_element_type()))
            
            self.set_field(field_rid, result)
        else:
            if isinstance(type_sig, net_sigs.ClassSig):
                self.set_field(field_rid, self.get_emulator_obj().pack_null())
            elif isinstance(type_sig, net_sigs.ValueTypeSig):
                ref_sig = type_sig
                type_def = ref_sig.get_type()
                if type_def.get_full_name() == b'System.Enum':
                    self.set_field(field_rid, self.get_emulator_obj().pack_i4(0))
                    return
                type_def = type_def.get_superclass()
                if type_def is not None and type_def.get_full_name() == b'System.Enum':
                    self.set_field(field_rid, self.get_emulator_obj().pack_i4(0))
                    return
                self.set_field(field_rid, DotNetObject(self.get_emulator_obj())) #ValueTypes are similar enough to objects it seems where this should be proper.
                #valuetypes are weird - seems the most prominent is basically enums which should be treated as numbers.  This might need to be adjusted eventually.
                #structs can also be valuetypes - we need dotnetobject() here.
            elif isinstance(type_sig, net_sigs.SZArraySig):       
                self.set_field(field_rid, self.get_emulator_obj().pack_null()) #DotNetNull() should work fine here since any arrays are going to be initialized by a newarr anyway.
            else:
                raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'unknown sigtype for initialize_field {}'.format(type(type_sig)))


    cpdef void initialize_type(self, net_row_objects.TypeDefOrRef type_obj):  
        self.type_obj = type_obj

    cpdef get_type(self):
        return type(self)

    def __gt__(self, other):
        if other.is_null():
            return True
        else:
            return self > other

    def __eq__(self, other):
        cdef DotNetObject dobj = other
        if self.is_null() and dobj.is_null():
            return True
        return object.__eq__(self, other)

    def __str__(self): #TODO: FIX this method
        cdef str str_val
        cdef int idno
        cdef DotNetObject dobj
        if self.is_null():
            return 'null'
        if self.get_type_obj():
            if len(self.fields) > 0:
                str_val = object.__str__(self) + ',type_obj={}:{}, fields='.format(self.get_type_obj().get_table_name(),
                                                                                  self.get_type_obj().get_rid())
                str_val += '{'
                for idno, dobj in self.fields.items():
                    str_val += str(idno) + ': ' + str(<DotNetObject>dobj) + ','
                str_val = str_val.rstrip(',') + '}'
                return str_val                
            return object.__str__(self) + ',type_obj={}:{}'.format(self.get_type_obj().get_table_name(), self.get_type_obj().get_rid())
        else:
            if len(self.fields) > 0:
                str_val = object.__str__(self) + ',fields={'
                for idno, dobj in self.fields.items():
                    str_val += str(idno) + ': ' + str(<DotNetObject>dobj) + ','
                str_val = str_val.rstrip(',') + '}'
                return str_val                
            return object.__str__(self)

    cdef void duplicate_into(self, DotNetObject result):
        result.__fields = self.__fields
        result.type_obj = self.type_obj
        result.type_sig_obj = self.type_sig_obj
        result.__initialized = self.__initialized
        result.__is_null = self.__is_null

    cdef DotNetObject duplicate(self):
        cdef DotNetObject result = DotNetObject(self.get_emulator_obj())
        self.duplicate_into(result)
        return result

    cdef net_emulator.StackCell ToString(self, net_emulator.StackCell * params, int nparams):
        raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'Called ToString() where it wasnt implemented {}'.format(type(self)))

cdef class DotNetNumber(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, CorElementType num_type, bytes num_data):
        DotNetObject.__init__(self, emu_obj)
        #At this moment for debugging purposes dont allow ELEMENT_TYPE_I or ELEMENT_TYPE_U
        self.__num_type = num_type
        self._ptr = NULL
        self.__amt_bytes = 0

        if num_data is not None:
            self.__amt_bytes = <int>len(num_data)
            if not self.__check_size(self.__amt_bytes, num_type):
                raise Exception
            self._ptr = <unsigned char *> malloc(sizeof(unsigned char) * self.__amt_bytes)
            if self._ptr == NULL:
                raise MemoryError('Could not allocate memory for DotNetNumber')
            memcpy(self._ptr, <char*>num_data, self.__amt_bytes)
        self.add_function(b'ToString', <emu_func_type>self.ToString)

    cdef bint is_number(self):
        return True

    cdef bint ptr_check(self):
        return self._ptr == NULL

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        cdef bytes tname = b''
        if self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I:
            tname = b'System.IntPtr'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
            tname = b'System.Int8'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
            tname = b'System.Int16'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
            tname = b'System.Int32'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
            tname = b'System.Int64'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_U:
            tname = b'System.UIntPtr'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_U1:
            tname = b'System.UInt8'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
            tname = b'System.UInt16'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_U4:
            tname = b'System.UInt32'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_U8:
            tname = b'System.UInt64'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_R4:
            tname = b'System.Single'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_R8:
            tname = b'System.Double'
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_CHAR:
            tname = b'System.Char'
        return tdef.get_full_name() == tname or DotNetObject.isinst(self, tdef)

    cdef DotNetNumber convert_unsigned(self):
        cdef DotNetNumber num_obj = None
        if self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
            num_obj = DotNetUInt8(self.get_emulator_obj(), None)
            num_obj.from_uchar(<unsigned char>self.as_char())
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I:
            num_obj = DotNetUIntPtr(self.get_emulator_obj(), self.as_bytes())
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
            num_obj = DotNetUInt16(self.get_emulator_obj(), None)
            num_obj.from_ushort(<unsigned short>self.as_short())
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
            num_obj = DotNetUInt32(self.get_emulator_obj(), None)
            num_obj.from_uint(<unsigned int>self.as_uint())
        elif self.__num_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
            num_obj = DotNetUInt64(self.get_emulator_obj(), None)
            num_obj.from_ulong(<uint64_t>self.as_long())
        else:
            if not self.is_signed():
                return self.duplicate()
            raise Exception('num type {}'.format(get_cor_type_name(self.__num_type)))
        return num_obj

    cdef DotNetObject duplicate(self):
        raise Exception()

    cdef void duplicate_into(self, DotNetObject result):
        DotNetObject.duplicate_into(self, result)

    cdef void from_bool(self, bint num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_long(self, int64_t num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_int(self, int num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_uchar(self, unsigned char num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_uint(self, unsigned int num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))
    
    cdef void from_ulong(self, uint64_t num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_char(self, char num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_float(self, float num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_double(self, double num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_short(self, short num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void from_ushort(self, unsigned short num):
        self.init_from_ptr(<unsigned char *>&num, sizeof(num))

    cdef void reset(self):
        if self._ptr != NULL:
            free(self._ptr)
            self._ptr = NULL
            self.__amt_bytes = 0
    
    cpdef bytes as_bytes(self):
        if self._ptr == NULL:
            return None
        return self._ptr[:self.__amt_bytes]

    cdef bint val_is_zero(self):
        if self._ptr == NULL:
            raise Exception()
        cdef int x
        for x in range(self.__amt_bytes):
            if self._ptr[x] != 0:
                return False
        return True

    cdef void init_zero(self):
        cdef int type_size = self.__util_get_type_size(self.__num_type)
        if type_size == -1:
            raise Exception
        self.__amt_bytes = type_size
        self._ptr = <unsigned char*>malloc(sizeof(unsigned char) * self.__amt_bytes)
        if self._ptr == NULL:
            raise MemoryError('Could not allocate memory for dotnetnumber')
        memset(self._ptr, 0x0, self.__amt_bytes)

    cdef void init_from_ptr(self, unsigned char * ptr, int ptr_size) except *:
        if not self.__check_size(ptr_size, self.__num_type):
            raise Exception('invalid size')
        self.__amt_bytes = ptr_size
        if self.__amt_bytes == 0:
            raise Exception('invalid amt bytes')
        self._ptr = <unsigned char *>malloc(sizeof(unsigned char) * self.__amt_bytes)
        if self._ptr == NULL:
            raise MemoryError('Could not allocate memoy for DotNetNumber')
        memcpy(self._ptr, ptr, ptr_size)

    cdef int __util_get_type_size(self, CorElementType num_type):
        if num_type == CorElementType.ELEMENT_TYPE_I or num_type == CorElementType.ELEMENT_TYPE_U:
            if self.get_emulator_obj().is_64bit():
                return 8
            else:
                return 4
        elif num_type == CorElementType.ELEMENT_TYPE_I4 or \
            num_type == CorElementType.ELEMENT_TYPE_U4 or \
            num_type == CorElementType.ELEMENT_TYPE_R4 or \
            num_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            return 4
        elif num_type == CorElementType.ELEMENT_TYPE_R8 or \
            num_type == CorElementType.ELEMENT_TYPE_I8 or \
            num_type == CorElementType.ELEMENT_TYPE_U8:
            return 8
        elif num_type == CorElementType.ELEMENT_TYPE_I1 or \
            num_type == CorElementType.ELEMENT_TYPE_U1:
            return 1
        elif num_type == CorElementType.ELEMENT_TYPE_I2 or \
            num_type == CorElementType.ELEMENT_TYPE_U2 or \
            num_type == CorElementType.ELEMENT_TYPE_CHAR:
            return 2
        raise Exception('Unknown type {}'.format(get_cor_type_name(num_type)))

    cdef bint __check_size(self, int amt_bytes, CorElementType num_type):
        cdef int calc_size = self.__util_get_type_size(num_type)
        if amt_bytes != calc_size:
            raise Exception('About to throw invalid size for type {} {} {}'.format(get_cor_type_name(num_type), calc_size, amt_bytes))
        return calc_size == amt_bytes

    def __dealloc__(self):
        if self._ptr != NULL:
            free(self._ptr)
            self._ptr = NULL

    def __hash__(self):
        cdef bytes data = self._ptr[:self.__amt_bytes]
        return hash(data + bytes([self.__num_type]))

    cpdef object as_python_obj(self):
        cdef float float_one = 0
        cdef double double_one = 0
        if self._ptr == NULL:
            return None
        if self.__num_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            if self._ptr[0]:
                return True
            return False
        elif self.__num_type == CorElementType.ELEMENT_TYPE_R4:
            float_one = (<float*>self._ptr)[0]
            return float_one
        elif self.__num_type == CorElementType.ELEMENT_TYPE_R8:
            double_one = (<double*>self._ptr)[0]
            return double_one
        if self.is_signed():
            return int.from_bytes(self._ptr[:self.__amt_bytes], 'little', signed=True)
        else:
            return int.from_bytes(self._ptr[:self.__amt_bytes], 'little', signed=False)

    cdef bint is_float(self):
        return self.__num_type == CorElementType.ELEMENT_TYPE_R4 or \
            self.__num_type == CorElementType.ELEMENT_TYPE_R8
        
    cdef bint is_signed(self):
        return self.__num_type == CorElementType.ELEMENT_TYPE_I or \
            self.__num_type == CorElementType.ELEMENT_TYPE_I1 or \
            self.__num_type == CorElementType.ELEMENT_TYPE_I2 or \
            self.__num_type == CorElementType.ELEMENT_TYPE_I4 or \
            self.__num_type == CorElementType.ELEMENT_TYPE_I8

    cdef CorElementType get_num_type(self):
        return self.__num_type

    cdef DotNetNumber cast(self, CorElementType new_type):
        raise Exception()

    cdef DotNetNumber add(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber subtract(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber multiply(self, DotNetNumber number):
        raise Exception()
    
    cdef DotNetNumber divide(self, DotNetNumber number):
        raise Exception('DotNetnUmber.Divide {} {}'.format(get_cor_type_name(self.get_num_type()), get_cor_type_name(number.get_num_type())))

    cdef DotNetNumber xor(self, DotNetNumber number):
        raise Exception('called DotNetNumber.xor for type {} {}'.format(get_cor_type_name(self.__num_type), get_cor_type_name(number.get_num_type())))

    cdef DotNetNumber andop(self, DotNetNumber number):
        raise Exception('DotNetNumber.andop for type {} {}'.format(get_cor_type_name(self.get_num_type()), get_cor_type_name(number.get_num_type())))

    cdef DotNetNumber orop(self, DotNetNumber number):
        raise Exception('orop DotNetNumber {} {}'.format(get_cor_type_name(self.get_num_type()), get_cor_type_name(number.get_num_type())))

    cdef DotNetNumber neg(self):
        raise Exception()

    cdef DotNetNumber notop(self):
        raise Exception()

    cdef DotNetNumber rem(self, DotNetNumber number):
        raise Exception('Called DotNetNumber.rem {} {}'.format(get_cor_type_name(self.__num_type), get_cor_type_name(number.get_num_type())))

    cdef DotNetNumber shl(self, DotNetNumber number):
        raise Exception('shl called by {} {}'.format(get_cor_type_name(self.get_num_type()), get_cor_type_name(number.get_num_type())))

    cdef DotNetNumber shr(self, DotNetNumber number):
        raise Exception('shr called by {}'.format(get_cor_type_name(self.get_num_type())))

    #For debugging purposes temporarily dont allow these.
    def __eq__(self, other):
        if other is None:
            return False
        return self.equals(other)

    def __ne__(self, other):
        if other is None:
            return True
        return self.notequals(other)

    def __le__(self, other):
        return self.lessthanequals(other)
    
    def __lt__(self, other):
        return self.lessthan(other)

    def __gt__(self, other):
        return self.greaterthan(other)

    def __ge__(self, other):
        return self.greaterthanequals(other)

    cdef unsigned char as_uchar(self):
        return (<unsigned char*>self._ptr)[0]

    cdef unsigned short as_ushort(self):
        return (<unsigned short*>self._ptr)[0]

    cdef unsigned int as_uint(self):
        return (<unsigned int*>self._ptr)[0]

    cdef uint64_t as_ulong(self):
        return (<uint64_t*>self._ptr)[0]

    cdef bint as_bool(self):
        return (<bint*>self._ptr)[0]

    cdef char as_char(self):
        return (<char*>self._ptr)[0]

    cdef short as_short(self):
        return (<short*>self._ptr)[0]

    cdef int as_int(self):
        return (<int*>self._ptr)[0]

    cdef int64_t as_long(self):
        return (<int64_t*>self._ptr)[0]

    cdef float as_float(self):
        return (<float*>self._ptr)[0]

    cdef double as_double(self):
        return (<double*>self._ptr)[0]

    cdef net_emulator.StackCell ToString(self, net_emulator.StackCell * params, int nparams):
        cdef object py_obj = None
        if self.__num_type == CorElementType.ELEMENT_TYPE_CHAR:
            return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), self._ptr[:self.__amt_bytes], 'utf-16le'))
        elif self.__num_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            if self._ptr[0]:
                return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), 'true'.encode('utf-16le'), 'utf-16le'))
            return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), 'false'.encode('utf-16le'), 'utf-16le'))
        else:
            py_obj = self.as_python_obj() #May want to change this up a bit later.
            return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), str(py_obj).encode('utf-16le'), 'utf-16le'))
    
    def __str__(self):
        if self.is_float():
            return str(self.as_python_obj())
        return hex(self.as_python_obj())

    def __repr__(self):
        return hex(self.as_python_obj())

    cdef bint equals(self, DotNetNumber other):
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        raise Exception()

    cdef bint lessthanequals(self, DotNetNumber other):
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        raise Exception()

cdef class DotNetIntPtr(DotNetNumber):

    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_I, num_data)

    @staticmethod
    cdef net_emulator.StackCell Zero(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_i(0)

    cdef DotNetObject duplicate(self):
        cdef DotNetIntPtr num = DotNetIntPtr(self.get_emulator_obj(), None)
        if self.get_emulator_obj().is_64bit():
            num.from_long(self.as_long())
        else:
            num.from_int(self.as_int())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_I:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_char(<char>self.as_long())
            else:
                res_obj.from_char(<char>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_short(<short>self.as_long())
            else:
                res_obj.from_short(<short>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_int(<int>self.as_long())
            else:
                res_obj.from_int(<int>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_long())
            else:
                res_obj.from_long(<int64_t>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_long())
            else:
                res_obj.from_uint(<unsigned int>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_uchar(<unsigned char>self.as_long())
            else:
                res_obj.from_uchar(<unsigned char>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ushort(<unsigned short>self.as_long())
            else:
                res_obj.from_ushort(<unsigned short>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_uint(<unsigned int>self.as_long())
            else:
                res_obj.from_uint(<unsigned int>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_long())
            else:
                res_obj.from_ulong(<uint64_t>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ushort(<unsigned short>self.as_long())
            else:
                res_obj.from_ushort(<unsigned short>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_float(<float>self.as_long())
            else:
                res_obj.from_float(<float>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_double(<double>self.as_long())
            else:
                res_obj.from_double(<double>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj #Checked 08/31/2025

    cdef DotNetNumber add(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_two = self.as_long()
                val_three = number.as_int()
                val_two += val_three
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one += val_three
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_two = self.as_long()
                val_four = number.as_long()
                val_two += val_four
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one += val_three
                result.from_int(val_one)
        else:
            raise Exception('Invalid type for DotNetIntPtr.add() {}'.format(get_cor_type_name(other_type)))
        return result #Checked 08/31/2025

    cdef DotNetNumber subtract(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_two = self.as_long()
                val_three = number.as_int()
                val_two -= val_three
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one -= val_three
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_two = self.as_long()
                val_four = number.as_long()
                val_two -= val_four
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one -= val_three
                result.from_int(val_one)
        else:
            raise Exception('Invalid type for DotNetIntPtr.subtract() {}'.format(get_cor_type_name(other_type)))
        return result #Checked 08/31/2025

    cdef DotNetNumber multiply(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_two = self.as_long()
                val_three = number.as_int()
                val_two *= val_three
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one *= val_three
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_two = self.as_long()
                val_four = number.as_long()
                val_two *= val_four
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one *= val_three
                result.from_int(val_one)
        else:
            raise Exception('Invalid type for DotNetIntPtr.multiply() {}'.format(get_cor_type_name(other_type)))
        return result #Checked 08/31/2025
    
    cdef DotNetNumber divide(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_two = self.as_long()
                val_three = number.as_int()
                val_two /= val_three
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one /= val_three
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_two = self.as_long()
                val_four = number.as_long()
                val_two /= val_four
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one /= val_three
                result.from_int(val_one)
        else:
            raise Exception()
        return result #Checked 08/31/2025

    cdef DotNetNumber xor(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_three = self.as_long()
                val_four = number.as_long()
                val_three ^= val_four
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one ^= val_two
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_three = self.as_long()
                val_one = number.as_int()
                val_three ^= val_one
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one ^= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result #Checked 08/31/2025

    cdef DotNetNumber andop(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_three = self.as_long()
                val_four = number.as_long()
                val_three &= val_four
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one &= val_two
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_three = self.as_long()
                val_one = number.as_int()
                val_three &= val_one
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one &= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber orop(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_three = self.as_long()
                val_four = number.as_long()
                val_three |= val_four
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one |= val_two
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_three = self.as_long()
                val_one = number.as_int()
                val_three |= val_one
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one |= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber neg(self):
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if is_64bit:
            val_two = self.as_long()
            result.from_long(-val_two)
        else:
            val_one = self.as_int()
            result.from_int(-val_one)
        return result

    cdef DotNetNumber notop(self):
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if is_64bit:
            val_two = self.as_long()
            result.from_long(~val_two)
        else:
            val_one = self.as_int()
            result.from_int(~val_one)
        return result

    cdef DotNetNumber rem(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef int val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_two = self.as_long()
                val_three = number.as_int()
                val_two = rem_i8(val_two, val_three)
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one = rem_i4(val_one, val_three)
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_two = self.as_long()
                val_four = number.as_long()
                val_two = rem_i8(val_two, val_four)
                result.from_long(val_two)
            else:
                val_one = self.as_int()
                val_three = number.as_int()
                val_one = rem_i4(val_one, val_three)
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef CorElementType other_type = number.get_num_type()
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0

        
        if other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_three = self.as_long()
                val_four = number.as_long()
                val_three <<= val_four
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one <<= val_two
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_three = self.as_long()
                val_one = number.as_int()
                val_three <<= val_one
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one <<= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shr(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetIntPtr result = DotNetIntPtr(self.get_emulator_obj(), None)
        cdef CorElementType other_type = number.get_num_type()
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_three = self.as_long()
                val_four = number.as_long()
                val_three >>= val_four
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one >>= val_two
                result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            if is_64bit:
                val_three = self.as_long()
                val_one = number.as_int()
                val_three >>= val_one
                result.from_long(val_three)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one >>= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_one = self.as_long()
                val_two = other.as_long()
                return val_one == val_two
            else:
                val_three = self.as_int()
                val_four = other.as_int()
                return val_three == val_four
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_one = self.as_long()
                val_two = other.as_long()
                return val_one <= val_two
            else:
                val_three = self.as_int()
                val_four = other.as_int()
                return val_three <= val_four
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_one = self.as_long()
                val_two = other.as_long()
                return val_one < val_two
            else:
                val_three = self.as_int()
                val_four = other.as_int()
                return val_three < val_four
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_one = self.as_long()
                val_two = other.as_long()
                return val_one > val_two
            else:
                val_three = self.as_int()
                val_four = other.as_int()
                return val_three > val_four
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        cdef int val_three = 0
        cdef int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_one = self.as_long()
                val_two = other.as_long()
                return val_one >= val_two
            else:
                val_three = self.as_int()
                val_four = other.as_int()
                return val_three >= val_four
        raise Exception()


cdef class DotNetUIntPtr(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_U, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetUIntPtr num = DotNetUIntPtr(self.get_emulator_obj(), None)
        if self.get_emulator_obj().is_64bit():
            num.from_ulong(self.as_ulong())
        else:
            num.from_uint(self.as_uint())
        DotNetNumber.duplicate_into(self, num)
        return num

    @staticmethod
    cdef net_emulator.StackCell op_Explicit(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams <= 0:
            raise net_exceptions.InvalidArgumentsException()
        cdef StackCell arg_obj = params[0]
        if arg_obj.tag == CorElementType.ELEMENT_TYPE_U4:
            arg_obj.tag = CorElementType.ELEMENT_TYPE_U
            return arg_obj
        elif arg_obj.tag == CorElementType.ELEMENT_TYPE_U:
            arg_obj.tag = CorElementType.ELEMENT_TYPE_U4
            return arg_obj
        raise net_exceptions.EmulatorExecutionException(app_domain.get_emulator_obj(), 'invalid op_Explicit type for UIntPtr')

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_U:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_char(<char>self.as_ulong())
            else:
                res_obj.from_char(<char>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_short(<short>self.as_ulong())
            else:
                res_obj.from_short(<short>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_int(<int>self.as_ulong())
            else:
                res_obj.from_int(<int>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_ulong())
            else:
                res_obj.from_long(<int64_t>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_ulong())
            else:
                res_obj.from_int(<int>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_uchar(<unsigned char>self.as_ulong())
            else:
                res_obj.from_uchar(<unsigned char>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ushort(<unsigned short>self.as_ulong())
            else:
                res_obj.from_ushort(<unsigned short>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_uint(<unsigned int>self.as_ulong())
            else:
                res_obj.from_uint(<unsigned int>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_ulong())
            else:
                res_obj.from_ulong(<uint64_t>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ushort(<unsigned short>self.as_ulong())
            else:
                res_obj.from_ushort(<unsigned short>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_float(<float>self.as_ulong())
            else:
                res_obj.from_float(<float>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_double(<double>self.as_ulong())
            else:
                res_obj.from_double(<double>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two += val_three
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one += val_three
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two += val_four
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one += val_three
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two -= val_three
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one -= val_three
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two -= val_four
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one -= val_three
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two *= val_three
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one *= val_three
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two *= val_four
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one *= val_three
                result.from_uint(val_one)
        else:
            raise Exception()
        return result
    
    cdef DotNetNumber divide(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two /= val_three
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one /= val_three
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two /= val_four
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one /= val_three
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_three = self.as_ulong()
                val_four = number.as_ulong()
                val_three ^= val_four
                result.from_ulong(val_three)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one ^= val_two
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_three = self.as_ulong()
                val_one = number.as_uint()
                val_three ^= val_one
                result.from_ulong(val_three)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one ^= val_two
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber andop(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_three = self.as_ulong()
                val_four = number.as_ulong()
                val_three &= val_four
                result.from_ulong(val_three)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one &= val_two
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_three = self.as_ulong()
                val_one = number.as_uint()
                val_three &= val_one
                result.from_ulong(val_three)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one &= val_two
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber orop(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_three = self.as_ulong()
                val_four = number.as_ulong()
                val_three |= val_four
                result.from_ulong(val_three)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one |= val_two
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_three = self.as_ulong()
                val_one = number.as_uint()
                val_three |= val_one
                result.from_ulong(val_three)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one |= val_two
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber neg(self):
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if is_64bit:
            val_two = self.as_ulong()
            result.from_ulong(<uint64_t>(-(<int64_t>val_two)))
        else:
            val_one = self.as_uint()
            result.from_uint(<unsigned int>(-(<int>val_one)))
        return result

    cdef DotNetNumber notop(self):
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if is_64bit:
            val_two = self.as_ulong()
            result.from_ulong(~val_two)
        else:
            val_one = self.as_uint()
            result.from_uint(~val_one)
        return result

    cdef DotNetNumber rem(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two = rem_u8(val_two, val_three)
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one = rem_i4(val_one, val_three)
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two = rem_u8(val_two, val_four)
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one = rem_u4(val_one, val_three)
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two <<= val_three
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one <<= val_three
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two <<= val_four
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one <<= val_three
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shr(self, DotNetNumber number):
        if self._ptr == NULL:
            raise Exception('Invalid DotNetNumber ptr')
        cdef DotNetUIntPtr result = DotNetUIntPtr(self.get_emulator_obj(), None)
        cdef unsigned int val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef uint64_t val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef CorElementType other_type = number.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            if is_64bit:
                val_two = self.as_ulong()
                val_three = number.as_uint()
                val_two >>= val_three
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one >>= val_three
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_two = self.as_ulong()
                val_four = number.as_ulong()
                val_two >>= val_four
                result.from_ulong(val_two)
            else:
                val_one = self.as_uint()
                val_three = number.as_uint()
                val_one >>= val_three
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef unsigned int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_one = self.as_ulong()
                val_two = other.as_ulong()
                return val_one == val_two
            else:
                val_three = self.as_uint()
                val_four = other.as_uint()
                return val_three == val_four
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef unsigned int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_one = self.as_ulong()
                val_two = other.as_ulong()
                return val_one <= val_two
            else:
                val_three = self.as_uint()
                val_four = other.as_uint()
                return val_three <= val_four
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef unsigned int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_one = self.as_ulong()
                val_two = other.as_ulong()
                return val_one < val_two
            else:
                val_three = self.as_uint()
                val_four = other.as_uint()
                return val_three < val_four
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef unsigned int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_one = self.as_ulong()
                val_two = other.as_ulong()
                return val_one > val_two
            else:
                val_three = self.as_uint()
                val_four = other.as_uint()
                return val_three > val_four
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        cdef unsigned int val_three = 0
        cdef unsigned int val_four = 0
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_one = self.as_ulong()
                val_two = other.as_ulong()
                return val_one >= val_two
            else:
                val_three = self.as_uint()
                val_four = other.as_uint()
                return val_three >= val_four
        raise Exception()

cdef class DotNetInt8(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_I1, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetInt8 num = DotNetInt8(self.get_emulator_obj(), None)
        num.from_char(self.as_char())
        DotNetNumber.duplicate_into(self, num)
        return num
    
    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_I1:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_char())
            else:
                res_obj.from_int(<int>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_char())
            else:
                res_obj.from_uint(<unsigned int>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_char())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber xor(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef DotNetInt8 result = DotNetInt8(self.get_emulator_obj(), None)
        cdef char val_one = self.as_char()
        cdef unsigned char val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_U1:
            val_two = other.as_uchar()
            val_one ^= val_two
            result.from_char(val_one)
            return result
        raise Exception('DotNetInt8.xor {}'.format(get_cor_type_name(other_type)))

    cdef bint equals(self, DotNetNumber other):
        cdef char val_one = 0
        cdef char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I1:
            val_one = self.as_char()
            val_two = other.as_char()
            return val_one == val_two
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef char val_one = 0
        cdef char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I1:
            val_one = self.as_char()
            val_two = other.as_char()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef char val_one = 0
        cdef char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I1:
            val_one = self.as_char()
            val_two = other.as_char()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef char val_one = 0
        cdef char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I1:
            val_one = self.as_char()
            val_two = other.as_char()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef char val_one = 0
        cdef char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I1:
            val_one = self.as_char()
            val_two = other.as_char()
            return val_one >= val_two
        raise Exception()

cdef class DotNetInt16(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_I2, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetInt16 num = DotNetInt16(self.get_emulator_obj(), None)
        num.from_short(self.as_short())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_I2:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_short())
            else:
                res_obj.from_int(<int>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_short())
            else:
                res_obj.from_uint(<unsigned int>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_short())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber subtract(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef short val_one = self.as_short()
        cdef int val_two = 0
        cdef DotNetInt16 result = DotNetInt16(self.get_emulator_obj(), None)
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = other.as_int()
            val_one -= val_two
            result.from_short(val_one)
        else:
            raise Exception('subtract {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber xor(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef short val_one = self.as_short()
        cdef short val_two = 0
        cdef DotNetInt16 result = DotNetInt16(self.get_emulator_obj(), None)
        if other_type == CorElementType.ELEMENT_TYPE_I2:
            val_two = other.as_short()
            val_one ^= val_two
            result.from_short(val_one)
        else:
            raise Exception('xor {}'.format(get_cor_type_name(other_type)))
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef short val_one = self.as_short()
        cdef short val_two = 0
        cdef int val_three = 0
        if other_type == CorElementType.ELEMENT_TYPE_I2:
            val_two = other.as_short()
            return val_one == val_two
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_three = other.as_int()
            return val_one == val_three
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef short val_one = 0
        cdef short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I2:
            val_one = self.as_short()
            val_two = other.as_short()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef short val_one = 0
        cdef short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I2:
            val_one = self.as_short()
            val_two = other.as_short()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef short val_one = self.as_short()
        cdef short val_two = 0
        cdef int val_three = 0
        if other_type == CorElementType.ELEMENT_TYPE_I2:
            val_two = other.as_short()
            return val_one > val_two
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_three = other.as_int()
            return val_one > val_three
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef short val_one = self.as_short()
        cdef short val_two = 0
        cdef int val_three = 0
        if other_type == CorElementType.ELEMENT_TYPE_I2:
            val_two = other.as_short()
            return val_one >= val_two
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_three = other.as_int()
            return val_one >= val_three
        raise Exception()

cdef class DotNetInt32(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_I4, num_data)
        self.add_function(b'CompareTo', <emu_func_type>self.CompareTo)

    cdef DotNetObject duplicate(self):
        cdef DotNetInt32 num = DotNetInt32(self.get_emulator_obj(), None)
        num.from_int(self.as_int())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell CompareTo(self, net_emulator.StackCell * params, int nparams):
        if nparams <= 0:
            raise net_exceptions.InvalidArgumentsException()
        cdef net_emulator.StackCell other = params[0]
        if other.tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        
        return self.get_emulator_obj().pack_i4(self.as_int() - other.item.i4)

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_I4:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_int())
            else:
                res_obj.from_int(<int>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_int())
            else:
                res_obj.from_uint(<unsigned int>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_int())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()

        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        cdef unsigned char val_six = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one += val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one += val_five
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_int()
            val_six = number.as_uchar()
            val_one += val_six
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four += val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one += val_two
                result.from_int(val_one)
        else:
            raise Exception(' unk type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one -= val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one -= val_five
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four -= val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one -= val_two
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one *= val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one *= val_five
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four *= val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one *= val_two
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one /= val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four /= val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one /= val_two
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        cdef unsigned char val_six = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one ^= val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_int()
            val_six = number.as_uchar()
            val_one ^= val_six
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one ^= val_five
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four ^= val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one ^= val_two
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber andop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one &= val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one &= val_five
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four &= val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one &= val_two
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber orop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one |= val_two
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one |= val_five
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = <int64_t>self.as_int()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four |= val_three
                result.from_long(val_four)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one |= val_two
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber neg(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        result.from_int(-self.as_int())
        return result

    cdef DotNetNumber notop(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        result.from_int(~self.as_int())
        return result

    cdef DotNetNumber rem(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = self.as_int()
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = number.as_int()
            val_one = rem_i4(val_one, val_two)
            result = DotNetInt32(self.get_emulator_obj(), None)
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four = rem_i8(val_one, val_three)
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_one = rem_i4(val_one, val_two)
                result.from_int(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetInt32(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        cdef unsigned int val_five = 0
        cdef unsigned char val_six = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one <<= val_two
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_int()
            val_five = number.as_uint()
            val_one <<= val_five
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_int()
            val_six = number.as_uchar()
            val_one <<= val_six
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_one = self.as_int()
            if is_64bit:
                val_three = number.as_long()
                val_one <<= val_three
                result.from_int(val_one)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one <<= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shr(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetInt32(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = number.as_int()
            val_one >>= val_two
            result.from_int(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_one = self.as_int()
            if is_64bit:
                val_three = number.as_long()
                val_one >>= val_three
                result.from_int(val_one)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one >>= val_two
                result.from_int(val_one)
        else:
            raise Exception()
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef int val_one = self.as_int()
        cdef int val_two = 0
        cdef bint val_three = False
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = other.as_int()
            return val_one == val_two
        elif other_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            val_three = other.as_bool()
            return (val_three and val_one != 0) or (not val_three and val_one == 0)
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef int val_one = 0
        cdef int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = other.as_int()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef int val_one = 0
        cdef int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = other.as_int()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef int val_one = 0
        cdef int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = other.as_int()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef int val_one = 0
        cdef int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_int()
            val_two = other.as_int()
            return val_one >= val_two
        raise Exception()


cdef class DotNetInt64(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_I8, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetInt64 num = DotNetInt64(self.get_emulator_obj(), None)
        num.from_long(self.as_long())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_I8:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_long())
            else:
                res_obj.from_int(<int>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_long())
            else:
                res_obj.from_uint(<unsigned int>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_long())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three += val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four += val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four += val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three -= val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four -= val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four -= val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three *= val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four *= val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four *= val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three /= val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four /= val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four /= val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three ^= val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four ^= val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four ^= val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber andop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three &= val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four &= val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four &= val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber orop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three |= val_four
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four |= val_three
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four |= val_two
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber neg(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetInt64 result = DotNetInt64(self.get_emulator_obj(), None)
        result.from_long(-self.as_long())
        return result

    cdef DotNetNumber notop(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetInt64 result = DotNetInt64(self.get_emulator_obj(), None)
        result.from_long(~self.as_long())
        return result

    cdef DotNetNumber rem(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_long()
            val_four = number.as_long()
            val_three = rem_i8(val_three, val_four)
            result = DotNetInt64(self.get_emulator_obj(), None)
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_long()
            result = DotNetIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_long()
                val_four = rem_i8(val_four, val_three)
                result.from_long(val_four)
            else:
                val_two = number.as_int()
                val_four = rem_i8(val_four, val_two)
                result.from_int(<int>val_four)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetInt64(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int64_t val_three = self.as_long()
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_four = number.as_long()
            val_three <<= val_four
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = number.as_int()
            val_three <<= val_one
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = number.as_int()
            val_three <<= val_one
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_four = number.as_long()
                val_three <<= val_four
                result.from_long(val_three)
            else:
                val_one = number.as_int()
                val_three <<= val_one
                result.from_int(<int>val_three)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shr(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetInt64(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int64_t val_three = self.as_long()
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_four = number.as_long()
            val_three >>= val_four
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = number.as_int()
            val_three >>= val_one
            result.from_long(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            if is_64bit:
                val_four = number.as_long()
                val_three >>= val_four
                result.from_long(val_three)
            else:
                val_one = number.as_int()
                val_three >>= val_one
                result.from_int(<int>val_three)
        else:
            raise Exception()
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_I8:
            val_one = self.as_long()
            val_two = other.as_long()
            return val_one == val_two
        raise Exception('DotNetInt64.equals {}'.format(get_cor_type_name(other_type)))

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I8:
            val_one = self.as_long()
            val_two = other.as_long()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef int64_t val_one = self.as_long()
        cdef int64_t val_two = 0
        cdef uint64_t val_three = 0
        if other_type == CorElementType.ELEMENT_TYPE_I8 or other_type == CorElementType.ELEMENT_TYPE_U8:
            val_two = other.as_long()
            return val_one < val_two
        raise Exception('DotNetInt64.lessthan {}'.format(get_cor_type_name(other.get_num_type())))

    cdef bint greaterthan(self, DotNetNumber other):
        cdef int64_t val_one = 0
        cdef int64_t val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_I8:
            val_one = self.as_long()
            val_two = other.as_long()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef int64_t val_one = self.as_long()
        cdef int64_t val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_I8 or other_type == CorElementType.ELEMENT_TYPE_U8:
            val_two = other.as_long()
            return val_one >= val_two
        raise Exception('int64 gte {}'.format(get_cor_type_name(other_type)))

cdef class DotNetUInt8(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_U1, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetUInt8 num = DotNetUInt8(self.get_emulator_obj(), None)
        num.from_uchar(self.as_uchar())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber shr(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned char val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uchar()
            val_two = number.as_int()
            val_one >>= val_two
            result.from_uchar(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_one = self.as_uchar()
            if is_64bit:
                val_three = number.as_long()
                val_one >>= val_three
                result.from_uchar(val_one)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one >>= val_two
                result.from_uchar(val_one)
        else:
            raise Exception('invalid other_type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned char val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uchar()
            val_two = number.as_int()
            val_one <<= val_two
            result.from_uchar(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_one = self.as_uchar()
            if is_64bit:
                val_three = number.as_long()
                val_one <<= val_three
                result.from_uchar(val_one)
            else:
                val_one = self.as_int()
                val_two = number.as_int()
                val_one <<= val_two
                result.from_uchar(val_one)
        else:
            raise Exception('invalid other_type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber rem(self, DotNetNumber number): #TODO: Once strict typing is introduced this should be removed.
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef unsigned char val_one = 0
        cdef int val_two = 0
        if self._ptr == NULL:
            raise Exception('Error with ptr')

        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uchar()
            val_two = number.as_int()
            val_one = <unsigned char>rem_u4(val_one, val_two)
            result.from_uchar(val_one)
            return result
        raise Exception('rem other type {}'.format(get_cor_type_name(other_type)))

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef unsigned char val_one = 0
        cdef int val_two = 0
        if self._ptr == NULL:
            raise Exception('Error with ptr')

        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uchar()
            val_two = number.as_int()
            val_one /= val_two
            result.from_uchar(val_one)
            return result
        raise Exception('rem other type {}'.format(get_cor_type_name(other_type)))

    cdef DotNetNumber orop(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef DotNetUInt8 result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef unsigned char val_one = self.as_uchar()
        cdef unsigned char val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_U1:
            val_two = other.as_uchar()
            val_one |= val_two
            result.from_uchar(val_one)
            return result
        raise Exception('orop {}'.format(get_cor_type_name(other_type)))

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_U1:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_uchar())
            else:
                res_obj.from_int(<int>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_uchar())
            else:
                res_obj.from_uint(<unsigned int>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<unsigned char>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_uchar())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber andop(self, DotNetNumber other):
        cdef DotNetUInt8 result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef unsigned char val_one = self.as_uchar()
        cdef int val_two = 0
        cdef CorElementType other_type = other.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = other.as_int()
            val_one &= val_two
            result.from_uchar(val_one)
            return result
        raise Exception('unkown type {}'.format(get_cor_type_name(other_type)))

    cdef DotNetNumber xor(self, DotNetNumber other):
        cdef DotNetUInt8 result = DotNetUInt8(self.get_emulator_obj(), None)
        cdef CorElementType other_type = other.get_num_type()
        cdef unsigned char val_one = self.as_uchar()
        cdef unsigned char val_two = 0
        cdef int val_three = 0
        if other_type == CorElementType.ELEMENT_TYPE_U1:
            val_two = other.as_uchar()
            val_one ^= val_two
            result.from_uchar(val_one)
            return result
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_three = other.as_int()
            val_one ^= val_three
            result.from_uchar(val_one)
            return result
        raise Exception('xor with type {}'.format(get_cor_type_name(other.get_num_type())))

    cdef bint equals(self, DotNetNumber other):
        cdef unsigned char val_one = 0
        cdef unsigned char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uchar()
            val_two = other.as_uchar()
            return val_one == val_two
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef unsigned char val_one = 0
        cdef unsigned char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uchar()
            val_two = other.as_uchar()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef unsigned char val_one = 0
        cdef unsigned char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uchar()
            val_two = other.as_uchar()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef unsigned char val_one = 0
        cdef unsigned char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uchar()
            val_two = other.as_uchar()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef unsigned char val_one = 0
        cdef unsigned char val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uchar()
            val_two = other.as_uchar()
            return val_one >= val_two
        raise Exception()

cdef class DotNetUInt16(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_U2, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetUInt16 num = DotNetUInt16(self.get_emulator_obj(), None)
        num.from_ushort(self.as_ushort())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_U2:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_ushort())
            else:
                res_obj.from_int(<int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_ushort())
            else:
                res_obj.from_uint(<unsigned int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<unsigned short>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber shr(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt16(self.get_emulator_obj(), None)
        cdef unsigned short val_one = self.as_ushort()
        cdef int val_two = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = number.as_int()
            val_one >>= val_two
            result.from_ushort(val_one)
        else:
            raise Exception()
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef unsigned short val_one = 0
        cdef unsigned short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U2:
            val_one = self.as_ushort()
            val_two = other.as_ushort()
            return val_one == val_two
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef unsigned short val_one = 0
        cdef unsigned short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U2:
            val_one = self.as_ushort()
            val_two = other.as_ushort()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef unsigned short val_one = 0
        cdef unsigned short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U2:
            val_one = self.as_ushort()
            val_two = other.as_ushort()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef unsigned short val_one = 0
        cdef unsigned short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U2:
            val_one = self.as_ushort()
            val_two = other.as_ushort()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef unsigned short val_one = 0
        cdef unsigned short val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U2:
            val_one = self.as_ushort()
            val_two = other.as_ushort()
            return val_one >= val_two
        raise Exception()

cdef class DotNetUInt32(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_U4, num_data)

    cdef DotNetObject duplicate(self):
        if self._ptr == NULL:
            raise Exception('ptr is null')
        cdef DotNetUInt32 num = DotNetUInt32(self.get_emulator_obj(), None)
        num.from_uint(self.as_uint())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if self._ptr == NULL:
            raise Exception('cannot cast an uninitialized integer')
        if new_type == CorElementType.ELEMENT_TYPE_U4:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_uint())
            else:
                res_obj.from_int(<int>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_uint())
            else:
                res_obj.from_uint(<unsigned int>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_uint())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()

        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int val_five = 0
        cdef unsigned char val_six = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one += val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uint()
            val_six = number.as_uchar()
            val_one += val_six
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uint()
            val_five = number.as_int()
            val_one += val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four += val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one += val_two
                result.from_uint(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one -= val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_five = number.as_int()
            val_one = self.as_uint()
            val_one -= val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four -= val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one -= val_two
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one *= val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uint()
            val_five = number.as_int()
            val_one *= val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four *= val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one *= val_two
                result.from_uint(val_one)
        else:
            raise Exception('multiply {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one /= val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four /= val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one /= val_two
                result.from_uint(val_one)
        else:
            raise Exception('divide {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one ^= val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uint()
            val_five = number.as_int()
            val_one ^= val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four ^= val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one ^= val_two
                result.from_uint(val_one)
        else:
            raise Exception('xorop {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber andop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one &= val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uint()
            val_five = number.as_int()
            val_one &= val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four &= val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one &= val_two
                result.from_uint(val_one)
        else:
            raise Exception(' andop uint32 {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber orop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef unsigned char val_five = 0
        cdef int val_six = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one |= val_two
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uint()
            val_six = number.as_int()
            val_one |= val_six
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four |= val_three
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one |= val_two
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uint()
            val_five = number.as_uchar()
            val_one |= val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber neg(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetUInt32 result = DotNetUInt32(self.get_emulator_obj(), None)
        result.from_uint(<unsigned int>(-(<int>self.as_uint())))
        return result

    cdef DotNetNumber notop(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetUInt32 result = DotNetUInt32(self.get_emulator_obj(), None)
        result.from_uint(~self.as_uint())
        return result

    cdef DotNetNumber rem(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one = rem_u4(val_one, val_two)
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = <uint64_t>self.as_uint()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four = rem_u8(val_four, val_three)
                result.from_ulong(val_four)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one = rem_u4(val_one, val_two)
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt32(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef unsigned char val_five = 0
        cdef int val_six = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one <<= val_two
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_one = self.as_uint()
            if is_64bit:
                val_three = number.as_ulong()
                val_one <<= val_three
                result.from_uint(val_one)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one <<= val_two
                result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U1:
            val_one = self.as_uint()
            val_five = number.as_uchar()
            val_one <<= val_five
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_one = self.as_uint()
            val_six = number.as_int()
            val_one <<= val_six
            result = DotNetUInt32(self.get_emulator_obj(), None)
            result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef DotNetNumber shr(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt32(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = number.as_uint()
            val_one >>= val_two
            result.from_uint(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_one = self.as_uint()
            if is_64bit:
                val_three = number.as_ulong()
                val_one >>= val_three
                result.from_uint(val_one)
            else:
                val_one = self.as_uint()
                val_two = number.as_uint()
                val_one >>= val_two
                result.from_uint(val_one)
        else:
            raise Exception()
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef CorElementType other_type = other.get_num_type()
        if other_type == CorElementType.ELEMENT_TYPE_U4 or other_type == CorElementType.ELEMENT_TYPE_I4: #For the compare treat it unsigned no matter what.
            val_one = self.as_uint()
            val_two = other.as_uint()
            return val_one == val_two
        raise Exception('DotNetUInt32.equals() {}'.format(get_cor_type_name(other_type)))

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = other.as_uint()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = other.as_uint()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = other.as_uint()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U4:
            val_one = self.as_uint()
            val_two = other.as_uint()
            return val_one >= val_two
        raise Exception()

cdef class DotNetUInt64(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_U8, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetUInt64 num = DotNetUInt64(self.get_emulator_obj(), None)
        num.from_ulong(self.as_ulong())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_U8:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_ulong())
            else:
                res_obj.from_int(<int>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_ulong())
            else:
                res_obj.from_uint(<unsigned int>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<uint64_t>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_ulong())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int64_t val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three += val_four
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_ulong()
            val_five = number.as_long()
            val_three += val_five
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four += val_three
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four += val_two
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three -= val_four
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four -= val_three
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four -= val_two
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three *= val_four
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four *= val_three
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four *= val_two
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef int val_one = 0
        cdef int val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three /= val_four
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four /= val_three
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four /= val_two
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetUInt64(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = self.as_ulong()
        cdef uint64_t val_four = 0
        cdef int64_t val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_four = number.as_ulong()
            val_three ^= val_four
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I8:
            val_five = number.as_long()
            val_three ^= val_five
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_four = number.as_ulong()
                val_three ^= val_four
                result.from_ulong(val_three)
            else:
                val_two = number.as_uint()
                val_three ^= val_two
                result.from_ulong(val_three)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber andop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three &= val_four
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four &= val_three
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four &= val_two
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber orop(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int64_t val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three |= val_four
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I8:
            val_three = self.as_ulong()
            val_five = number.as_long()
            val_three |= val_five
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four |= val_three
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four |= val_two
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber neg(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetUInt64 result = DotNetUInt64(self.get_emulator_obj(), None)
        result.from_ulong(<uint64_t>(-(<int64_t>self.as_ulong())))
        return result

    cdef DotNetNumber notop(self):
        if self._ptr == NULL:
            raise Exception('number memory')
        cdef DotNetUInt64 result = DotNetUInt64(self.get_emulator_obj(), None)
        result.from_ulong(~self.as_ulong())
        return result

    cdef DotNetNumber rem(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = None
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three = rem_u8(val_three, val_four)
            result = DotNetUInt64(self.get_emulator_obj(), None)
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_four = self.as_ulong()
            result = DotNetUIntPtr(self.get_emulator_obj(), None)
            if is_64bit:
                val_three = number.as_ulong()
                val_four = rem_u8(val_four, val_three)
                result.from_ulong(val_four)
            else:
                val_two = number.as_uint()
                val_four = rem_u8(val_four, val_two)
                result.from_uint(<unsigned int>val_four)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetInt64(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = 0
        cdef uint64_t val_four = 0
        cdef int val_five = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_three = self.as_ulong()
            val_four = number.as_ulong()
            val_three <<= val_four
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            val_three = self.as_uint()
            if is_64bit:
                val_four = number.as_ulong()
                val_three <<= val_four
                result.from_ulong(val_three)
            else:
                val_two = number.as_uint()
                val_three <<= val_two
                result.from_uint(<unsigned int>val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_I4:
            val_three = self.as_long()
            val_five = number.as_int()
            result = DotNetInt64(self.get_emulator_obj(), None)
            val_three <<= val_five
            result.from_long(val_three)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber shr(self, DotNetNumber number):
        cdef CorElementType other_type = number.get_num_type()
        cdef DotNetNumber result = DotNetInt64(self.get_emulator_obj(), None)
        cdef bint is_64bit = self.get_emulator_obj().is_64bit()
        cdef unsigned int val_one = 0
        cdef unsigned int val_two = 0
        cdef uint64_t val_three = self.as_ulong()
        cdef uint64_t val_four = 0
        if self._ptr == NULL:
            raise Exception('error with number ptr')
        if other_type == CorElementType.ELEMENT_TYPE_U8:
            val_four = number.as_ulong()
            val_three >>= val_four
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_one = number.as_uint()
            val_three >>= val_one
            result.from_ulong(val_three)
        elif other_type == CorElementType.ELEMENT_TYPE_U:
            if is_64bit:
                val_four = number.as_ulong()
                val_three >>= val_four
                result.from_ulong(val_three)
            else:
                val_two = number.as_uint()
                val_three >>= val_two
                result.from_uint(<unsigned int>val_three)
        else:
            raise Exception('invalid type {}'.format(get_cor_type_name(other_type)))
        return result

    cdef bint equals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_U8 or other_type == CorElementType.ELEMENT_TYPE_I8:
            val_one = self.as_ulong()
            val_two = other.as_ulong()
            return val_one == val_two
        raise Exception('DotNetUint64 equals {}'.format(get_cor_type_name(other_type)))

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U8:
            val_one = self.as_ulong()
            val_two = other.as_ulong()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U8:
            val_one = self.as_ulong()
            val_two = other.as_ulong()
            return val_one < val_two
        elif other.get_num_type() == CorElementType.ELEMENT_TYPE_I8:
            val_one = self.as_ulong()
            val_two = other.as_ulong() #Its likely going to be treated as a ulong anyway so lets see if this causes issues.
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_U8:
            val_one = self.as_ulong()
            val_two = other.as_ulong()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef uint64_t val_one = self.as_ulong()
        cdef uint64_t val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_U8 or other_type == CorElementType.ELEMENT_TYPE_I8:
            val_two = other.as_ulong()
            return val_one >= val_two
        raise Exception()

cdef class DotNetSingle(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_R4, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetSingle num = DotNetSingle(self.get_emulator_obj(), None)
        num.from_float(self.as_float())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_R4:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_float())
            else:
                res_obj.from_int(<int>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_float())
            else:
                res_obj.from_uint(<unsigned int>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_float())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        cdef DotNetSingle result = DotNetSingle(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            result.from_float(self.as_float() + number.as_float())
        else:
            raise Exception()
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        cdef DotNetSingle result = DotNetSingle(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            result.from_float(self.as_float() - number.as_float())
        else:
            raise Exception()
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        cdef DotNetSingle result = DotNetSingle(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            result.from_float(self.as_float() * number.as_float())
        else:
            raise Exception()
        return result

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef DotNetSingle result = DotNetSingle(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            result.from_float(self.as_float() / number.as_float())
        else:
            raise Exception()
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber andop(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber orop(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber neg(self):
        raise Exception()

    cdef DotNetNumber notop(self):
        raise Exception()

    cdef DotNetNumber rem(self, DotNetNumber number):
        cdef DotNetSingle result = DotNetSingle(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            result.from_float(fmod(self.as_float(), number.as_float()))
        else:
            raise Exception()
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber shr(self, DotNetNumber number):
        raise Exception()

    cdef bint equals(self, DotNetNumber other):
        cdef float val_one = 0
        cdef float val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            val_one = self.as_float()
            val_two = other.as_float()
            return val_one == val_two
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef float val_one = 0
        cdef float val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            val_one = self.as_float()
            val_two = other.as_float()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef float val_one = 0
        cdef float val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            val_one = self.as_float()
            val_two = other.as_float()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef float val_one = 0
        cdef float val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            val_one = self.as_float()
            val_two = other.as_float()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef float val_one = 0
        cdef float val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R4:
            val_one = self.as_float()
            val_two = other.as_float()
            return val_one >= val_two
        raise Exception()

cdef class DotNetDouble(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_R8, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetDouble num = DotNetDouble(self.get_emulator_obj(), None)
        num.from_double(self.as_double())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_R8:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_double())
            else:
                res_obj.from_int(<int>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_double())
            else:
                res_obj.from_uint(<unsigned int>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_CHAR:
            res_obj = DotNetChar(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_double())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber add(self, DotNetNumber number):
        cdef DotNetDouble result = DotNetDouble(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            result.from_double(self.as_double() + number.as_double())
        else:
            raise Exception()
        return result

    cdef DotNetNumber subtract(self, DotNetNumber number):
        cdef DotNetDouble result = DotNetDouble(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            result.from_double(self.as_double() - number.as_double())
        else:
            raise Exception()
        return result

    cdef DotNetNumber multiply(self, DotNetNumber number):
        cdef DotNetDouble result = DotNetDouble(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            result.from_double(self.as_double() * number.as_double())
        else:
            raise Exception()
        return result

    cdef DotNetNumber divide(self, DotNetNumber number):
        cdef DotNetDouble result = DotNetDouble(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            result.from_double(self.as_double() / number.as_double())
        else:
            raise Exception()
        return result

    cdef DotNetNumber xor(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber andop(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber orop(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber neg(self):
        raise Exception()

    cdef DotNetNumber notop(self):
        raise Exception()

    cdef DotNetNumber rem(self, DotNetNumber number):
        cdef DotNetDouble result = DotNetDouble(self.get_emulator_obj(), None)
        if number.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            result.from_double(fmod(self.as_double(), number.as_double()))
        else:
            raise Exception()
        return result

    cdef DotNetNumber shl(self, DotNetNumber number):
        raise Exception()

    cdef DotNetNumber shr(self, DotNetNumber number):
        raise Exception()

    cdef bint equals(self, DotNetNumber other):
        cdef double val_one = 0
        cdef double val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            val_one = self.as_double()
            val_two = other.as_double()
            return val_one == val_two
        raise Exception()

    cdef bint notequals(self, DotNetNumber other):
        return not self.equals(other)

    cdef bint lessthanequals(self, DotNetNumber other):
        cdef double val_one = 0
        cdef double val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            val_one = self.as_double()
            val_two = other.as_double()
            return val_one <= val_two
        raise Exception()

    cdef bint lessthan(self, DotNetNumber other):
        cdef double val_one = 0
        cdef double val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            val_one = self.as_double()
            val_two = other.as_double()
            return val_one < val_two
        raise Exception()

    cdef bint greaterthan(self, DotNetNumber other):
        cdef double val_one = 0
        cdef double val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            val_one = self.as_double()
            val_two = other.as_double()
            return val_one > val_two
        raise Exception()

    cdef bint greaterthanequals(self, DotNetNumber other):
        cdef double val_one = 0
        cdef double val_two = 0
        if other.get_num_type() == CorElementType.ELEMENT_TYPE_R8:
            val_one = self.as_double()
            val_two = other.as_double()
            return val_one >= val_two
        raise Exception()

cdef class DotNetBoolean(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_BOOLEAN, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetBoolean num = DotNetBoolean(self.get_emulator_obj(), None)
        num.from_bool(self.as_bool())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint equals(self, DotNetNumber other):
        cdef DotNetBoolean bobj = other.cast(CorElementType.ELEMENT_TYPE_BOOLEAN)
        return bobj.as_bool() == self.as_bool()

    cdef DotNetNumber cast(self, CorElementType new_type):
        if new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            return self
        raise Exception()

    cdef DotNetNumber notop(self):
        cdef DotNetBoolean result = DotNetBoolean(self.get_emulator_obj(), None)
        cdef bint r = not self.as_bool()
        result.from_bool(r)
        return result

cdef class DotNetVoid(DotNetNumber):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_VOID, num_data)

    cdef DotNetObject duplicate(self):
        raise Exception()

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        raise Exception()

cdef class DotNetChar(DotNetUInt16):
    def __init__(self, net_emulator.DotNetEmulator emu_obj, bytes num_data):
        DotNetNumber.__init__(self, emu_obj, CorElementType.ELEMENT_TYPE_CHAR, num_data)

    cdef DotNetObject duplicate(self):
        cdef DotNetChar num = DotNetChar(self.get_emulator_obj(), None)
        num.from_ushort(self.as_ushort())
        DotNetNumber.duplicate_into(self, num)
        return num

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetNumber cast(self, CorElementType new_type):
        cdef DotNetNumber res_obj = None
        cdef bint native_64 = self.get_emulator_obj().is_64bit()
        if new_type == CorElementType.ELEMENT_TYPE_CHAR:
            return self
        elif new_type == CorElementType.ELEMENT_TYPE_I:
            res_obj = DotNetIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_long(<int64_t>self.as_ushort())
            else:
                res_obj.from_int(<int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I2:
            res_obj = DotNetInt16(self.get_emulator_obj(), None)
            res_obj.from_short(<short>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I4:
            res_obj = DotNetInt32(self.get_emulator_obj(), None)
            res_obj.from_int(<int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I1:
            res_obj = DotNetInt8(self.get_emulator_obj(), None)
            res_obj.from_char(<char>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U:
            res_obj = DotNetUIntPtr(self.get_emulator_obj(), None)
            if native_64:
                res_obj.from_ulong(<uint64_t>self.as_ushort())
            else:
                res_obj.from_uint(<unsigned int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U1:
            res_obj = DotNetUInt8(self.get_emulator_obj(), None)
            res_obj.from_uchar(<unsigned char>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U2:
            res_obj = DotNetUInt16(self.get_emulator_obj(), None)
            res_obj.from_ushort(<unsigned short>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U4:
            res_obj = DotNetUInt32(self.get_emulator_obj(), None)
            res_obj.from_uint(<unsigned int>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_U8:
            res_obj = DotNetUInt64(self.get_emulator_obj(), None)
            res_obj.from_ulong(<uint64_t>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_R8:
            res_obj = DotNetDouble(self.get_emulator_obj(), None)
            res_obj.from_double(<double>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_I8:
            res_obj = DotNetInt64(self.get_emulator_obj(), None)
            res_obj.from_long(<int64_t>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_R4:
            res_obj = DotNetSingle(self.get_emulator_obj(), None)
            res_obj.from_float(<float>self.as_ushort())
        elif new_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
            res_obj = DotNetBoolean(self.get_emulator_obj(), None)
            if self.val_is_zero():
                res_obj.init_zero()
            else:
                res_obj.from_bool(True)
        else:
            raise Exception()
        return res_obj

    cdef DotNetNumber xor(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef DotNetChar result = DotNetChar(self.get_emulator_obj(), None)
        cdef unsigned short val_one = self.as_ushort()
        cdef int val_two = 0
        cdef unsigned int val_three = 0
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = other.as_int()
            val_one ^= val_two
            result.from_ushort(val_one)
        elif other_type == CorElementType.ELEMENT_TYPE_U4:
            val_three = other.as_uint()
            val_one ^= val_three
            result.from_ushort(val_one)
        else:
            raise Exception('xor {}'.format(get_cor_type_name(other_type)))
        return result

    cdef DotNetNumber shr(self, DotNetNumber other):
        cdef CorElementType other_type = other.get_num_type()
        cdef DotNetChar result = DotNetChar(self.get_emulator_obj(), None)
        cdef unsigned short val_one = self.as_ushort()
        cdef int val_two = 0
        if other_type == CorElementType.ELEMENT_TYPE_I4:
            val_two = other.as_int()
            val_one >>= val_two
            result.from_ushort(val_one)
        else:
            raise Exception('shr {}'.format(get_cor_type_name(other_type)))
        return result



#TODO: For NULL / DotNetNull removal make sure all python methods check if the value is null.
#TODO likely another utility constructor.
cdef class DotNetType(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.TypeDefOrRef type_handle, net_sigs.TypeSig sig_obj=None):
        DotNetObject.__init__(self, emulator_obj)
        if isinstance(type_handle, net_row_objects.TypeDef) or isinstance(type_handle, net_row_objects.TypeRef):
            self.type_handle = type_handle
        elif isinstance(type_handle, net_row_objects.TypeSpec):
            self.type_handle = type_handle.get_type()
        else:
            raise net_exceptions.FeatureNotImplementedException()
        self.sig_obj = sig_obj
        self.add_function(b'get_IsByRef', <emu_func_type>self.get_IsByRef)
        self.add_function(b'get_Module', <emu_func_type>self.get_Module)
        self.add_function(b'GetFields', <emu_func_type>self.GetFields)
        self.add_function(b'get_MetadataToken', <emu_func_type>self.get_MetadataToken)
        self.add_function(b'get_Assembly', <emu_func_type>self.get_Assembly)
        self.add_function(b'get_IsValueType', <emu_func_type>self.get_IsValueType)

    def __str__(self):
        return 'TypeObject {} {}'.format(hex(self.type_handle.get_token()), self.type_handle.get_full_name())

    cdef net_emulator.StackCell get_IsValueType(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_bool(self.type_handle.is_valuetype())

    cdef DotNetObject duplicate(self):
        cdef DotNetType type_obj = DotNetType(self.get_emulator_obj(), self.type_handle, self.sig_obj)
        DotNetObject.duplicate_into(self, type_obj)
        return type_obj

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Type' or DotNetObject.isinst(self, tdef)

    cdef void duplicate_into(self, DotNetObject result):
        pass #Will never be called.

    cpdef net_row_objects.TypeDefOrRef get_type_handle(self):
        return self.type_handle

    cdef net_emulator.StackCell get_IsByRef(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_bool(isinstance(self.sig_obj, net_sigs.ByRefsig))

    @staticmethod
    cdef net_emulator.StackCell op_Equality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetObject arg_one = <DotNetObject>params[0].item.ref
        cdef DotNetObject arg_two = <DotNetObject>params[1].item.ref
        cdef bint result = arg_one == arg_two
        return app_domain.get_emulator_obj().pack_bool(result)

    @staticmethod
    cdef net_emulator.StackCell op_Inequality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetObject arg_one = <DotNetObject>params[0].item.ref
        cdef DotNetObject arg_two = <DotNetObject>params[1].item.ref
        cdef bint result = arg_one != arg_two
        return app_domain.get_emulator_obj().pack_bool(result)

    @staticmethod
    cdef net_emulator.StackCell GetTypeFromHandle(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams <= 0 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetRuntimeTypeHandle runtime_handle = <DotNetRuntimeTypeHandle>params[0].ref
        cdef DotNetType obj2 = DotNetType(app_domain.get_emulator_obj(), runtime_handle.get_internal_typedef())
        obj2.set_type_obj(app_domain.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(b'System.Type'))
        return app_domain.get_emulator_obj().pack_object(obj2)

    cdef net_emulator.StackCell get_Module(self, net_emulator.StackCell * params, int nparams):
        if not isinstance(self.type_handle, net_row_objects.TypeDef):
            raise net_exceptions.ObjectTypeException
        #There is going to have to be a ton of reimplementation to support this for TypeRefs.
        return self.get_emulator_obj().pack_object(DotNetModule(self.get_emulator_obj(), self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Module').get(1)))

    cdef net_emulator.StackCell GetFields(self, net_emulator.StackCell * params, int nparams):
        cdef list field_objs
        cdef net_row_objects.TypeDef type_obj
        cdef net_row_objects.Field item
        cdef DotNetFieldInfo field_info
        cdef DotNetArray result_array
        cdef int binding_flags = 0
        cdef Py_ssize_t x = 0
        if nparams == 1:
            if params[0].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            binding_flags = params[0].item.i4
        if binding_flags == 1064:
            # static, nonpublic, getfield
            field_objs = list()
            type_obj = self.get_type_handle()
            for item in type_obj['FieldList'].get_formatted_value():
                if item.is_static():
                    field_info = DotNetFieldInfo(self.get_emulator_obj(), item)
                    field_objs.append(field_info)

            result_array = DotNetArray(self.get_emulator_obj(), len(field_objs), type_obj.get_dotnetpe().get_type_by_full_name(
                b'System.Reflection.FieldInfo'), initialize=False)
            for x in range(len(field_objs)):
                result_array._set_item(x, self.get_emulator_obj().pack_object(field_objs[x]))
            return result_array
        else:
            raise net_exceptions.OperationNotSupportedException()

    cdef net_emulator.StackCell get_MetadataToken(self, net_emulator.StackCell * params, int nparams):
        cdef int coded_token = self.get_type_handle().get_token()
        return self.get_emulator_obj().pack_i4(coded_token)

    def __eq__(self, other):
        return isinstance(other, DotNetType) and self.get_type_handle() == other.get_type_handle()

    cdef net_emulator.StackCell get_Assembly(self, net_emulator.StackCell * params, int nparams):
        cdef net_row_objects.RowObject module_obj = self.get_type_handle().get_dotnetpe().get_metadata_table('Assembly').get(1)
        return self.get_emulator_obj().pack_object(DotNetAssembly(self.get_emulator_obj(), module_obj))

cdef class DotNetMonitor(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    cdef DotNetObject duplicate(self):
        cdef DotNetMonitor mon = DotNetMonitor(self.get_emulator_obj())
        DotNetObject.duplicate_into(self, mon)
        return mon

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        raise Exception()

    @staticmethod
    cdef net_emulator.StackCell Enter(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        """
        System.Threading.Monitor.Enter
        Doesnt appear to do anything emulatable
        """
        return app_domain.get_emulator_obj().pack_blanktag()

    @staticmethod
    cdef net_emulator.StackCell Exit(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        # same as above
        return app_domain.get_emulator_obj().pack_blanktag()

cdef class DotNetDictionary(DotNetObject): #TODO need to rewrite this a bit to fit with the new model.
    def __init__(self, net_emulator.DotNetEmulator emulator_obj): #Capacity probably doesnt actually matter.
        DotNetObject.__init__(self, emulator_obj)
        self.__internal_dict = dict()
        self.add_function(b'TryGetValue', <emu_func_type>self.TryGetValue)
        self.add_function(b'set_Item', <emu_func_type>self.set_Item)
        self.add_function(b'Add', <emu_func_type>self.Add)
        self.add_function(b'ContainsKey', <emu_func_type>self.ContainsKey)
        self.add_function(b'get_Count', <emu_func_type>self.get_Count)

    cdef DotNetObject duplicate(self):
        cdef pair[net_emulator.StackCell, net_emulator.StackCell] kv
        cdef DotNetDictionary result = DotNetDictionary(self.get_emulator_obj())
        self.duplicate_into(result)
        return result

    cdef void duplicate_into(self, DotNetObject result):
        cdef DotNetDictionary dict_obj = result
        cdef pair[net_emulator.StackCell, net_emulator.StackCell] kv
        cdef net_emulator.StackCell args[2]
        for kv in self.__internal_dict:
            args[0] = kv.first
            args[1] = kv.second
            dict_obj.set_Item(args, 2)
        DotNetObject.duplicate_into(self, result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name().startswith(b'System.Collections.Generic.Dictionary') or DotNetObject.isinst(self, tdef)

    cdef net_emulator.StackCell TryGetValue(self, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[1].tag != CorElementType.ELEMENT_TYPE_BYREF:
            raise net_exceptions.InvalidArgumentsException()
        
        cdef net_emulator.StackCell param1 = params[0]
        cdef net_emulator.StackCell param2 = params[1]
        cdef bint result = False
        cdef StackCell value1 = None
  
        if self.__internal_dict.find(param1) != self.__internal_dict.end():
            value1 = self.__internal_dict[param1]
            self.get_emulator_obj().set_ref(param2, value1)
            result = True
        return self.get_emulator_obj().pack_bool(result)

    cdef net_emulator.StackCell set_Item(self, net_emulator.StackCell * params, int nparams):
        if nparams != 2:
            raise net_exceptions.InvalidArgumentsException()
        cdef net_emulator.StackCell param1 = self.get_emulator_obj().duplicate_cell(param1)
        cdef net_emulator.StackCell param2 = self.get_emulator_obj().duplicate_cell(param2)
        cdef net_emulator.StackCell old_key
        cdef net_emulator.StackCell old_value
        cdef unordered_map[net_emulator.StackCell, net_emulator.StackCell].const_iterator it = self.__internal_dict.begin()
        if param1.tag == CorElementType.ELEMENT_TYPE_STRING or param1.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if param1.item.ref != NULL:
                Py_INCREF(param1.item.ref)
        if param2.tag == CorElementType.ELEMENT_TYPE_STRING or param2.tag == CorElementType.ELEMENT_TYPE_OBJECT:
            if param2.item.ref != NULL:
                Py_INCREF(param2.item.ref)
        it = self.__internal_dict.find(params[0])
        if it != self.__internal_dict.end():
            old_key = it.first
            old_value = it.second
            self.__internal_dict[param1] = param2
            if old_key.tag == CorElementType.ELEMENT_TYPE_STRING or old_key.tag == CorElementType.ELEMENT_TYPE_OBJECT:
                Py_XDECREF(old_key.item.ref)
            if old_value.tag == CorElementType.ELEMENT_TYPE_STRING or old_value.tag == CorElementType.ELEMENT_TYPE_OBJECT:
                Py_XDECREF(old_value.item.ref)
        else:
            self.__internal_dict[param1] = param2
        return self.get_emulator_obj().pack_blanktag()

    cdef net_emulator.StackCell Add(self, net_emulator.StackCell * params, int nparams):
        return self.set_Item(params, nparams)

    cdef net_emulator.StackCell ContainsKey(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1:
            raise net_exceptions.InvalidArgumentsException()
        cdef bint result = self.__internal_dict.find(params[0]) != self.__internal_dict.end()
        return self.get_emulator_obj().pack_bool(result)

    cdef net_emulator.StackCell get_Count(self, net_emulator.StackCell * params, int nparams):
        cdef int count = <int>self.__internal_dict.size()
        return self.get_emulator_obj().pack_i4(count)

cdef class DotNetConcurrentDictionary(DotNetDictionary):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetDictionary.__init__(self, emulator_obj)

    cdef DotNetObject duplicate(self):
        cdef DotNetConcurrentDictionary result = DotNetConcurrentDictionary(self.get_emulator_obj())
        DotNetDictionary.duplicate_into(self, result)
        return result

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name().startswith(b'System.Collections.Generic.ConcurrentDictionary') or DotNetDictionary.isinst(self, tdef)

cdef class DotNetStringBuilder(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.char_array = bytes()
        self.is_wide = False
        self.add_function(b'Append', <emu_func_type>self.Append)
        self.add_function(b'ToString', <emu_func_type>self.ToString)

    cdef DotNetObject duplicate(self):
        cdef DotNetStringBuilder strbuild = DotNetStringBuilder(self.get_emulator_obj())
        strbuild.char_array = self.char_array
        strbuild.is_wide = self.is_wide
        DotNetObject.duplicate_into(self, strbuild)
        return strbuild

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Text.StringBuilder' or DotNetObject.isinst(self, tdef)

    cdef net_emulator.StackCell Append(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_CHAR:
            raise net_exceptions.InvalidArgumentsException()
        if not isinstance(args[0], DotNetNumber):
            raise net_exceptions.InvalidArgumentsException()
        self.char_array += self.get_emulator_obj().cell_to_bytes(params[0])
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell ToString(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), self.char_array, str_encoding='utf-16le'))

cdef class DotNetStream(DotNetObject): #TODO: going to need to rewrite this a bit
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self._position = 0
        self.add_function(b'Read', <emu_func_type>self.Read)
        self.add_function(b'set_Position', <emu_func_type>self.set_Position)
        self.add_function(b'get_Position', <emu_func_type>self.get_Position)
        self.add_function(b'ReadByte', <emu_func_type>self.ReadByte)
        self.add_function(b'get_Length', <emu_func_type>self.get_Length)
        self.add_function(b'Write', <emu_func_type>self.Write)
        self.add_function(b'ReadBytes', <emu_func_type>self.ReadBytes)
        self.add_function(b'Close', <emu_func_type>self.Close)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.IO.Stream' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetStream result = DotNetStream(self.get_emulator_obj())
        result._position = self._position
        result._internal = self._internal
        DotNetObject.duplicate_into(self, result)
        return result

    cdef void duplicate_into(self, DotNetObject result):
        (<DotNetStream>result)._position = self._position
        (<DotNetStream>result)._internal = self._internal
        DotNetObject.duplicate_into(self, result)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetObject rsrc_data = args[0]
        if isinstance(rsrc_data, DotNetArray):
            self._internal = rsrc_data
        else:
            if isinstance(rsrc_data, DotNetStream):
                self._internal = rsrc_data._internal
        return self
        
    cdef DotNetArray get_internal_array(self):
        return self._internal

    cdef net_emulator.StackCell Read(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray buffer = <DotNetArray>args[0]
        cdef DotNetNumber offset = <DotNetNumber>args[1]
        cdef DotNetNumber count = <DotNetNumber>args[2]
        cdef int usable_count = 0
        cdef DotNetInt32 result = None
        offset = offset.cast(CorElementType.ELEMENT_TYPE_I4)
        count = count.cast(CorElementType.ELEMENT_TYPE_I4)
        cdef list empty = list()
        cdef int x
        cdef DotNetInt32 num = None
        for x in range(count.as_int()):
            num = self.ReadByte(empty)
            buffer[offset.as_int() + x] = num.cast(CorElementType.ELEMENT_TYPE_U1)
        return count

    cdef net_emulator.StackCell set_Position(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt64 pos = <DotNetInt64>args[0]
        self._position = pos.as_long()
        return None

    cdef net_emulator.StackCell get_Position(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_i8(self._position)

    cdef net_emulator.StackCell ReadByte(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetNumber result = self._internal[self._position]
        self._position += 1
        return result.cast(net_structs.CorElementType.ELEMENT_TYPE_I4)

    cdef net_emulator.StackCell get_Length(self, net_emulator.StackCell * params, int nparams):
        cdef int64_t pos = len(self._internal)
        return self.get_emulator_obj().pack_i8(pos)

    cdef net_emulator.StackCell Write(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray buffer = <DotNetArray>args[0]
        cdef DotNetInt32 offset = <DotNetInt32>(<DotNetNumber>args[1]).cast(CorElementType.ELEMENT_TYPE_I4)
        cdef DotNetInt32 count = <DotNetInt32>(<DotNetNumber>args[2]).cast(CorElementType.ELEMENT_TYPE_I4)
        for x in range(count.as_int()):
            self._internal[self._position + x] = buffer[offset.as_int() + x]
        self._position += count.as_int()
        return None

    cdef net_emulator.StackCell ReadBytes(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 count = <DotNetInt32>args[0]
        cdef DotNetArray arr_obj = self._internal[self._position: self._position + count.as_int()]
        self._position += count.as_int()
        return arr_obj

    cdef net_emulator.StackCell Close(self, net_emulator.StackCell * params, int nparams):
        self._position = 0
        return self.get_emulator_obj().pack_blanktag()

    def __str__(self):
        return 'DotNetStream: length={}, position={}, buffer={}'.format(self.get_Length([]), self.get_Position([]), self._internal)


cdef class DotNetMemoryStream(DotNetStream):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetStream.__init__(self, emulator_obj)
        self.add_function(b'ToArray', <emu_func_type>self.ToArray)

    cdef DotNetObject duplicate(self):
        cdef DotNetMemoryStream mstream = DotNetMemoryStream(self.get_emulator_obj())
        DotNetStream.duplicate_into(self, mstream)
        return mstream

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.IO.MemoryStream' or DotNetStream.isinst(self, tdef)

    cdef net_emulator.StackCell ToArray(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(self._internal)

    def __str__(self):
        return str(self._internal[:50]) + ' Object: ' + DotNetObject.__str__(self) + ' position: {}'.format(
            self._position)

#TODO: No ctor needed internal use?
cdef class DotNetAssemblyName(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, bytes name, DotNetAssembly assembly):
        DotNetObject.__init__(self, emulator_obj)
        self.name = name
        self.assembly = assembly
        if self.name.endswith(b'.exe'):
            self.name = self.name.rstrip(b'.exe')
        elif self.name.endswith(b'.dll'):
            self.name = self.name.rstrip(b'.dll')
        self.add_function(b'GetPublicKeyToken', <emu_func_type>self.GetPublicKeyToken)
        self.add_function(b'get_Name', <emu_func_type>self.get_Name)

    cdef DotNetObject duplicate(self):
        cdef DotNetAssemblyName n = DotNetAssemblyName(self.get_emulator_obj(), self.name, self.assembly)
        DotNetObject.duplicate_into(self, n)
        return n

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.AssemblyName' or DotNetObject.isinst(self, tdef)

    cdef net_emulator.StackCell GetPublicKeyToken(self, net_emulator.StackCell * params, int nparams):
        cdef net_row_objects.RowObject module_obj = self.assembly.get_module().get_dotnetpe().get_metadata_table(
            'Assembly').get(1)
        cdef bytes public_key
        cdef object sha_hash
        cdef bytes hashed_key
        cdef list public_key_token
        cdef DotNetArray array
        cdef unsigned char c
        cdef net_emulator.StackCell num

        if module_obj['PublicKey'].get_raw_value() == 0:
            #If raw value is 0, return a empty array.
            return self.pack_object(DotNetArray(self.get_emulator_obj(), 0, self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte')))
        public_key = module_obj['PublicKey'].get_value()

        sha_hash = hashlib.sha1()
        sha_hash.update(public_key)
        hashed_key = sha_hash.digest()
        public_key_token = list(hashed_key[-8:][::-1])
        array = DotNetArray(self.get_emulator_obj(), 8, self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                            initialize=False)
        for x in range(8):
            c = public_key_token[x]
            num = self.get_emulator_obj().pack_u1(c)
            array._set_item(x, num)
        return array

    cdef net_emulator.StackCell get_Name(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), self.name, 'utf-8'))

cdef class DotNetManifestModule(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, DotNetAssembly dnassembly):
        DotNetObject.__init__(self, emulator_obj)
        self.dnassembly = dnassembly

    cdef DotNetObject duplicate(self):
        cdef DotNetManifestModule m = DotNetManifestModule(self.get_emulator_obj(), self.dnassembly)
        DotNetObject.duplicate_into(self, m)
        return m

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.Assembly.ManifestModule' or DotNetObject.isinst(self, tdef)

    cdef void duplicate_into(self, DotNetObject result):
        pass


cdef class DotNetAssembly(DotNetObject):
    """
    This class is meant to fool checks to ensure that
    Deobfuscation methods are being executed by their assembly.
    """
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.RowObject internal_module):
        DotNetObject.__init__(self, emulator_obj)
        self.module = internal_module
        self.add_function(b'get_ManifestModule', <emu_func_type>self.get_ManifestModule)
        self.add_function(b'get_EntryPoint', <emu_func_type>self.get_EntryPoint)
        self.add_function(b'get_FullName', <emu_func_type>self.get_FullName)
        self.add_function(b'get_Location', <emu_func_type>self.get_Location)
        self.add_function(b'GetManifestResourceStream', <emu_func_type>self.GetManifestResourceStream)
        self.add_function(b'GetManifestResourceNames', <emu_func_type>self.GetManifestResourceNames)
        self.add_function(b'GetName', <emu_func_type>self.GetName)
        self.add_function(b'GetModules', <emu_func_type>self.GetModules)
        self.add_function(b'Equals', <emu_func_type>self.Equals)

    cdef DotNetObject duplicate(self):
        cdef DotNetAssembly asm = DotNetAssembly(self.get_emulator_obj(), self.module)
        DotNetObject.duplicate_into(self, asm)
        return asm

    cdef void duplicate_into(self, DotNetObject result):
        (<DotNetAssembly>result).module = self.module
        DotNetObject.duplicate_into(self, result)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.Assembly' or DotNetObject.isinst(self, tdef)

    cpdef get_module(self):
        return self.module

    cdef net_emulator.StackCell get_ManifestModule(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetManifestModule(self.get_emulator_obj(), self))

    cdef net_emulator.StackCell get_EntryPoint(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetMemberInfo(self.get_emulator_obj(), self.get_module().get_dotnetpe().get_entry_point()))

    cdef net_emulator.StackCell get_FullName(self, net_emulator.StackCell * params, int nparams):
        cdef dotnetpefile.DotNetPeFile dpe
        cdef net_row_objects.RowObject assembly_obj
        cdef str name
        cdef str version
        cdef net_emulator.StackCell name_cell
        cdef net_emulator.StackCell token_cell
        cdef DotNetAssemblyName assembly_name
        cdef DotNetArray assembly_token
        cdef str pkeytoken
        cdef str string_name
        dpe = self.get_module().get_dotnetpe()
        assembly_obj = dpe.get_metadata_table('Assembly').get(1)
        name = assembly_obj['Name'].get_value().decode('utf-8')
        version = '{}.{}.{}'.format(assembly_obj['MajorVersion'].get_value(), assembly_obj['MinorVersion'].get_value(), assembly_obj['BuildNumber'].get_value())

        name_cell = self.GetName(NULL, 0)
        assembly_name = <DotNetAssemblyName>name_cell.item.ref
        token_cell = assembly_name.GetPublicKeyToken()
        assembly_token = <DotNetArray>token_cell.item.ref
        pkeytoken = binascii.hexlify(assembly_token.as_bytes()).decode()
        string_name = '{}, Version={}, Culture=neutral, PublicKeyToken={}'.format(name, version, pkeytoken)
        self.get_emulator_obj().dealloc_cell(name_cell)
        self.get_emulator_obj().dealloc_cell(token_cell)
        return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), string_name.encode('utf-16le')))

    cdef net_emulator.StackCell get_Location(self, net_emulator.StackCell * params, int nparams):
        """
        Some DotNetReactor tamper checks use this. 
        Can be fooled due to the way its structured
        It throws an exception if it detects tampering with the binary, but it wont throw that exception if it cant get the location.
        Return a blank string to fool these checks.  Of note: this may need to be changed eventually if a binary comes along that actually requires this method to work. 
        """
        return self.get_emulator_obj().pack_object(DotNetString.Empty(self.get_emulator_obj().get_appdomain(), NULL, 0))

    @staticmethod
    cdef net_emulator.StackCell GetExecutingAssembly(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetAssembly dotnetassembly
        dotnetassembly = DotNetAssembly(app_domain.get_emulator_obj(),
            app_domain.get_executing_dotnetpe().get_metadata_table('Assembly').get(1))
        dotnetassembly.set_type_obj(app_domain.get_executing_dotnetpe().get_type_by_full_name(
            b'System.Reflection.Assembly'))
        return app_domain.get_emulator_obj().pack_object(dotnetassembly)

    @staticmethod
    cdef net_emulator.StackCell GetCallingAssembly(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetAssembly dotnetassembly = DotNetAssembly(app_domain.get_emulator_obj(), app_domain.get_calling_dotnetpe().get_metadata_table('Assembly').get(1))
        dotnetassembly.set_type_obj(app_domain.get_calling_dotnetpe().get_type_by_full_name(b'System.Reflection.Assembly'))
        return app_domain.get_emulator_obj().pack_object(dotnetassembly)

    cdef net_emulator.StackCell GetManifestResourceStream(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetString name = <DotNetString> args[0]
        cdef bytes resource_data
        cdef DotNetObject obj
        cdef DotNetArray array_obj = None
        cdef Py_ssize_t x = 0
        cdef list internal_list = list()
        cdef net_emulator.StackCell num
        resource_data = self.get_emulator_obj().get_appdomain().get_resource_by_name(name, self)
        if not resource_data:
            return self.get_emulator_obj().pack_null()

        array_obj = DotNetArray(self.get_emulator_obj(), len(resource_data), self.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(b'System.Byte'), False)
        for x in range(len(resource_data)):
            num = self.get_emulator_obj().pack_u1(resource_data[x])
            array_obj._set_item(x, num)
        obj = DotNetStream(self.get_emulator_obj())
        num = self.get_emulator_obj().pack_object(obj)
        obj.ctor(&num, 1)
        self.get_emulator_obj().dealloc_cell(num)
        
        obj.set_type_obj(self.get_module().get_dotnetpe().get_type_by_full_name(
            b'System.IO.Stream'))
        return self.get_emulator_obj().pack_object(obj)

    cdef net_emulator.StackCell GetManifestResourceNames(self, net_emulator.StackCell * params, int nparams):
        cdef net_table_objects.TableObject resources = self.get_module().get_dotnetpe().get_metadata_table('ManifestResource')
        cdef list result = list()
        cdef net_row_objects.RowObject item
        cdef DotNetString dns
        cdef DotNetArray results
        cdef Py_ssize_t x = 0
        if resources:
            for item in resources:
                dns = DotNetString(self.get_emulator_obj(), item['Name'].get_value(), 'utf-8')
                result.append(dns)
        
        results = DotNetArray(self.get_emulator_obj(), len(result), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.String'),
                    initialize=False)
        for x in range(len(result)):
            results._set_item(x, self.get_emulator_obj().pack_object(result[x]))

        return self.get_emulator_obj().pack_object(results)

    cdef net_emulator.StackCell GetName(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetAssemblyName obj = DotNetAssemblyName(self.get_emulator_obj(), self.get_module()['Name'].get_value(), self)
        obj.set_type_obj(self.get_module().get_dotnetpe().get_type_by_full_name(
            b'System.Reflection.AssemblyName'))
        return self.get_emulator_obj().pack_object(obj)

    cdef net_emulator.StackCell GetModules(self, net_emulator.StackCell * params, int nparams):
        cdef net_table_objects.TableObject modules = self.get_module().get_dotnetpe().get_metadata_table('Module')
        cdef DotNetArray result = DotNetArray(self.get_emulator_obj(), len(modules), self.get_module().get_dotnetpe().get_type_by_full_name(b'System.Reflection.Module'))
        cdef int x = 0
        for x in range(len(modules)):
            result._set_item(x, self.get_emulator_obj().pack_object(DotNetModule(self.get_emulator_obj(), modules.get(x))))
        return self.pack_object(result)

    cdef net_emulator.StackCell Equals(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()

        cdef DotNetObject other = <DotNetObject>params[0].item.ref
        cdef bint res_val = self.__eq__(other)
        return self.get_emulator_obj().pack_bool(res_val)

    @staticmethod
    cdef net_emulator.StackCell op_Inequality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT or \
            params[0].item.ref == NULL or params[1].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()

        cdef DotNetAssembly param1 = <DotNetAssembly>params[0].item.ref
        cdef DotNetObject param2 = <DotNetObject>params[1].item.ref
        return self.get_emulator_obj().cell_not(param1.Equals([param2]))

    @staticmethod
    cdef net_emulator.StackCell Load(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef net_emulator.StackCell result
        cdef DotNetObject nobj
        cdef DotNetObject dobj = <DotNetObject> params[0].item.ref
        if isinstance(dobj, DotNetArray):
            return app_domain.load_assembly_from_bytes((<DotNetArray>dobj).as_bytes())
        elif isinstance(dobj, DotNetString):
            #For now dont search the filesystem for assemblies, only the current loaded stuff.
            result = app_domain.get_assembly_by_name(<DotNetString>dobj)
            if result.tag == CorElementType.ELEMENT_TYPE_END:
                return app_domain.get_emulator_obj().pack_null()
            return result
        else:
            raise net_exceptions.InvalidArgumentsException()

    def __eq__(self, other):
        return isinstance(other, DotNetAssembly) and self.get_module() == other.get_module()

cdef struct SortHelperStruct:
    PyObject * compare_method
    PyObject * comparison

cdef bint list_sort_helper(net_emulator.StackCell a, net_emulator.StackCell b)
    cdef SortHelperStruct * helper = a.extra_data
    cdef net_row_objects.MethodDef compare_method = helper.compare_method
    cdef DotNetComparison comparison = helper.comparison
    cdef net_emulator.DotNetEmulator emu_obj = compare_method.get_emulator_obj().spawn_new_emulator(compare_method, caller=None)
    cdef net_emulator.StackCell * temp_params = malloc(sizeof(net_emulator.StackCell) * 3)
    cdef Py_ssize_t x = 0
    cdef net_emulator.StackCel result
    if temp_params == NULL:
        raise net_exceptions.EmulatorExecutionException(compare_method.get_emulator_obj(), 'memory error')
    if compare_method.is_static_method():
        raise net_exceptions.OperationNotSupportedException()
    temp_params[0] = compare_method.get_emulator_obj().pack_object(comparison)
    temp_params[1] = compare_method.get_emulator_obj().duplicate_cell(a)
    temp_params[2] = compare_method.get_emulator_obj().duplicate_cell(b)
    for x in range(3):
        emu_obj._add_param(temp_params[x])
    emu_obj.run_function()
    result = emu_obj.get_stack().pop()
    for x in range(3):
        compare_method.get_emulator_obj().dealloc_cell(temp_params[x])
    if result.tag != CorElementType.ELEMENT_TYPE_I4:
        raise net_exceptions.OperationNotSupportedException()
    if result.item.i4 < 0:
        return True #Goes before since its - TODO check this
    return False

cdef class DotNetList(DotNetObject):  #TODO: Going to need to reorient this to a vector
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'AddRange', <emu_func_type>self.AddRange)
        self.add_function(b'Add', <emu_func_type>self.Add)
        self.add_function(b'Count', <emu_func_type>self.Count)
        self.add_function(b'get_Count', <emu_func_type>self.get_Count)
        self.add_function(b'get_Item', <emu_func_type>self.get_Item)
        self.add_function(b'set_Item', <emu_func_type>self.set_Item)
        self.add_function(b'Sort', <emu_func_type>self.Sort)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef DotNetObject duplicate(self):
        cdef DotNetList result = DotNetList(self.get_emulator_obj())
        self.duplicate_into(result)
        return result

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name().startswith(b'System.Collections.Generic.List') or DotNetObject.isinst(self, tdef)

    cdef void duplicate_into(self, DotNetObject result):
        DotNetObject.duplicate_into(self, result)
        cdef DotNetList other_list = <DotNetList>result
        cdef Py_ssize_t x = 0
        cdef net_emulator.StackCell item
        for x in range(len(self)):
            cell = self.internal[x]
            other_list.Add(&cell, 1)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        cdef int initial_size = 0
        if nparams != 0:
            if params[0].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            initial_size = params[0].item.i4
        self.internal.reserve(initial_size)
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell AddRange(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetArray range_obj = <DotNetArray>params[0].item.ref
        cdef Py_ssize_t x = 0
        cdef net_emulator.StackCell cell
        for x in range(len(range_obj)):
            cell = range_obj._get_item(x)
            self.internal.push_back(cell) #get_item already returns a copy so theres no need to deallocate it and such.
            #Still make clear that we have a ref though on top of the original cell ref
            if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
                if cell.item.ref != NULL:
                    Py_INREF(cell.item.ref)
        return self.get_emulator_obj().pack_blanktag()

    cdef net_emulator.StackCell Add(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1:
            raise net_exceptions.InvalidArgumentsException()
        cdef net_emulator.StackCell cell = self.get_emulator_obj().duplicate_cell(params[0])
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if cell.item.ref != NULL:
                Py_INREF(cell.item.ref)
        self.internal.push_back(cell)
        return self.get_emulator_obj().pack_blanktag()

    cdef net_emulator.StackCell Count(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_i4(<int>self.internal.size())

    cdef net_emulator.StackCell get_Count(self, net_emulator.StackCell * params, int nparams):
        return self.Count(params, nparams)

    cdef net_emulator.StackCell get_Item(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int index = params[0].item.i4
        if index < 0 or index >= len(self):
            raise net_exceptions.InvalidArgumentsException()
        return self.get_emulator_obj().duplicate_cell(self.internal[index])

    cdef net_emulator.StackCell set_Item(self, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int index = params[0].item.i4
        cdef net_emulator.StackCell old
        if index < 0 or index >= len(self):
            raise net_exceptions.InvalidArgumentsException()
        old = self.internal[index]
        if old.tag == CorElementType.ELEMENT_TYPE_OBJECT or old.tag == CorElementType.ELEMENT_TYPE_STRING:
            Py_XDECREF(old.item.ref)
        self.get_emulator_obj().dealloc_cell(old)
        self.internal[index] = self.get_emulator_obj().duplicate_cell(params[1])
        old = self.internal[index]
        if old.tag == CorElementType.ELEMENT_TYPE_OBJECT or old.tag == CorElementType.ELEMENT_TYPE_STRING:
            if old.item.ref != NULL:
                Py_INCREF(old.item.ref)
        return self.get_emulator_obj().pack_blanktag()

    cdef net_emulator.StackCell Sort(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetComparison comparison = <DotNetComparison> params[0].item.ref
        cdef net_row_objects.MethodDefOrRef compare_method
        cdef net_row_objects.TypeDefOrRef parent_type
        cdef net_row_objects.MethodDef method
        cdef SortHelperStruct * sort_helper = malloc(sizeof(SortHelperStruct))
        cdef net_emulator.StackCell * ptr = NULL
        cdef Py_ssize_t x = 0
        if sort_helper == NULL:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'memory error sorting')
        compare_method = comparison.get_method_object()
        if isinstance(compare_method, net_row_objects.MemberRef):
            parent_type = compare_method.get_parent_type()
            if isinstance(parent_type, net_row_objects.TypeSpec):
                parent_type = parent_type.get_type()
            if isinstance(parent_type, net_row_objects.TypeRef):
                raise net_exceptions.OperationNotSupportedException() #likely requires similar logic as a call with a MemberRef and a TypeRef - TODO
            
            #assume parent_Type is TypeDef here.
            for method in parent_type['MethodList'].get_formatted_value():
                if method['Name'].get_value() == compare_method['Name'].get_value():
                    if method.get_method_signature() == compare_method.get_method_signature():
                        compare_method = method
                        break

        if not isinstance(compare_method, net_row_objects.MethodDef):
            raise net_exceptions.ObjectTypeException
        #not my favorite way to do this, but lets start by tagging all elements with sort_helper
        sort_helper.compare_method = compare_method
        sort_helper.comparison = comparison
        for x in range(len(self)):
            ptr = &self.internal[x]
            ptr.extra_data = sort_helper

        sort(self.internal.begin(), self.internal.end(), list_sort_helper)
        for x in range(len(self)):
            ptr = &self.internal[x]
            ptr.extra_data = NULL
        free(sort_helper)
        return self.get_emulator_obj().pack_blanktag()

    def __str__(self):
        cdef str list_string = '['
        cdef Py_ssize_t length = len(self)
        for x in range(length):
            list_string += self.get_emulator_obj().cell_to_str(self.internal[x])
            if x != (length - 1):
                list_string += ', '
        list_string += ']'
        return '{} Count={}'.format(list_string, length)

    def __len__(self):
        return <Py_ssize_t>self.internal.size()

    def __dealloc__(self):
        cdef Py_ssize_t x = 0
        cdef net_emulator.StackCell old
        for x in range(len(self)):
            old = self.internal[x]
            if old.tag == CorElementType.ELEMENT_TYPE_OBJECT or old.tag == CorElementType.ELEMENT_TYPE_STRING:
                Py_XDECREF(old.item.ref)
            self.get_emulator_obj().dealloc_cell(old)
        self.internal.clear()

#TODO: This might have to be a special constructor to support internal stuff
#TODO: I dont think System.Array newobj is valid anyway, should be fine.
cdef class DotNetArray(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, uint64_t size, net_row_objects.TypeDefOrRef type_obj=None, bint initialize=False):
        DotNetObject.__init__(self, emulator_obj)
        self.__size = size
        self.set_type_obj(type_obj)
        #If I change how this is set up, it will save a literal ton of time.
        self.__internal_array = malloc(sizeof(net_emulator.StackCell) * self.__size)
        if self.__internal_array == NULL and self.__size > 0:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'memory error for array')
        if self.__internal_array != NULL:
            memset(self.__internal_array, 0, sizeof(net_emulator.StackCell) * self.__size)
        if initialize:
            self.setup_default_value(0, size)

    def __dealloc__(self):
        cdef uint64_t x = 0
        cdef net_emulator.StackCell cell
        if self.__internal_array != NULL:
            for x in range(self.__size):
                cell = self.__internal_array[x]
                if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
                    Py_XDECREF(cell.item.ref)
                self.get_emulator_obj().dealloc_cell(cell)
            free(self.__internal_array)
            self.__internal_array = NULL

    cdef net_emulator.StackCell _get_item(self, uint64_t index):
        if index < self.__size:
            return self.get_emulator_obj().duplicate_cell(self.__internal_array[index])
        return self.get_emulator_obj().pack_blanktag()

    cdef bint _set_item(self, uint64_t index, net_emulator.StackCell cell): #TODO: Here and in other similar places (feilds, static fields, locals, we are going to want to copy the cell to prevent memory issues)
        if index >= self.__size:
            return False
        if cell.tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        cdef net_emulator.StackCell old = self.__internal_array[index]
        cdef net_emulator.StackCell duped = self.get_emulator_obj().duplicate_cell(cell)
        if old.tag == CorElementType.ELEMENT_TYPE_OBJECT or old.tag == CorElementType.ELEMENT_TYPE_STRING:
            Py_XDECREF(old.item.ref)
        if cell.tag == CorElementType.ELEMENT_TYPE_OBJECT or cell.tag == CorElementType.ELEMENT_TYPE_STRING:
            if cell.item.ref != NULL:
                Py_INCREF(cell.item.ref)
        self.get_emulator_obj().dealloc_cell(old)
        memcpy(&self.__internal_array[index], &duped, sizeof(duped))
        return True

    cdef DotNetObject duplicate(self):
        cdef DotNetArray result = DotNetArray(self.get_emulator_obj(), self.__size, self.get_type_obj(), initialize=False)
        cdef uint64_t x = 0
        cdef net_emulator.StackCell cell
        for x in range(self.__size):
            cell = self._get_item(x)
            result._set_item(x, cell)
            self.get_emulator_obj().dealloc_cell(cell)
        DotNetObject.duplicate_into(self, result) #TODO FIXME: need to do this for the others to get type_obj
        return result

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Array' or DotNetObject.isinst(self, tdef)

    cpdef bytes as_bytes(self):
        cdef bytes result = b''
        cdef bytes type_name = None
        cdef uint64_t x = 0
        if self.get_type_obj() is not None:
            type_name = self.get_type_obj().get_full_name()
            if type_name == b'System.Byte' or type_name == b'System.UInt8':
                for x in range(self.__size):
                    result += bytes([self.__internal_array[x].item.u4])
                return result
        raise net_exceptions.OperationNotSupportedException()

    cdef void setup_default_value(self, uint64_t index, uint64_t size):
        cdef uint64_t x = 0
        cdef net_emulator.StackCell num
        cdef DotNetObject dno = None
        cdef bytes full_name = self.get_type_obj().get_full_name()
        cdef net_sigs.CorLibTypeSig type_sig = net_utils.get_cor_type_from_name(full_name)
        if type_sig is not NULL:
            for x in range(size):
                num =  self.get_emulator_obj()._get_default_value(type_sig)
                self._set_item(index + x, num)
                self.get_emulator_obj().dealloc_cell(num)
        else:
            for x in range(size):
                if not self.get_type_obj().is_valuetype():
                    num = self.get_emulator_obj().pack_null():
                    self._set_item(index + x, num)
                else:
                    dno = DotNetObject(emulator_obj, self.get_type_obj())
                    num = self.get_emulator_obj().pack_object(dno)
                    self._set_item(index + x, num)
                self.get_emulator_obj().dealloc_cell(num)

    @staticmethod
    cdef net_emulator.StackCell Copy(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 5:
            raise net_exceptions.InvalidArgumentsException()
        if params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or param[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        if params[1].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        if params[2].tag != CorElementType.ELEMENT_TYPE_OBJECT or param[2].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        if params[3].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        if params[4].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        
        cdef DotNetArray src = <DotNetArray> params[0].item.ref
        cdef int srcIndex = params[1].item.i4
        cdef DotNetArray dst = <DotNetArray> params[2].item.ref
        cdef int dstIndex = params[3].item.i4
        cdef int count = params[4].item.i4
        cdef int x = 0
        cdef net_emulator.StackCell cell
        for x in range(count):
            cell = src._get_item(srcIndex + x)
            dst._set_item(dstIndex + x, cell)
            app_domain.get_emulator_obj().dealloc_cell(cell)
        return app_domain.get_emulator_obj().pack_blanktag()

    @staticmethod
    cdef net_emulator.StackCell Clear(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 3 or params[1].tag != CorElementType.ELEMENT_TYPE_I4 or params[2].tag != CorElementType.ELEMENT_TYPE_I4 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetArray array_obj = <DotNetArray>params[0].item.ref
        cdef int index = params[1].item.i4
        cdef int length = params[2].item.i4

        array_obj.setup_default_value(index, length)
        return app_domain.get_emulator_obj().pack_blanktag()

    cdef void reverse_internal(self, int start, int end):
        if self.__internal_array == NULL:
            return
        cdef int actual_start = start
        cdef int actual_end = 0
        cdef net_emulator.StackCell * ptr = NULL
        cdef int size = 0
        cdef int x = 0
        cdef int y = 0
        cdef net_emulator.StackCell cell
        if actual_start == -1:
            actual_start = 0
        if end == -1:
            actual_end = <int>self.__size - actual_start
        else:
            actual_end = actual_start + end
        
        if (actual_end - actual_start) == 0:
            return
        size = actual_end - actual_start
        ptr = malloc(sizeof(net_emulator.StackCell) * size)
        if ptr == NULL:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'not enough memory')
        
        for x in range(actual_end - 1, actual_start - 1):
            ptr[y] = self.__internal_array[x]
            y += 1

    @staticmethod
    cdef net_emulator.StackCell Reverse(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams == 0 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetArray array = <DotNetArray>params[0].item.ref
        cdef int start = -1
        cdef int end = -1
        if nparams == 3:
            if params[1].tag != CorElementType.ELEMENT_TYPE_I4 or params[2].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            start = params[1].item.i4
            end = params[2].item.i4
        array.reverse_internal(start, end)
        return app_domain.get_emulator_obj().pack_blanktag()

    def __len__(self):
        return <Py_ssize_t>self.__size

    def __str__(self): #TODO Fix this method
        cdef str array_str = ''
        cdef int type_rid = 0
        cdef str type_name = None
        cdef Py_ssize_t int_len = len(self)
        cdef str begin = None
        cdef str end = None
        cdef Py_ssize_t x = 0
        array_str += '['
        for x in range(int_len):
            array_str += self.get_emulator_obj().cell_to_str(self.__internal_array[x])
            if x != (int_len - 1):
                array_str += ', '
        array_str += ']'
        if len(array_str) > 250:
            if self.get_type_obj() != None:
                type_rid = self.get_type_obj().get_rid()
                type_name = self.get_type_obj().get_table_name()
            else:
                type_rid = 'unkown_rid'
                type_name = 'unknown_table_name'
            begin = array_str[:50]
            end = array_str[-50:]
            return 'DotNetArray: type_obj={}:{}, len={}, begin={}, end={}'.format(type_name,
                                                                                  type_rid,
                                                                                  int_len,
                                                                                  begin, end)
        return 'DotnetArray: type_obj={}:{} len={}, content={}'.format(self.get_type_obj().get_table_name(), self.get_type_obj().get_rid(),
                                                                       len(self), array_str)

cdef class DotNetStackTrace(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'GetFrame', <emu_func_type>self.GetFrame)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Diagnostics.StackTrace' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetStackTrace strace = DotNetStackTrace(self.get_emulator_obj())
        strace.skipFrames = self.skipFrames
        strace.fNeedFileInfo = self.fNeedFileInfo
        DotNetObject.duplicate_into(self, strace)
        return strace

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        cdef int num = 0
        cdef bint bobj = False
        if nparams >= 1:
            if params[0].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            self.skipFrames = params[0].item.i4
        else:
            self.skipFrames = num
        if len(args) == 2:
            if params[1].tag != CorElementType.ELEMENT_TYPE_BOOLEAN:
                raise net_exceptions.InvalidArgumentsException()
            self.fNeedFileInfo = params[1].item.b
        else:
            self.fNeedFileInfo = bobj
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell GetFrame(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int number = <DotNetInt32>params[0].item.i4
        cdef list emulator_list
        cdef net_emulator.DotNetEmulator emulator_ptr
        cdef DotNetStackFrame sf_obj
        emulator_list = list()
        # first generate the list of emulators
        emulator_ptr = self.get_emulator_obj()
        while emulator_ptr:
            emulator_list.insert(0, emulator_ptr)
            emulator_ptr = emulator_ptr.get_caller()
        sf_obj = DotNetStackFrame(self.get_emulator_obj())
        sf_obj.ctor(&self.skipFrames, 1)
        sf_obj.set_type_obj(self.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(
            b'System.Diagnostics.StackFrame'))
        sf_obj.current_emulator = emulator_list[number.as_int()]
        return self.get_emulator_obj().pack_object(sf_obj)

cdef class DotNetStackFrame(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.current_emulator = None
        self.add_function(b'.ctor', <emu_func_type>self.ctor)
        self.add_function(b'GetMethod', <emu_func_type>self.GetMethod)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Diagnostics.StackFrame' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetStackFrame sframe = DotNetStackFrame(self.get_emulator_obj())
        sframe.skip_frames = self.skip_frames
        sframe.current_emulator = self.current_emulator
        DotNetObject.duplicate_into(self, sframe)
        return sframe

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams == 1:
            if params[0].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            self.skip_frames = params[0].item.i4
        else:
            self.skip_frames = 0
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell GetMethod(self, net_emulator.StackCell * params, int nparams):
        cdef net_emulator.DotNetEmulator emulator_obj = self.get_emulator_obj()
        cdef int x = 0
        cdef DotNetMemberInfo obj = None
        cdef DotNetObject n = None
        for x in range(self.skip_frames):
            emulator_obj = emulator_obj.get_caller()
        if emulator_obj is None:
            return self.get_emulator_obj().pack_null()
        obj = DotNetMemberInfo(self.get_emulator_obj(), emulator_obj.get_method_obj())
        obj.set_type_obj(emulator_obj.get_method_obj().get_dotnetpe().get_type_by_full_name(
            b'System.Reflection.MemberInfo'))
        return self.get_emulator_obj().pack_object(obj)

cdef class DotNetMemberInfo(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.MethodDefOrRef internal_method):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_method = internal_method
        if self.internal_method is None:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'Invalid DotNetMemberInfo created')
        self.add_function(b'get_DeclaringType', <emu_func_type>self.get_DeclaringType)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.MemberInfo' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetMemberInfo minfo = DotNetMemberInfo(self.get_emulator_obj(), self.internal_method)
        DotNetObject.duplicate_into(self, minfo)
        return minfo

    cdef void duplicate_into(self, DotNetObject result):
        (<DotNetMemberInfo>result).internal_method = self.internal_method

    cdef net_emulator.StackCell get_DeclaringType(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), self.internal_method.get_parent_type()))

#There should never be a DotNetConsole() object on the stack so no need for duplicate etc.
cdef class DotNetConsole(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell WriteLine(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1:
            raise net_exceptions.InvalidArgumentsException()
        print(app_domain.get_emulator_obj().cell_to_str(params[0]))
        return app_domain.get_emulator_obj().pack_blanktag()

    @staticmethod
    cdef net_emulator.StackCell Write(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        #print(item)
        return app_domain.get_emulator_obj().pack_blanktag()

cpdef object dne_thread_runner(dnfunc):
    raise Exception()
"""
    cdef DotNetFunc func = <DotNetFunc>dnfunc
    func.Invoke([])
    return None
"""
cdef class DotNetThread(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        cdef int one = 1
        DotNetObject.__init__(self, emulator_obj)
        #DotNetThread.__identifier should increment on each new thread.  Going to need to work on this a bit. TODO
        
        self.__identifier = DotNetInt32(self.get_emulator_obj(), None)
        self.__identifier.from_int(one)
        self.__internal_thread = None

        self.add_function(b'Start', <emu_func_type>self.Start)
        self.add_function(b'Join', <emu_func_type>self.Join)
        self.add_function(b'get_ManagedThreadId', <emu_func_type>self.get_ManagedThreadId)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Threading.Thread' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetThread tobj = DotNetThread(self.get_emulator_obj())
        tobj.__identifier = self.__identifier
        tobj.__internal_thread = self.__internal_thread
        tobj.__thread_start = self.__thread_start
        DotNetObject.duplicate_into(self, tobj)
        return tobj

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams == 1:
            if params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
                raise net_exceptions.InvalidArgumentsException()
            self.__thread_start = params[0].item.ref
        else:
            self.__thread_start = None
        return self.get_emulator_obj().pack_object(self)

    cpdef void set_identifier(self, int identifier):
        self.__identifier = identifier

    cdef net_emulator.StackCell Start(self, net_emulator.StackCell * params, int nparams):
        """cdef DotNetObject nobj
        cdef DotNetFunc dnfunc
        if not isinstance(self.__thread_start, DotNetThreadStart):
            raise net_exceptions.InvalidArgumentsException()
        nobj = DotNetObject(self.get_emulator_obj())
        nobj.flag_null()
        dnfunc = DotNetFunc(self.get_emulator_obj(), nobj, self.__thread_start.get_method_object())
        self.__internal_thread = threading.Thread(target=dne_thread_runner, args=[dnfunc])
        self.__internal_thread.start()
        return None"""
        raise Exception()

    cdef net_emulator.StackCell Join(self, net_emulator.StackCell * params, int nparams):
        if self.__internal_thread == None:
            raise net_exceptions.InvalidArgumentsException()
        self.__internal_thread.join()
        return self.get_emulator_obj().pack_blanktag()

    @staticmethod
    cdef net_emulator.StackCell get_CurrentThread(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetThread tobj
        # Emulator doesnt support threads so just return a fake object.
        tobj = DotNetThread(app_domain.get_emulator_obj())
        tobj.set_type_obj(app_domain.get_executing_dotnetpe().get_type_by_full_name(
            b'System.Threading.Thread'))
        return self.get_emulator_obj().pack_object(tobj)

    @staticmethod
    cdef net_emulator.StackCell Sleep(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_blanktag() # For now, just ignore sleeps.  I have not seen an obfuscator attempt to detect this.

    cdef net_emulator.StackCell get_ManagedThreadId(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_i4(self.__identifier)

#TODO: left off here
cdef void initialize_array_helper(DotNetArray arr, net_row_objects.RowObject runtime_handle) except *:
    cdef net_row_objects.Field field_obj
    cdef Py_ssize_t x
    cdef Py_ssize_t type_size
    cdef Py_ssize_t curr_index
    cdef bytes type_name
    cdef bytes data
    cdef net_emulator.StackCell current_number
    if isinstance(runtime_handle, net_row_objects.Field):
        field_obj = <net_row_objects.Field> runtime_handle
        data = field_obj.get_data()
        type_name = arr.get_type_obj()['TypeName'].get_value()
        if type_name == b'UInt32':
            type_size = 4
            curr_index = 0
            for x in range(len(arr)):
                current_number = arr.get_emulator_obj().pack_u4(int.from_bytes(data[curr_index:curr_index + type_size], 'little', signed=False))
                arr._set_item(x, current_number)
                arr.get_emulator_obj().dealloc_cell(current_number)
                curr_index += type_size

        elif type_name == b'Int32':
            type_size = 4
            curr_index = 0
            for x in range(len(arr)):
                current_number = arr.get_emulator_obj().pack_i4(int.from_bytes(data[curr_index:curr_index + type_size], 'little', signed=True))
                arr._set_item(x, current_number)
                arr.get_emulator_obj().dealloc_cell(current_number)
                curr_index += type_size

        elif type_name == b'Char':
            type_size = 2
            curr_index = 0
            for x in range(len(arr)):
                current_number = arr.get_emulator_obj().pack_char(int.from_bytes(data[curr_index:curr_index + type_size], 'little', signed=False))
                arr._set_item(x, current_number)
                arr.get_emulator_obj().dealloc_cell(current_number)
                curr_index += type_size

        elif type_name == b'Byte':
            curr_index = 0
            for x in range(len(arr)):
                current_number = arr.get_emulator_obj().pack_u1(data[curr_index])
                arr._set_item(x, current_number)
                arr.get_emulator_obj().dealloc_cell(current_number)
                curr_index += 1

        else:
            raise Exception()  # FIXME: change
    else:
        raise Exception()  # FIXME: change

cdef class DotNetRuntimeHelpers(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell InitializeArray(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        #static methods cant be cdef but we should take advantage of loop speeds.
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetArray arr = <DotNetArray>params[0].item.ref
        cdef DotNetRuntimeFieldHandle runtime_handle = <DotNetRuntimeFieldHandle>params[1].item.ref
        initialize_array_helper(arr, runtime_handle.internal_field)
        return app_domain.get_emulator_obj().pack_blanktag()

cdef class DotNetMath(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell Max(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or not net_utils.is_cortype_number(params[0]) or not net_utils.is_cortype_number(params[1]):
            raise net_exceptions.InvalidArgumentsException()
        if params[0].tag != params[1].tag:
            raise net_exceptions.InvalidArgumentsException()

        cdef net_emulator.StackCell cell

        cdef uint64_t val_one = 0
        cdef uint64_t val_two = 0
        cdef int64_t val_three = 0
        cdef int64_t val_four = 0

        if net_utils.is_cortype_signed(params[0].tag):
            val_three = params[0].item.i8
            val_four = params[1].item.i8
            if val_three > val_four:
                cell = app_domain.get_emulator_obj().pack_i8(val_three)
                cell.tag = params[0].tag
            else:
                cell = app_domain.get_emulator_obj().pack_i8(val_four)
                cell.tag = params[1].tag
            return cell
        elif net_utils.is_cortype_unsigned(params[0].tag):
            val_one = params[0].item.u8
            val_two = params[1].item.u8
            if val_three > val_four:
                cell = app_domain.get_emulator_obj().pack_u8(val_one)
                cell.tag = params[0].tag
            else:
                cell = app_domain.get_emulator_obj().pack_u8(val_two)
                cell.tag = params[1].tag
            return cell
        raise net_exceptions.InvalidArgumentsException()
                

    @staticmethod
    cdef net_emulator.StackCell Abs(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams == 0 or not net_utils.is_cortype_number(params[0].tag):
            raise net_exceptions.InvalidArgumentsException()
        cdef net_emulator.StackCell arg = params[0]
        cdef int val_one = 0
        cdef unsigned int val_two = 0
        cdef int64_t val_three = 0
        cdef uint64_t val_four = 0
        if arg.tag == CorElementType.ELEMENT_TYPE_I:
            if app_domain.get_emulator_obj().is_64bit():
                val_three = abs(arg.item.i8)
                return app_domain.get_emulator_obj().pack_i(val_three)
            else:
                val_one = abs(arg.item.i4)
                return app_domain.get_emulator_obj().pack_i(val_one)
        elif arg.tag == CorElementType.ELEMENT_TYPE_U:
            if app_domain.get_emulator_obj().is_64bit():
                val_four = abs(arg.item.u8)
                return app_domain.get_emulator_obj().pack_u(val_four)
            else:
                val_two = abs(arg.item.u4)
                return app_domain.get_emulator_obj().pack_u(val_two)
        elif arg.tag == CorElementType.ELEMENT_TYPE_I4:
            return app_domain.get_emulator_obj().pack_i4(abs(arg.item.i4))
        elif arg.tag == CorElementType.ELEMENT_TYPE_U4:
            return app_domain.get_emulator_obj().pack_u4(abs(arg.item.u4))
        elif arg.tag == CorElementType.ELEMENT_TYPE_I8:
            return app_domain.get_emulator_obj().pack_i8(abs(arg.item.i8))
        elif arg.tag == CorElementType.ELEMENT_TYPE_U8:
            return app_domain.get_emulator_obj().pack_u8(abs(arg.item.u8))
        elif arg.tag == CorElementType.ELEMENT_TYPE_R4:
            return app_domain.get_emulator_obj().pack_r4(abs(<float>arg.item.r8))
        elif arg.tag == CorElementType.ELEMENT_TYPE_R8:
            return app_domain.get_emulator_obj().pack_r8(abs(arg.item.r8))

        raise net_exceptions.InvalidArgumentsException()

    @staticmethod
    cdef net_emulator.StackCell Exp(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_R8:
            raise net_exceptions.InvalidArgumentsException()
        cdef double res_val = exp(params[0].item.r8)
        return app_domain.get_emulator_obj().pack_r8(res_val)

    @staticmethod
    cdef net_emulator.StackCell Cos(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_R8:
            raise net_exceptions.InvalidArgumentsException()        
        cdef double res_val = cos(params[0].item.r8)
        return app_domain.get_emulator_obj().pack_r8(res_val)

    @staticmethod
    cdef net_emulator.StackCell Sin(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_R8:
            raise net_exceptions.InvalidArgumentsException()        
        cdef double res_val = sin(params[0].item.r8)
        return app_domain.get_emulator_obj().pack_r8(res_val)

    @staticmethod
    cdef net_emulator.StackCell Tan(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_R8:
            raise net_exceptions.InvalidArgumentsException()        
        cdef double res_val = tan(params[0].item.r8)
        return app_domain.get_emulator_obj().pack_r8(res_val)

    @staticmethod
    cdef net_emulator.StackCell Log(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_R8:
            raise net_exceptions.InvalidArgumentsException()        
        cdef double res_val = log(params[0].item.r8)
        return app_domain.get_emulator_obj().pack_r8(res_val)

cdef class DotNetBitConverter(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell IsLittleEndian(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef bint res_val = sys.byteorder == 'little'
        return app_domain.get_emulator_obj().pack_bool(res_val)

    @staticmethod
    cdef net_emulator.StackCell ToInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams == 0 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetArray aobj = <DotNetArray>params[0].item.ref
        cdef int start_index = 0
        cdef bytearray data = bytearray()
        cdef int x = 0
        cdef net_emulator.StackCell cell
        if nparams == 2:
            if params[1].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            start_index = params[1].item.i4
        for x in range(start_index, start_index+4):
            cell = aobj._get_item(x)
            if cell.tag != CorElementType.ELEMENT_TYPE_U1:
                raise net_exceptions.InvalidArgumentsException()
            data.append(<unsigned char>cell.item.u4)
        
        return app_domain.get_emulator_obj().pack_i4(int.from_bytes(data, 'little', signed=True))

    @staticmethod
    cdef net_emulator.StackCell GetBytes(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or not net_utils.is_cortype_number(params[0].tag):
            raise net_exceptions.InvalidArgumentsException()
        cdef bytes b_data = app_domain.get_emulator_obj().cell_to_bytes(params[0])
        cdef int x = 0
        cdef DotNetArray dnr = DotNetArray(app_domain.get_emulator_obj(), <int>len(b_data),
                          app_domain.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(b'System.Byte'),
                          initialize=False)
        for x in range(len(b_data)):
            dnr._set_item(x, app_domain.get_emulator_obj().pack_u1(b_data[x]))
        return app_domain.get_emulator_obj().pack_object(dnr)

cdef class DotNetBuffer(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell BlockCopy(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 5 or params[1].tag != CorElementType.ELEMENT_TYPE_I4 or params[3].tag != CorElementType.ELEMENT_TYPE_I4 or params[4].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        if params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL or params[2].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[2].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetArray src = <DotNetArray>params[0].item.ref
        cdef int srcOffset = params[1].item.i4
        cdef DotNetArray dst = <DotNetArray>params[2].item.ref
        cdef int dstOffset = params[3].item.i4
        cdef int count = params[4].item.i4
        cdef int x = 0
        cdef net_emulator.StackCell cell
        for x in range(count):
            cell = src._get_item(srcOffset+x)
            if cell.tag == CorElementType.ELEMENT_TYPE_END:
                raise net_exceptions.InvalidArgumentsException()
            
            dst._set_item(dstOffset + x, cell)
            src.get_emulator_obj().dealloc_cell(cell)
        return app_domain.get_emulator_obj().pack_blanktag()

cdef class DotNetAppDomain(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'get_CurrentDomain', <emu_func_type>self.get_CurrentDomain)
        self.add_function(b'add_AssemblyResolve', <emu_func_type>self.add_AssemblyResolve)
        self.add_function(b'add_ResourceResolve', <emu_func_type>self.add_ResourceResolve)
    
    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.AppDomain' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetAppDomain domain = DotNetAppDomain(self.get_emulator_obj())
        DotNetObject.duplicate_into(self, domain)
        return domain

    cdef void duplicate_into(self, DotNetObject result):
        pass

    @staticmethod
    cdef net_emulator.StackCell get_CurrentDomain(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_object(DotNetAppDomain(app_domain.get_emulator_obj()))

    cdef net_emulator.StackCell add_AssemblyResolve(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetResolveEventHandler obj = <DotNetResolveEventHandler>params[0].item.ref
        self.get_emulator_obj().get_appdomain().add_assembly_handler(obj.get_method_obj())
        return self.get_emulator_obj().pack_blanktag()

    cdef net_emulator.StackCell add_ResourceResolve(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetResolveEventHandler obj = <DotNetResolveEventHandler>params[0].item.ref
        self.get_emulator_obj().get_appdomain().add_resource_handler(obj.get_method_obj())
        return self.get_emulator_obj().pack_blanktag()

cdef class DotNetResolveEventHandler(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.ResolveEventHandler'

    cdef DotNetObject duplicate(self): #TODO: may need to rework a bit due to DotNetDelegate change
        cdef DotNetResolveEventHandler h = DotNetResolveEventHandler(self.get_emulator_obj())
        h.__method_object = self.__method_object
        DotNetObject.duplicate_into(self, h)
        return h

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        self.__method_object = params[0].item.ref
        return self.get_emulator_obj().pack_object(self)

    cpdef net_row_objects.MethodDefOrRef get_method_obj(self):
        return self.__method_object.internal_method

cdef class DotNetEncoding(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, str name):
        DotNetObject.__init__(self, emulator_obj)
        self.name = name
        self.add_function(b'GetString', <emu_func_type>self.GetString)
        self.add_function(b'GetBytes', <emu_func_type>self.GetBytes)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Text.Encoding' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetEncoding enc = DotNetEncoding(self.get_emulator_obj(), self.name)
        DotNetObject.duplicate_into(self, enc)
        return enc

    cdef void duplicate_into(self, DotNetObject result):
        pass

    @staticmethod
    cdef net_emulator.StackCell get_UTF8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_object(DotNetEncoding(app_domain.get_emulator_obj(), 'utf-8'))

    @staticmethod
    cdef net_emulator.StackCell get_Unicode(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_object(DotNetEncoding(app_domain.get_emulator_obj(), 'utf-16le'))

    #TODO FIXME This function delcaration is wrong need to figure out expected args.
    cdef net_emulator.StackCell GetString(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray data = <DotNetArray>args[0]
        cdef DotNetInt32 index = DotNetInt32(self.get_emulator_obj(), None)
        cdef DotNetInt32 count = DotNetInt32(self.get_emulator_obj(), None)
        cdef int one = -1
        index.init_zero()
        count.init_from_ptr(<unsigned char *>&one, sizeof(one))
        if len(args) == 3:
            index = <DotNetInt32>args[1]
            count = <DotNetInt32>args[2]

        if count.as_int() >= 0:
            return DotNetString(self.get_emulator_obj(), data[index.as_int():index.as_int() + count.as_int()], self.name)
        else:
            return DotNetString(self.get_emulator_obj(), data[index.as_int():], self.name)
    #TODO this one as well.
    cdef net_emulator.StackCell GetBytes(self, net_emulator.StackCell * params, int nparams):
        if not isinstance(args[0], DotNetString):
            raise net_exceptions.ObjectTypeException
        cdef DotNetString str_obj = <DotNetString>args[0]
        cdef bytes raw_bytes
        cdef DotNetArray result
        cdef unsigned char uc = 0
        cdef DotNetUInt8 num = None
        raw_bytes = str_obj.get_str_data_as_bytes().decode(str_obj.get_str_encoding()).encode(self.name)
        result = DotNetArray(self.get_emulator_obj(), len(raw_bytes),
                             self.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(b'System.Byte'))
        for x in range(len(raw_bytes)):
            num = DotNetUInt8(self.get_emulator_obj(), None)
            uc = raw_bytes[x]
            num.init_from_ptr(&uc, sizeof(uc))
            result[x] = num
        return result

#TODO: need to update this class for new changes
cdef class DotNetString(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, str_data, str str_encoding='utf-16le'):
        DotNetObject.__init__(self, emulator_obj)
        self.str_encoding = str_encoding
        if str_data is not None:
            self.str_data = self.__sanitize_data(str_data)
        else:
            self.str_data = None
        self.add_function(b'Empty', <emu_func_type>self.Empty)
        self.add_function(b'IndexOf', <emu_func_type>self.IndexOf)
        self.add_function(b'StartsWith', <emu_func_type>self.StartsWith)
        self.add_function(b'Replace', <emu_func_type>self.Replace)
        self.add_function(b'get_Length', <emu_func_type>self.get_Length)
        self.add_function(b'EndsWith', <emu_func_type>self.EndsWith)
        self.add_function(b'get_Chars', <emu_func_type>self.get_Chars)
        self.add_function(b'Substring', <emu_func_type>self.Substring)
        self.add_function(b'Split', <emu_func_type>self.Split)
        self.add_function(b'ToString', <emu_func_type>self.ToString)
        self.add_function(b'ctor', <emu_func_type>self.ctor)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray arg = None
        if not isinstance(args[0], DotNetArray):
            raise net_exceptions.InvalidArgumentsException()
        arg = args[0]
        self.str_data = arg.get_internal_array()
        return self

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.String' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetString strobj = DotNetString(self.get_emulator_obj(), self.str_data, self.str_encoding)
        DotNetObject.duplicate_into(self, strobj)
        return strobj

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cpdef str get_str_data_as_str(self):
        return self.get_str_data_as_bytes().decode(self.get_str_encoding())
    
    cdef list __sanitize_data(self, str_data):
        """
        Prevent typing issues by forcing all str_data to be a list of uint8s.
        """
        cdef Py_ssize_t x
        cdef bint is_list_of_dtypes
        cdef list usable_data
        cdef bytes b_data
        cdef bint skip_next_value
        cdef unsigned char * tmpptr = NULL
        cdef unsigned char uc = 0
        cdef unsigned short wc = 0
        cdef DotNetNumber item = None
        cdef DotNetNumber item2 = None
        if isinstance(str_data, DotNetArray) or isinstance(str_data, list) or isinstance(str_data, bytes) or isinstance(str_data, bytearray):
            usable_data = list()
            if isinstance(str_data, bytes) or isinstance(str_data, bytearray):
                #convert all bytes to DotNetChar or DotNetUInt8 according to encoding.
                if self.is_encoding_wide():
                    for x in range(0, len(str_data), 2):
                        item = DotNetChar(self.get_emulator_obj(), None)
                        wc = <unsigned short>int.from_bytes(str_data[x:x+2], 'little')
                        item.from_ushort(wc)
                        usable_data.append(item)
                else:
                    for x in range(len(str_data)):
                        item = DotNetUInt8(self.get_emulator_obj(), None)
                        uc = str_data[x]
                        item.init_from_ptr(&uc, sizeof(uc))
                        usable_data.append(item)
                return usable_data
            else:
                skip_next_value = False
                #if its a list or a DotNetArray, we can check to make sure everything is a dtype.  Dont allow lists that arent dtypes.
                for x in range(len(str_data)):
                    if skip_next_value:
                        skip_next_value = False
                        continue
                    item = str_data[x]
                    if self.is_encoding_wide():
                        if item.__amt_bytes == 2:
                            usable_data.append(item)
                        else:
                            b_data = item.as_bytes() + str_data[x+1].as_bytes()
                            tmpptr = b_data
                            item = DotNetChar(self.get_emulator_obj(), None)
                            item.init_from_ptr(tmpptr, 2)
                            usable_data.append(item)
                            skip_next_value = True
                    else:
                        if item.__amt_bytes == 2:
                            b_data = item.as_bytes()
                            item = DotNetUInt8(self.get_emulator_obj(), None)
                            uc = b_data[0]
                            item.init_from_ptr(&uc, sizeof(uc))
                            usable_data.append(item)
                            item = DotNetUInt8(self.get_emulator_obj(), None)
                            uc = b_data[1]
                            item.init_from_ptr(&uc, sizeof(uc))
                            usable_data.append(item)
                        else:
                            item2 = DotNetUInt8(self.get_emulator_obj(), None)
                            uc = item.as_uchar()
                            item2.init_from_ptr(&uc, sizeof(uc))
                            usable_data.append(item2)
                return usable_data         
        else:
            raise net_exceptions.InvalidArgumentsException()

    cpdef bytes get_str_data_as_bytes(self):
        cdef bytearray result = bytearray()
        cdef DotNetNumber num_obj
        for num_obj in self.str_data:
            result += num_obj.as_bytes() #since weve mostly got typing down we can expect this to be DotNetChar / DotNetUInt8 or something.
        return bytes(result)

    cpdef list get_str_data(self):
        return self.str_data 

    cpdef str get_str_encoding(self):
        return self.str_encoding

    cdef void add_string_internal(self, DotNetString other):
        if self.get_str_encoding() != other.get_str_encoding():
            raise Exception("cant add two strings of different encodings")
        self.str_data = self.str_data + other.get_str_data()

    @staticmethod
    cdef net_emulator.StackCell Empty(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetString(app_domain.get_emulator_obj(), bytes(), 'utf-16le')

    @staticmethod
    cdef net_emulator.StackCell Intern(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetString str_obj = <DotNetString>args[0]
        return str_obj

    @staticmethod
    cdef net_emulator.StackCell Concat(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef int x = 0
        cdef int y = 0
        cdef DotNetString result = DotNetString.Empty(app_domain, [])
        cdef DotNetObject current_arg = None
        cdef list internal_array = None
        for x in range(0, len(args)):
            current_arg = <DotNetObject>args[x]
            if current_arg.is_null():
                current_arg = DotNetString.Empty(app_domain, [])
            if isinstance(current_arg, DotNetString):
                result.add_string_internal(<DotNetString>current_arg)
            elif isinstance(current_arg, DotNetArray):
                internal_array = (<DotNetArray>current_arg).get_internal_array()
                for y in range(len(internal_array)):
                    current_arg = <DotNetObject>internal_array[y]
                    result.add_string_internal(current_arg.ToString([]))
            else:
                result.add_string_internal(current_arg.ToString([]))
        return result

    cdef net_emulator.StackCell IndexOf(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetNumber char_val = <DotNetNumber>args[0]
        cdef int x = 0
        cdef int result = -1
        cdef DotNetInt32 res_obj = DotNetInt32(self.get_emulator_obj(), None)
        for x in range(len(self.get_str_data())):
            item = self.str_data[x]
            if item == char_val:
                result = x
                break
        res_obj.from_int(result)
        return res_obj
    
    cdef net_emulator.StackCell StartsWith(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetString string = <DotNetString>args[0]
        cdef DotNetBoolean result = DotNetBoolean(self.get_emulator_obj(), None)
        cdef bint bobj = False
        if self.get_str_data_as_bytes().startswith(string.get_str_data_as_bytes()):
            bobj = True
        result.from_bool(bobj)
        return result

    cdef net_emulator.StackCell Replace(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetString old_char = <DotNetString> args[0]
        cdef DotNetString new_char = <DotNetString> args[1]
        cdef bytes new_str_data
        if not self.get_str_encoding() == old_char.get_str_encoding() == new_char.get_str_encoding():
            raise net_exceptions.EncodingMismatchException
        new_str_data = self.get_str_data_as_bytes().replace(old_char.get_str_data_as_bytes(), new_char.get_str_data_as_bytes())
        return DotNetString(self.get_emulator_obj(), new_str_data, self.get_str_encoding())

    cdef net_emulator.StackCell get_Length(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        cdef int iobj = <int>len(self.get_str_data())
        result.init_from_ptr(<unsigned char *>&iobj, sizeof(iobj))
        return result

    cpdef bint is_encoding_wide(self):
        cdef str str_encoding
        str_encoding = self.get_str_encoding()
        if str_encoding == 'ascii' or str_encoding == 'utf-8':
            return False
        return True

    cdef net_emulator.StackCell EndsWith(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetString param1 = <DotNetString> args[0]
        cdef DotNetBoolean result = DotNetBoolean(self.get_emulator_obj(), None)
        cdef bint retval = self.get_str_data_as_bytes().endswith(param1.get_str_data_as_bytes())
        result.init_from_ptr(<unsigned char *>&retval, sizeof(retval))
        return result

    def __len__(self):
        return (<DotNetNumber>self.get_Length([])).as_int()

    cdef net_emulator.StackCell get_Chars(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 index = <DotNetInt32>args[0]
        return self.str_data[index.as_int()]

    cdef net_emulator.StackCell Substring(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 start = <DotNetInt32>args[0]
        cdef DotNetInt32 end_index = self.get_Length([])
        if len(args) == 2:
            end_index = <DotNetInt32>args[1]

        return DotNetString(self.get_emulator_obj(), self.get_str_data()[start.as_int():end_index.as_int()], self.get_str_encoding())

    cdef net_emulator.StackCell Split(self, net_emulator.StackCell * params, int nparams):
        if not isinstance(args[0], DotNetArray):
            raise net_exceptions.ObjectTypeException
        cdef DotNetArray char_array = <DotNetArray>args[0]
        cdef bytes python_data
        cdef DotNetNumber item
        cdef DotNetString item2
        cdef bytearray split_by
        cdef DotNetArray result
        cdef int x
        cdef list python_result
        cdef dotnetpefile.DotNetPeFile dpe
        cdef net_emulator.DotNetEmulator emu_obj
        cdef net_row_objects.TypeRef type_obj
        cdef net_row_objects.MethodDef method_obj

        #first get the result in terms of python
        #assume utf-16le for now
        if not self.get_str_encoding() == 'utf-16le':
            raise net_exceptions.EncodingMismatchException

        python_data = self.get_str_data_as_bytes()

        split_by = bytearray()
        for item in char_array.get_internal_array():
            split_by += item.as_bytes()

        python_result = python_data.split(split_by)
        emu_obj = self.get_emulator_obj()
        method_obj = emu_obj.get_method_obj()
        dpe = method_obj.get_dotnetpe()
        type_obj = dpe.get_type_by_full_name(b'System.String')
        result = DotNetArray(self.get_emulator_obj(), len(python_result), type_obj=type_obj)
        for x in range(len(python_result)):
            item = DotNetString(self.get_emulator_obj(), python_result[x])
            result[x] = item
        return result

    def __eq__(self, other):
        return isinstance(other, DotNetString) and self.get_str_data_as_bytes().decode(self.get_str_encoding()) == other.get_str_data_as_bytes().decode(other.get_str_encoding())

    @staticmethod
    cdef net_emulator.StackCell op_Equality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetObject obj1 = <DotNetObject> args[0]
        cdef DotNetObject obj2 = <DotNetObject> args[1]
        cdef DotNetBoolean res_obj = DotNetBoolean(app_domain.get_emulator_obj(), None)
        cdef bint result = obj1 == obj2
        res_obj.from_bool(result)
        return res_obj

    def __str__(self):
        return 'string={}, encoding={}, hexlified={}, decoded={}'.format(self.get_str_data().__str__()[:50], self.get_str_encoding(), binascii.hexlify(self.get_str_data_as_bytes())[:50], self.get_str_data_as_bytes().decode(self.get_str_encoding(), errors='ignore')[:50])

    cdef net_emulator.StackCell ToString(self, net_emulator.StackCell * params, int nparams):
        return self

    def __hash__(self):
        cdef bytes full_val = bytes(self.get_str_data_as_bytes() + self.get_str_encoding().encode('ascii'))
        return hash(full_val)

#Utility constructor
cdef class DotNetModule(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.RowObject internal_module):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_module = internal_module
        self.add_function(b'get_ModuleHandle', <emu_func_type>self.get_ModuleHandle)
        self.add_function(b'ResolveMethod', <emu_func_type>self.ResolveMethod)
        self.add_function(b'ResolveType', <emu_func_type>self.ResolveType)
        self.add_function(b'ResolveField', <emu_func_type>self.ResolveField)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.Module' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetModule module = DotNetModule(self.get_emulator_obj(), self.internal_module)
        DotNetObject.duplicate_into(self, module)
        return module

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell get_ModuleHandle(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetModuleHandle(self.get_emulator_obj(), self.internal_module))

    cdef net_emulator.StackCell ResolveMethod(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int method_token = params[0].item.i4
        cdef net_row_objects.RowObject robj = self.internal_module.get_dotnetpe().get_token_value(method_token)
        if robj is None:
            raise net_exceptions.InvalidArgumentsException()
        return self.get_emulator_obj().pack_object(DotNetMethodInfo(self.get_emulator_obj(), robj))

    cdef net_emulator.StackCell ResolveType(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int method_token = params[0].item.i4
        cdef net_row_objects.RowObject robj = self.internal_module.get_dotnetpe().get_token_value(method_token)
        if robj is None:
            raise net_exceptions.InvalidArgumentsException()
        return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), robj))

    cdef net_emulator.StackCell ResolveField(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int method_token = params[0].item.i4
        cdef net_row_objects.RowObject robj = self.internal_module.get_dotnetpe().get_token_value(method_token)
        if robj is None:
            raise net_exceptions.InvalidArgumentsException()
        return self.get_emulator_obj().pack_object(DotNetFieldInfo(self.get_emulator_obj(), robj))

#Utility constructor
cdef class DotNetModuleHandle(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.RowObject internal_module):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_module = internal_module
        self.add_function(b'ResolveTypeHandle', <emu_func_type>self.ResolveTypeHandle)
        self.add_function(b'ResolveMethodHandle', <emu_func_type>self.ResolveMethodHandle)
        self.add_function(b'GetRuntimeTypeHandleFromMetadataToken', <emu_func_type>self.GetRuntimeTypeHandleFromMetadataToken)

    def __str__(self):
        return 'ModuleObject {}'.format(self.internal_module)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.ModuleHandle' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetModuleHandle modh = DotNetModuleHandle(self.get_emulator_obj(), self.internal_module)
        DotNetObject.duplicate_into(self, modh)

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell ResolveTypeHandle(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int method_token = params[0].item.i4
        cdef net_row_objects.RowObject robj = self.internal_module.get_dotnetpe().get_token_value(method_token)
        if robj is None:
            raise net_exceptions.InvalidArgumentsException()
        return self.get_emulator_obj().pack_object(DotNetRuntimeTypeHandle(self.get_emulator_obj(), robj))

    cdef net_emulator.StackCell ResolveMethodHandle(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int method_token = params[0].item.i4
        cdef net_row_objects.RowObject robj = self.internal_module.get_dotnetpe().get_token_value(method_token)
        if robj is None:
            raise net_exceptions.InvalidArgumentsException()
        return self.get_emulator_obj().pack_object(DotNetRuntimeMethodHandle(self.get_emulator_obj(), robj))

    cdef net_emulator.StackCell GetRuntimeTypeHandleFromMetadataToken(self, net_emulator.StackCell * params, int nparams):
        return self.ResolveTypeHandle(params, nparams)

cdef class DotNetRuntimeTypeHandle(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.TypeDefOrRef internal_typedef):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_typedef = internal_typedef
        if self.internal_typedef is None:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'Invalid RuntimeTypeHandle created')
    
    cpdef get_internal_typedef(self):
        return self.internal_typedef

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.RuntimeTypeHandle' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetRuntimeTypeHandle thandle = DotNetRuntimeTypeHandle(self.get_emulator_obj(), self.internal_typedef)
        DotNetObject.duplicate_into(self, thandle)
        return thandle

    cdef void duplicate_into(self, DotNetObject result):
        pass

    def __str__(self):
        return 'DotNetRuntimeTypeHandle: {}-{} - {}'.format(self.internal_typedef.get_table_name(), self.internal_typedef.get_rid(),
                                                            self.internal_typedef.get_full_name())

cdef class DotNetRuntimeMethodHandle(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.MethodDefOrRef internal_method):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_method = internal_method

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.RuntimeMethodHandle' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetRuntimeMethodHandle mhandle = DotNetRuntimeMethodHandle(self.get_emulator_obj(), self.internal_method)
        DotNetObject.duplicate_into(self, mhandle)
        return mhandle

    cdef void duplicate_into(self, DotNetObject result):
        pass

cdef class DotNetRuntimeFieldHandle(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.Field internal_field):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_field = internal_field

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.RuntimeFieldHandle' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetRuntimeFieldHandle fhandle = DotNetRuntimeFieldHandle(self.get_emulator_obj(), self.internal_field)
        DotNetObject.duplicate_into(self, fhandle)
        return fhandle

    cdef void duplicate_into(self, DotNetObject result):
        pass

cdef class DotNetFieldInfo(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.Field internal_field):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_field = internal_field
        if self.internal_field is None:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'Invalid FieldInfo created')
        self.add_function(b'get_FieldType', <emu_func_type>self.get_FieldType)
        self.add_function(b'SetValue', <emu_func_type>self.SetValue)
        self.add_function(b'get_Name', <emu_func_type>self.get_Name)

    def __str__(self):
        return 'FieldObject {} {}'.format(hex(self.internal_field.get_token()), self.internal_field.get_full_name())

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.FieldInfo' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetFieldInfo finfo = DotNetFieldInfo(self.get_emulator_obj(), self.internal_field)
        DotNetObject.duplicate_into(self, finfo)
        return finfo

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell get_FieldType(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetType type_obj = DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(
            self.internal_field.get_parent_type()))
        return self.get_emulator_obj().pack_object(type_obj)

    cdef net_emulator.StackCell SetValue(self, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag == CorElementType.ELEMENT_TYPE_END:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetObject obj = <DotNetObject> params[0].item.ref
        cdef net_emulator.StackCell cell = params[1]
        if self.internal_field.is_static():
            self.get_emulator_obj().set_static_field(self.internal_field.get_rid(), cell)
        else:
            obj.set_field(self.internal_field.get_rid(), cell)
        return self.get_emulator_obj().pack_blanktag()

    cdef net_emulator.StackCell get_Name(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNetString(self.get_emulator_obj(), self.internal_field['Name'].get_value(), 'utf-8'))

    def __str__(self):
        return 'DotNetFieldInfo: Field-{}, {}'.format(self.internal_field.get_rid(), self.internal_field['Name'].get_value())

cdef class DotNetMethodInfo(DotNetMethodBase):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.MethodDefOrRef internal_method):
        DotNetMethodBase.__init__(self, emulator_obj, internal_method)
        self.add_function(b'get_ReturnType', <emu_func_type>self.get_ReturnType)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.MethodInfo' or DotNetMethodBase.isinst(self, tdef)

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef DotNetObject duplicate(self):
        cdef DotNetMethodInfo minfo = DotNetMethodInfo(self.get_emulator_obj(), self.internal_method)
        DotNetMethodBase.duplicate_into(self, minfo)
        return minfo

    cdef net_emulator.StackCell get_ReturnType(self, net_emulator.StackCell * params, int nparams):
        cdef net_sigs.TypeSig return_sig = self.internal_method.get_method_signature().get_return_type()
        cdef bytes type_name
        cdef net_row_objects.TypeDefOrRef type_obj
        if isinstance(return_sig, net_sigs.CorLibTypeSig):
            type_name = get_cor_type_name(return_sig.get_element_type())
            type_obj = self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(type_name)
            return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), type_obj, return_sig))
        else:
            if isinstance(return_sig, net_sigs.TypeDefOrRefSig) and return_sig.get_type() is not None:
                return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), return_sig.get_type(), return_sig))
        raise net_exceptions.OperationNotSupportedException()

    def __str__(self):
        return 'DotNetMethodInfo: {}:{} {} Name:{}'.format(self.internal_method.get_table_name(), self.internal_method.get_rid(), hex(self.internal_method.get_token()), self.internal_method.get_full_name())

cdef class DotNetMethodBase(DotNetMemberInfo):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_row_objects.MethodDefOrRef internal_method):
        DotNetMemberInfo.__init__(self, emulator_obj, internal_method)
        self.add_function(b'get_IsStatic', <emu_func_type>self.get_IsStatic)
        self.add_function(b'GetParameters', <emu_func_type>self.GetParameters)

    def __str__(self):
        return 'DotNetMethodObject: Token {} Name {}'.format(hex(self.internal_method.get_token()), self.internal_method.get_full_name())

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.MethodBase' or DotNetMemberInfo.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetMethodBase mbase = DotNetMethodBase(self.get_emulator_obj(), self.internal_method)
        DotNetMemberInfo.duplicate_into(self, mbase)
        return mbase

    cdef void duplicate_into(self, DotNetObject result):
        DotNetMemberInfo.duplicate_into(self, result)

    @staticmethod
    cdef net_emulator.StackCell GetMethodFromHandle(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetRuntimeMethodHandle method_handle = <DotNetRuntimeMethodHandle>params[0].item.ref
        return app_domain.get_emulator_obj().pack_object(DotNetMethodInfo(app_domain.get_emulator_obj(), method_handle.internal_method))

    cdef net_emulator.StackCell get_IsStatic(self, net_emulator.StackCell * params, int nparams):
        # TODO: does this work?
        cdef bint res = self.internal_method.method_has_this()
        return self.get_emulator_obj().pack_bool(res)

    cdef net_emulator.StackCell GetParameters(self, net_emulator.StackCell * params, int nparams):
        cdef list param_list = self.internal_method.get_param_types()
        cdef int x
        result = DotNetArray(self.get_emulator_obj(), len(param_list),
                             self.internal_method.get_dotnetpe().get_type_by_full_name(b'System.Reflection.ParameterInfo'))
        for x in range(len(param_list)):
            result._set_item(x, self.get_emulator_obj().pack_object(DotNetParameterInfo(self.get_emulator_obj(), param_list[x])))
        return result

    @staticmethod
    cdef net_emulator.StackCell op_Equality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT:
            raise net_exceptions.InvalidArgumentsException()
        return app_domain.get_emulator_obj().pack_bool(app_domain.get_emulator_obj().cell_is_equal(params[0], params[1]))

    @staticmethod
    cdef net_emulator.StackCell op_Inequality(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT:
            raise net_exceptions.InvalidArgumentsException()
        return app_domain.get_emulator_obj().pack_bool(app_domain.get_emulator_obj().cell_is_not_equal(params[0], params[1]))

cdef class DotNetParameterInfo(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, net_sigs.TypeSig internal_param):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_param = internal_param
        if self.internal_param is None:
            raise net_exceptions.EmulatorExecutionException(self.get_emulator_obj(), 'Invalid ParamInfo created')
        self.add_function(b'.ctor', <emu_func_type>self.ctor)
        self.add_function(b'get_ParameterType', <emu_func_type>self.get_ParameterType)
    
    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.ParameterInfo' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetParameterInfo pinfo = DotNetParameterInfo(self.get_emulator_obj(), self.internal_param)
        DotNetObject.duplicate_into(self, pinfo)
        return pinfo

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell get_ParameterType(self, net_emulator.StackCell * params, int nparams):
        cdef bytes type_name 
        if isinstance(self.internal_param, net_sigs.CorLibTypeSig):
            type_name = get_cor_type_name(self.internal_param.get_element_type())
            return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(type_name), self.internal_param))
        elif isinstance(self.internal_param, net_sigs.SZArraySig):
            return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Array'), self.internal_param)) #NOTE: this might not account for generics.
        elif isinstance(self.internal_param, net_sigs.ClassSig):
            return self.get_emulator_obj().pack_object(DotNetType(self.get_emulator_obj(), self.internal_param.get_type(), self.internal_param))
        raise net_exceptions.OperationNotSupportedException()

    def __str__(self):
        return 'ParameterObject: {} {}'.format(hex(self.internal_param.get_token()), self.internal_param.get_column('Name').get_value())

cdef class DotNetDelegate(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)
        self.add_function(b'Invoke', <emu_func_type>self.Invoke)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name().startswith(b'System.Delegate') or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetDelegate dele = DotNetDelegate(self.get_emulator_obj())
        dele.dn_type = self.dn_type
        dele.dn_methodinfo = self.dn_methodinfo
        DotNetObject.duplicate_into(self, dele)
        return dele

    cdef void duplicate_into(self, DotNetObject result):
        (<DotNetDelegate>result).dn_type = self.dn_type
        (<DotNetDelegate>result).dn_methodinfo = self.dn_methodinfo

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()

        if params[0].item.ref == NULL:
            self.dn_type = None
        else:
            self.dn_type = params[0].item.ref
        self.dn_methodinfo = params[1].item.ref
        return self.get_emulator_obj().pack_object(self)

    @staticmethod
    cdef net_emulator.StackCell CreateDelegate(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        raise Exception()
    
    #TODO: need to fix for new classes.
    cdef net_emulator.StackCell Invoke(self, net_emulator.StackCell * params, int nparams):
        if self.dn_type is not None: #For delegates, the first arg is the instance class.
            args.insert(0, self.dn_type)
        net_emulator.do_call(self.get_emulator_obj(), False, self.dn_methodinfo.internal_method.get_column('Name') == b'.ctor', self.dn_methodinfo.internal_method, None, args)
        if self.dn_methodinfo.internal_method.has_return_value():
            return self.get_emulator_obj().get_stack().pop()
        return self.get_emulator_obj().pack_blanktag()

    def __str__(self):
        """if isinstance(self.dn_methodinfo, DotNetDynamicMethod):
            return 'Delegate: DynamicMethod'
        else:"""
        return 'Delegate: {}'.format(self.dn_methodinfo.internal_method.get_full_name())

cdef class DotNetMulticastDelegate(DotNetDelegate):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetDelegate.__init__(self, emulator_obj)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.MulticastDelegate' or DotNetDelegate.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetMulticastDelegate dnm = DotNetMulticastDelegate(self.get_emulator_obj())
        DotNetDelegate.duplicate_into(self, dnm)
        return dnm

    cdef void duplicate_into(self, DotNetObject result):
        DotNetDelegate.duplicate_into(self, result)

cdef class DotNetConvert(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell ToInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_STRING or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetString string_obj = <DotNetString> params[0].item.ref
        cdef int result = int(param1.get_str_data_as_str())
        return app_domain.get_emulator_obj().pack_i4(result)

    @staticmethod
    cdef net_emulator.StackCell FromBase64String(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_STRING or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetString string = <DotNetString> params[0].item.ref
        cdef bytes str_data
        cdef bytes new_str_data
        cdef DotNetArray dnarray
        cdef list int_array
        cdef unsigned char uc = 0
        cdef DotNetUInt8 num = None
        str_data = string.get_str_data_as_bytes()
        new_str_data = base64.b64decode(bytes(str_data))
        dnarray = DotNetArray(app_domain.get_emulator_obj(), len(new_str_data), app_domain.get_executing_dotnetpe().get_type_by_full_name(
            b'System.Byte'), initialize=False)
        int_array = list()
        for x in range(len(new_str_data)):
            int_array._set_item(x, app_domain.get_emulator_obj().pack_u1(new_str_data[x]))
        return app_domain.get_emulator_obj().pack_object(dnarray)

    @staticmethod
    cdef net_emulator.StackCell ToChar(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or not net_utils.is_cortype_number(params[0]):
            raise net_Exceptions.InvalidArgumentsException()
        return app_domain.get_emulator_obj().pack_char(<unsigned short>params[0].item.u4)

    @staticmethod
    cdef net_emulator.StackCell ToString(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetObject obj1 = <DotNetObject>params[0].item.ref
        return obj1.ToString(NULL, 0)

"""
cdef class DotNetOpCode(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    #TODO fix ctor This has to be an internal ctor
    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        self.stringname = args[0]
        self.pop = args[1]
        self.push = args[2]
        self.operand = args[3]
        self.op_type = args[4]
        self.size = args[5]
        self.s1 = args[6]
        self.s2 = args[7]
        self.ctrl = args[8]
        self.endsjmpblk = args[9]
        self.stack = args[10]
        return self

    cpdef get_net_cil_equiv(self):
        return net_opcodes.OpcodeCollection.get_opcode_by_name(self.stringname)

    cpdef _get_opcode(self):
        if self.s1 == 255:
            return self.s2
        else:
            # TODO: add two byte opcode support
            raise net_exceptions.OperationNotSupportedException()

    def __str__(self):
        return self.stringname


cdef class DotNetOpCodes(DotNetObject):

    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
    #TODO Fix method instantiation
    @staticmethod
    cdef DotNetObject Nop(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "nop", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                        DotNetOpCodeType.Primitive, 1, 255, 0, DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Break(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "break", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                         DotNetOpCodeType.Primitive, 1, 255, 1, DotNetFlowControl.Break, False, 0)

    @staticmethod
    cdef DotNetObject Ldarg_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.0", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 2, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    cdef DotNetObject Ldarg_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 3, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    cdef DotNetObject Ldarg_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 4, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    cdef DotNetObject Ldarg_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 5, DotNetFlowControl.Next,
                           False, 1)
    @staticmethod
    cdef DotNetObject Ldloc_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.0", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 6, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    cdef DotNetObject Ldloc_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 7, DotNetFlowControl.Next,
                           False, 1)
    @staticmethod
    cdef DotNetObject Ldloc_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 8, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    cdef DotNetObject Ldloc_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 9, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    cdef DotNetObject Stloc_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.0", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xA, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    cdef DotNetObject Stloc_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xB, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    cdef DotNetObject Stloc_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xC, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    cdef DotNetObject Stloc_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.3", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xD, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    cdef DotNetObject Ldarg_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0xE,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldarga_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarga.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0xF,
                            DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Starg_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "starg.s", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x10,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Ldloc_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x11,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldloca_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloca.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x12,
                            DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Stloc_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.s", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x13,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Ldnull(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldnull", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushref,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x14,
                          DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_M1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.m1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x15, DotNetFlowControl.Next,
                             False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_0(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.0", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x16, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x17, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x18, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x19, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1A, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_5(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.5", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1B, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_6(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.6", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1C, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_7(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.7", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1D, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.8", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1E, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.ShortInlineI, DotNetOpCodeType.Macro, 1, 255, 0x1F,
                            DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineI,
                          DotNetOpCodeType.Primitive, 1, 255, 0x20, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldc_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i8", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi8, DotNetOperandType.InlineI8,
                          DotNetOpCodeType.Primitive, 1, 255, 0x21, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldc_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.r4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushr4,
                          DotNetOperandType.ShortInlineR, DotNetOpCodeType.Primitive, 1, 255, 0x22,
                          DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldc_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.r8", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushr8, DotNetOperandType.InlineR,
                          DotNetOpCodeType.Primitive, 1, 255, 0x23, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Dup(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "dup", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push1_push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x25, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Pop(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "pop", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x26, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Jmp(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "jmp", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineMethod,
                       DotNetOpCodeType.Primitive, 1, 255, 0x27, DotNetFlowControl.Call, True, 0)
    @staticmethod
    cdef DotNetObject Call(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "call", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Varpush,
                        DotNetOperandType.InlineMethod, DotNetOpCodeType.Primitive, 1, 255, 0x28,
                        DotNetFlowControl.Call, False, 0)
    @staticmethod
    cdef DotNetObject Calli(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "calli", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Varpush,
                         DotNetOperandType.InlineSig, DotNetOpCodeType.Primitive, 1, 255, 0x29, DotNetFlowControl.Call,
                         False, 0)
    @staticmethod
    cdef DotNetObject Ret(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ret", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x2A, DotNetFlowControl.Return, True, 0)
    @staticmethod
    cdef DotNetObject Br_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "br.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                        DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2B,
                        DotNetFlowControl.Branch, True, 0)
    @staticmethod
    cdef DotNetObject BrFalse_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brFalse.s", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2C,
                             DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    cdef DotNetObject BrTrue_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brTrue.s", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2D,
                            DotNetFlowControl.Cond_Branch, False, -1)

    @staticmethod
    cdef DotNetObject Beq_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "beq.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2E,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bge_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2F,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bgt_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x30,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Ble_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x31,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Blt_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x32,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bne_Un_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bne.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x33,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bge_Un_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x34,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bgt_Un_s(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x35,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Ble_Un_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x36,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Blt_Un_s(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x37,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Br(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "br", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineBrTarget,
                      DotNetOpCodeType.Primitive, 1, 255, 0x38, DotNetFlowControl.Branch, True, 0)
    @staticmethod
    cdef DotNetObject BrFalse(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brFalse", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0x39,
                           DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    cdef DotNetObject BrTrue(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brTrue", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0x3A,
                          DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    cdef DotNetObject Beq(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "beq", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3B,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bge(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3C,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bgt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3D,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Ble(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3E,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Blt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3F,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bne_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bne.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x40,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bge_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x41,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Bgt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x42,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Ble_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x43,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Blt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x44,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    cdef DotNetObject Switch(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "switch", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineSwitch, DotNetOpCodeType.Primitive, 1, 255, 0x45,
                          DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    cdef DotNetObject Ldind_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i1", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x46,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.u1", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x47,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i2", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x48,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.u2", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x49,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i4", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4A,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.u4", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4B,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i8", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi8,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4C,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                        DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4D,
                        DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.r4", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushr4,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4E,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.r8", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushr8,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4F,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldind_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.ref", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushref,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x50,
                            DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Stind_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.ref", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x51,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Stind_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i1", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x52,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Stind_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i2", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x53,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Stind_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i4", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x54,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Stind_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i8", DotNetStackBehaviour.Popi_popi8, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x55,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Stind_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.r4", DotNetStackBehaviour.Popi_popr4, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x56,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Add(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.r8", DotNetStackBehaviour.Popi_popr8, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x57,
                            DotNetFlowControl.Next, False, -2)

    @staticmethod
    cdef DotNetObject Stind_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "add", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x58, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Sub(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sub", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x59, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Mul(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mul", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5A, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Div(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "div", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5B, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Div_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "div.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x5C,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Rem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "rem", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5D, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Rem_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "rem.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x5E,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject And(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "and", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5F, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Or(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "or", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                      DotNetOpCodeType.Primitive, 1, 255, 0x60, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Xor(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "xor", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x61, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Shl(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "shl", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x62, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Shr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "shr", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x63, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Shr_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "shr.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x64,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Neg(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "neg", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x65, DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Not(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "not", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x66, DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x67,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x68,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x69,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6A,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.r4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr4,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6B,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.r8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr8,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6C,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6D,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_U8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6E,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Callvirt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "callvirt", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Varpush,
                            DotNetOperandType.InlineMethod, DotNetOpCodeType.Objmodel, 1, 255, 0x6F,
                            DotNetFlowControl.Call, False, 0)
    @staticmethod
    cdef DotNetObject Cpobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cpobj", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x70, DotNetFlowControl.Next,
                         False, -2)
    @staticmethod
    cdef DotNetObject Ldobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldobj", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push1, DotNetOperandType.InlineType,
                         DotNetOpCodeType.Objmodel, 1, 255, 0x71, DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Ldstr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldstr", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushref,
                         DotNetOperandType.InlineString, DotNetOpCodeType.Objmodel, 1, 255, 0x72,
                         DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Newobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "newobj", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Pushref,
                          DotNetOperandType.InlineMethod, DotNetOpCodeType.Objmodel, 1, 255, 0x73,
                          DotNetFlowControl.Call, False, 1)
    @staticmethod
    cdef DotNetObject Castclass(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "castclass", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushref,
                             DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x74,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject IsInst(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "isinst", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x75, DotNetFlowControl.Next,
                          False, 0)
    @staticmethod
    cdef DotNetObject Conv_R_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.r.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr8,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x76,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Unbox(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "unbox", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineType,
                         DotNetOpCodeType.Primitive, 1, 255, 0x79, DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Throw(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "throw", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                         DotNetOpCodeType.Objmodel, 1, 255, 0x7A, DotNetFlowControl.Throw, True, -1)
    @staticmethod
    cdef DotNetObject Ldfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldfld", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Push1,
                         DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7B, DotNetFlowControl.Next,
                         False, 0)
    @staticmethod
    cdef DotNetObject Ldflda(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldflda", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7C,
                          DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Stfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stfld", DotNetStackBehaviour.Popref_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7D, DotNetFlowControl.Next,
                         False, -2)
    @staticmethod
    cdef DotNetObject Ldsfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldsfld", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7E,
                          DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldsflda(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldsflda", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7F,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Stsfld(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stsfld", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x80,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Stobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stobj", DotNetStackBehaviour.Popi_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineType, DotNetOpCodeType.Primitive, 1, 255, 0x81, DotNetFlowControl.Next,
                         False, -2)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I1_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i1.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x82,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I2_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i2.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x83,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I4_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i4.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x84,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I8_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i8.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x85,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U1_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u1.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x86,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U2_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u2.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x87,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U4_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u4.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x88,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U8_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u8.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x89,
                                  DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_I_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                 DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x8A,
                                 DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Conv_Ovf_U_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                 DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x8B,
                                 DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Box(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "box", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushref, DotNetOperandType.InlineType,
                       DotNetOpCodeType.Primitive, 1, 255, 0x8C, DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Newarr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "newarr", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushref,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x8D, DotNetFlowControl.Next,
                          False, 0)

    @staticmethod
    cdef DotNetObject Ldlen(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldlen", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                         DotNetOpCodeType.Objmodel, 1, 255, 0x8E, DotNetFlowControl.Next, False, 0)

    @staticmethod
    cdef DotNetObject Ldelema(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelema", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x8F,
                           DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i1", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x90,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.u1", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x91,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i2", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x92,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.u2", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x93,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i4", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x94,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.u4", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x95,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i8", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi8,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x96,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x97,
                            DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.r4", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushr4,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x98,
                             DotNetFlowControl.Next, False, -1)

    @staticmethod
    cdef DotNetObject Ldelem_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.r8", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushr8,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x99,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Ldelem_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.ref", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushref,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9A,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Stelem_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9B,
                            DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i1", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9C,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i2", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9D,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i4", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9E,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i8", DotNetStackBehaviour.Popref_popi_popi8, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9F,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_R4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.r4", DotNetStackBehaviour.Popref_popi_popr4, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0xA0,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_R8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.r8", DotNetStackBehaviour.Popref_popi_popr8, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0xA1,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Stelem_Ref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.ref", DotNetStackBehaviour.Popref_popi_popref, DotNetStackBehaviour.Push0,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0xA2,
                              DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Ldelem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0xA3, DotNetFlowControl.Next,
                          False, -1)
    @staticmethod
    cdef DotNetObject Stelem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem", DotNetStackBehaviour.Popref_popi_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0xA4, DotNetFlowControl.Next,
                          False, 0)
    @staticmethod
    cdef DotNetObject Unbox_Any(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "unbox.any", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Push1,
                             DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0xA5,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_I1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB3,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB4,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_I2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB5,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB6,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_I4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB7,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_U4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB8,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_I8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB9,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_U8(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xBA,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Refanyval(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "refanyval", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineType, DotNetOpCodeType.Primitive, 1, 255, 0xC2,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Ckfinite(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ckfinite", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr8,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xC3,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Mkrefany(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mkrefany", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push1,
                            DotNetOperandType.InlineType, DotNetOpCodeType.Primitive, 1, 255, 0xC6,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Ldtoken(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldtoken", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineTok, DotNetOpCodeType.Primitive, 1, 255, 0xD0,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Conv_U2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD1,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_U1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD2,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                          DotNetOpCodeType.Primitive, 1, 255, 0xD3, DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD4,
                              DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Conv_Ovf_U(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD5,
                              DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Add_Ovf(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "add.ovf", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD6,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Add_Ovf_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "add.ovf.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD7,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Mul_Ovf(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mul.ovf", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD8,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Mul_Ovf_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mul.ovf.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD9,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Sub_Ovf(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sub.ovf", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDA,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Sub_Ovf_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sub.ovf.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDB,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Endfinally(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "endfinally", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDC,
                              DotNetFlowControl.Return, True, 0)
    @staticmethod
    cdef DotNetObject Leave(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "leave", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0xDD,
                         DotNetFlowControl.Branch, True, 0)
    @staticmethod
    cdef DotNetObject Leave_S(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "leave.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0xDE,
                           DotNetFlowControl.Branch, True, 0)
    @staticmethod
    cdef DotNetObject Stind_I(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDF,
                           DotNetFlowControl.Next, False, -2)
    @staticmethod
    cdef DotNetObject Conv_U(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                          DotNetOpCodeType.Primitive, 1, 255, 0xE0, DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Prefix7(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix7", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xF8, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefix6(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix6", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xF9, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefix5(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix5", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFA, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefix4(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFB, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefix3(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFC, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefix2(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFD, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefix1(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFE, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    cdef DotNetObject Prefixref(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefixref", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 255,
                             DotNetFlowControl.Meta, False, 0)
    @staticmethod
    cdef DotNetObject Arglist(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "arglist", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0, DotNetFlowControl.Next,
                           False, 1)
    @staticmethod
    cdef DotNetObject Ceq(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ceq", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 2, 0xFE, 1, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Cgt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cgt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 2, 0xFE, 2, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Cgt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cgt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 3, DotNetFlowControl.Next,
                          False, -1)
    @staticmethod
    cdef DotNetObject Clt(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "clt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 2, 0xFE, 4, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Clt_Un(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "clt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 5, DotNetFlowControl.Next,
                          False, -1)
    @staticmethod
    cdef DotNetObject Ldftn(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldftn", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineMethod,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 6, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldvirtftn(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldvirtftn", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineMethod, DotNetOpCodeType.Primitive, 2, 0xFE, 7,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Ldarg(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 9, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldarga(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarga", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineVar,
                          DotNetOpCodeType.Primitive, 2, 0xFE, 0xA, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Starg(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "starg", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 0xB, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Ldloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 0xC, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Ldloca(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloca", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineVar,
                          DotNetOpCodeType.Primitive, 2, 0xFE, 0xD, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Stloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 0xE, DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Localloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "localloc", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0xF,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Endfilter(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "endfilter", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x11,
                             DotNetFlowControl.Return, True, -1)
    @staticmethod
    cdef DotNetObject Unaligned(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "unaligned.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                             DotNetOperandType.ShortInlineI, DotNetOpCodeType.Prefix, 2, 0xFE, 0x12,
                             DotNetFlowControl.Meta, False, 0)
    @staticmethod
    cdef DotNetObject Volatile(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "volatile.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Prefix, 2, 0xFE, 0x13,
                            DotNetFlowControl.Meta, False, 0)
    @staticmethod
    cdef DotNetObject Tailcall(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "tail.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Prefix, 2, 0xFE, 0x14,
                            DotNetFlowControl.Meta, False, 0)
    @staticmethod
    cdef DotNetObject Initobj(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "initobj", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 2, 0xFE, 0x15,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    cdef DotNetObject Constrained(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "constrained.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                               DotNetOperandType.InlineType, DotNetOpCodeType.Prefix, 2, 0xFE, 0x16,
                               DotNetFlowControl.Meta, False, 0)
    @staticmethod
    cdef DotNetObject Cpblk(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cpblk", DotNetStackBehaviour.Popi_popi_popi, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x17,
                         DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Initblk(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "initblk", DotNetStackBehaviour.Popi_popi_popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x18,
                           DotNetFlowControl.Next, False, -3)
    @staticmethod
    cdef DotNetObject Rethrow(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "rethrow", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 2, 0xFE, 0x1A,
                           DotNetFlowControl.Throw, True, 0)
    @staticmethod
    cdef DotNetObject Sizeof(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sizeof", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineType,
                          DotNetOpCodeType.Primitive, 2, 0xFE, 0x1C, DotNetFlowControl.Next, False, 1)
    @staticmethod
    cdef DotNetObject Refanytype(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "refanytype", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x1D,
                              DotNetFlowControl.Next, False, 0)
    @staticmethod
    cdef DotNetObject Readonly(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return DotNetOpCode(app_domain.get_emulator_obj(), "readonly.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Prefix, 2, 0xFE, 0x1E,
                            DotNetFlowControl.Meta, False, 0)

    @staticmethod
    cdef DotNetObject TakesSingleByteArgument(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetOpCode opcode = <DotNetOpCode>args[1]
        cdef DotNetBoolean bool_obj = DotNetBoolean(app_domain.get_emulator_obj(), None)
        cdef bint result = False
        if opcode.operand == DotNetOperandType.ShortInlineBrTarget:
            result = True
        elif opcode.operand == DotNetOperandType.ShortInlineI:
            result = True
        elif opcode.operand == DotNetOperandType.ShortInlineVar:
            result = True
        bool_obj.from_bool(result)
        return bool_obj

cdef class DotNetILGenerator(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.method_body = bytes()
        self.add_function(b'Emit', <emu_func_type>self.Emit)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Reflection.Emit.ILGenerator' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetILGenerator gen = DotNetILGenerator(self.get_emulator_obj())
        gen.method_body = self.method_body
        DotNetObject.duplicate_into(self, gen)
        return gen

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef __internal_emit_noargs(self, DotNetOpCode opcode):
        if opcode.size == 1:
            self.method_body += bytes([opcode.s2])
        else:
            self.method_body += bytes([opcode.s1, opcode.s2])

    cdef __internal_emit_call(self, DotNetOpCode opcode, DotNetMethodInfo method_obj):
        cdef net_row_objects.MethodDefOrRef internal_obj
        if isinstance(method_obj, DotNetMethodInfo):
            internal_obj = method_obj.internal_method
            if isinstance(internal_obj, net_row_objects.MemberRef):
                instr_bytes = bytes([opcode.s2])
                instr_bytes += int.to_bytes(internal_obj.get_rid(), 3, 'little')
                instr_bytes += bytes([0xA])
                self.method_body += instr_bytes
            else:
                raise net_exceptions.OperationNotSupportedException()
        else:
            raise net_exceptions.OperationNotSupportedException()

    #TODO: can this be optimized?
    cdef DotNetObject Emit(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetOpCode opcode = args[0]
        cdef list other_stuff
        if len(args) > 1:
            other_stuff = args[1:]
        else:
            other_stuff = []

        if not isinstance(opcode, DotNetOpCode):
            raise net_exceptions.ObjectTypeException

        if opcode == DotNetOpCodes.Ldarg_0:
            self.__internal_emit_noargs(opcode)
        elif opcode == DotNetOpCodes.Ldarg_1:
            self.__internal_emit_noargs(opcode)
        elif opcode == DotNetOpCodes.Ldarg_2:
            self.__internal_emit_noargs(opcode)
        elif opcode == DotNetOpCodes.Ldarg_3:
            self.__internal_emit_noargs(opcode)
        elif opcode == DotNetOpCodes.Ldarg_S:
            self.__internal_emit_noargs(opcode)
        elif opcode == DotNetOpCodes.Tailcall:
            self.__internal_emit_noargs(opcode)
        elif opcode == DotNetOpCodes.Callvirt:
            self.__internal_emit_call(opcode, other_stuff[0])
        elif opcode == DotNetOpCodes.Call:
            self.__internal_emit_call(opcode, other_stuff[0])
        elif opcode == DotNetOpCodes.Ret:
            self.__internal_emit_noargs(opcode)
        else:
            raise net_exceptions.OperationNotSupportedException()


#FIXME: This needs to extend MethodDefOrRef
cdef class DotNetDynamicMethod(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)
    
    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams):
        self.name = args[0]
        self.return_type = args[1]
        self.parameter_types = args[2]
        self.parent_type = args[3]
        self.skip_visibility = args[4]
        self.il_generar = DotNetILGenerator(self.get_emulator_obj())
        self.sig_obj = None
        self.static = True

    def disassemble_method(self, no_save=False):
        return net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self)

    cpdef get_dotnetpe(self):
        return self.get_emulator_obj().get_appdomain().get_executing_dotnetpe()

    def GetILGenerator(self):
        return self.il_generator

    def CreateDelegate(self, owner):
        return DotNetDelegate.CreateDelegate(owner, self)

    cpdef get_method_data(self):
        if not len(self.il_generator.method_body) < 0xFF:
            raise net_exceptions.MethodTooLargeException

        # NOTE: This currently only supports writing tiny headers for basic methods.
        code_size = len(self.il_generator.method_body)
        header_byte = (code_size << 2 | 2) & 0xFF
        return bytes([header_byte]) + self.il_generator.method_body

    cpdef get_method_signature(self):
        if self.sig_obj:
            return self.sig_obj

        typedef_obj = self.return_type.get_type_handle()

        return_sig = get_cor_type_from_name(typedef_obj.get_full_name())
        if not return_sig:
            return_sig = net_sigs.TypeDefOrRefSig(None, typedef_obj)
        param_sigs = list()
        for param in self.parameter_types:
            ptype_obj = param.get_type_handle()
            param_sig = get_cor_type_from_name(ptype_obj.get_full_name())
            if not param_sig:
                param_sig = net_sigs.TypeDefOrRefSig(None, ptype_obj)
            param_sigs.append(param_sig)
        self.sig_obj = net_sigs.MethodSig(net_structs.CallingConvention_Default, bytes(), None, param_sigs, 0, 0, 0,
                                           return_sig)
        return self.sig_obj

    cpdef method_has_this(self):
        return False

    cpdef is_static(self):
        return self.static

    cpdef has_return_value(self):
        type_obj = self.return_type.get_type_handle()
        return type_obj.get_full_name() != b'System.Void'
"""

cdef class DotNetSortedList(DotNetList):
    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.Collections.SortedList' or DotNetList.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetSortedList result = DotNetSortedList(self.get_emulator_obj())
        DotNetList.duplicate_into(self, result)
        return result

    cdef void duplicate_into(self, DotNetObject result):
        pass

"""
cdef class DotNetHashTable(DotNetConcurrentDictionary):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetConcurrentDictionary.__init__(self, emulator_obj)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        pass 

    cdef DotNetObject duplicate(self)

    cdef void duplicate_into(self, DotNetObject result):
        pass

"""

cdef class DotNetRSACryptoServiceProvider(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell set_UseMachineKeyStore(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_blanktag() #I dont think this needs to do anything.

cdef class DotNetBinaryReader(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'get_BaseStream', <emu_func_type>self.get_BaseStream)
        self.add_function(b'ReadBytes', <emu_func_type>self.ReadBytes)
        self.add_function(b'ReadByte', <emu_func_type>self.ReadByte)
        self.add_function(b'Close', <emu_func_type>self.Close)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.IO.BinaryReader' or DotNetObject.isinst(self, tdef)

    cdef DotNetObject duplicate(self):
        cdef DotNetBinaryReader reader = DotNetBinaryReader(self.get_emulator_obj())
        reader.stream = self.stream
        DotNetObject.duplicate_into(self, reader)
        return reader

    cdef void duplicate_into(self, DotNetObject result):
        pass
    
    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        self.stream = params[0].item.ref
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell get_BaseStream(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(self.stream)

    cdef net_emulator.StackCell ReadBytes(self, net_emulator.StackCell * params, int nparams):
        return self.stream.ReadBytes(args)

    cdef net_emulator.StackCell ReadByte(self, net_emulator.StackCell * params, int nparams):
        return self.stream.ReadByte(args)

    cdef net_emulator.StackCell Close(self, net_emulator.StackCell * params, int nparams):
        self.stream.Close(args)
        return self.get_emulator_obj().pack_blanktag()

"""

#TODO: actually implement these functions if needed.
cdef class DotNetMarshal(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell ReadIntPtr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetObject intptr = <DotNetObject> args[0]
        if isinstance(intptr, DotNetIntPtr):
            return intptr
        raise Exception()

    @staticmethod
    cdef net_emulator.StackCell ReadInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetObject intptr = <DotNetObject>args[0]
        cdef DotNetInt32 offset = None
        cdef DotNetInt32 result = DotNetInt32(app_domain.get_emulator_obj(), None)
        if len(args) == 3:
            offset = args[2]
        if isinstance(intptr, DotNetIntPtr) and offset is not None:
            if offset.val_is_zero():
                result.init_zero()
                return result
        raise Exception()

    @staticmethod
    cdef net_emulator.StackCell ReadInt64(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetObject intptr = <DotNetObject>args[0]
        cdef DotNetInt32 offset = None
        cdef DotNetInt64 result = DotNetInt64(app_domain.get_emulator_obj(), None)
        if len(args) == 3:
            offset = args[2]
        if isinstance(intptr, DotNetIntPtr) and offset is not None:
            if offset.val_is_zero():
                result.init_zero()
                return result
        raise Exception()

    @staticmethod
    cdef net_emulator.StackCell WriteIntPtr(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return None

    @staticmethod
    cdef net_emulator.StackCell WriteInt32(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return None

    @staticmethod
    cdef net_emulator.StackCell WriteInt64(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return None


cdef class DotNetWaitCallback(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, _object, method_object):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)
    
    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams):
        self.__object = args[0]
        self.__method_object = args[1]
        return self

cdef class DotNetFunc(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'Invoke', <emu_func_type>self.Invoke)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef DotNetObject ctor(self, net_emulator.StackCell * params, int nparams):
        self.__object = args[0]
        self.__method_object = args[1]
        return self

    #TODO: UPDATE THIS METHOD IT WONT WORK
    #TODO: for DotNetDynamicMethod, going to need to find a way to make it extend MethodDef otherwise it wont work with the cython typiing.
    cdef DotNetObject Invoke(self, net_emulator.StackCell * params, int nparams):
        raise Exception()

cdef class DotNetThreadPool(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef DotNetObject QueueUserWorkItem(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetBoolean result = DotNetBoolean(app_domain.get_emulator_obj(), None)
        cdef bint val = True
        result.init_from_ptr(<unsigned char *>&val, sizeof(val))
        return result

"""
#TODO needs to be reworked a bit.
cdef class DotNetThreadStart(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)
    
    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        self.__object = args[0]
        self.__method_object = args[1]
        return self

    cpdef get_method_object(self):
        return self.__method_object

"""
cdef class DotNetDebugger(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell get_IsAttached(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_bool(False)


"""

cdef class DotNetComparison(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.__object = None
        self.__method_object = None
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[1].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        if params[0].item.ref != NULL:
            self.__object = params[0].item.ref
        else:
            self.__object = None
        self.__method_object = params[1].item.ref
        return self

    cpdef net_row_objects.MethodDef get_method_object(self):
        return self.__method_object.internal_method

cdef class DotNetGC(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self)

    @staticmethod
    cdef net_emulator.StackCell Collect(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_blanktag()

cdef class DotNetPath(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell GetTempPath(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_string(DotNetString(app_domain.get_emulator_obj(), '%Temp%'.encode('utf-16le')))

    @staticmethod
    cdef net_emulator.StackCell Combine(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 2 or params[0].tag != CorElementType.ELEMENT_TYPE_STRING or params[1].tag != CorElementType.ELEMENT_TYPE_STRING or params[0].item.ref == NULL or params[1].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        cdef DotNetString path_one = <DotNetString>params[0].item.ref
        cdef DotNetString path_two = <DotNetString>params[1].item.ref
        cdef str str_one
        cdef str str_two
        cdef str combined
        str_one = path_one.get_str_data_as_str()
        str_two = path_two.get_str_data_as_str()

        #for now assume windows
        combined = ntpath.join(str_one, str_two)
        return app_domain.get_emulator_obj().pack_string(DotNetString(app_domain.get_emulator_obj(), combined.encode('utf-16le')))

cdef class DotNetEnvironment(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
    
    @staticmethod
    cdef net_emulator.StackCell GetFolderPath(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_I4:
            raise net_exceptions.InvalidArgumentsException()
        cdef int folder_enum = params[0].item.i4
        if folder_enum == 28:
            return app_domain.get_emulator_obj().pack_string(DotNetString(app_domain.get_emulator_obj(), '%LocalAppData%'.encode('utf-16le')))
        raise net_exceptions.OperationNotSupportedException()

    @staticmethod
    cdef net_emulator.StackCell get_Version(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_object(DotNetVersion(app_domain.get_emulator_obj()))


cdef class DotNetResolveEventArgs(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.__name = None
        self.add_function(b'get_Name', <emu_func_type>self.get_Name)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams != 1 or params[0].tag != CorElementType.ELEMENT_TYPE_STRING or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        self.__name = params[0].item.ref
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell get_Name(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_string(self.__name)

"""

cdef class DotNetDeflateStream(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'Read', <emu_func_type>self.Read)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetStream original_stream = args[0]
        cdef DotNetInt32 mode = args[1]
        decom = zlib.decompressobj(-15)
        self.decompressed_buffer = decom.decompress(original_stream.get_rsrc_stream().read())
        self.position = 0
        self.__decompress = mode.val_is_zero()
        return self

    cdef net_emulator.StackCell Read(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray buffer = <DotNetArray>args[0]
        cdef DotNetInt32 offset = None
        cdef DotNetInt32 count = None
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        cdef int amt_written
        cdef int x
        cdef DotNetUInt8 num = None
        cdef unsigned char uc = 0
        if len(args) == 3:
            offset = <DotNetInt32>args[1]
            count = <DotNetInt32>args[2]
        else:
            offset = DotNetInt32(self.get_emulator_obj(), None)
            offset.init_zero()
            count = buffer.Count([])
        amt_written = 0
        for x in range(count.as_int()):
            if (self.position + x) >= len(self.decompressed_buffer):
                break
            amt_written += 1
            uc = self.decompressed_buffer[x + self.position]
            num = DotNetUInt8(self.get_emulator_obj(), None)
            num.init_from_ptr(&uc, sizeof(uc))
            buffer[offset.as_int() + x] = num

        self.position += amt_written
        result.init_from_ptr(<unsigned char *>&amt_written, sizeof(amt_written))
        return result
"""
#TODO: need some work on these classes in relation to stackcell changes
cdef class DotNetSymmetricAlgorithm(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.__key = None
        self.__iv = None
        self.add_function(b'get_Key', <emu_func_type>self.get_Key)
        self.add_function(b'set_Key', <emu_func_type>self.set_Key)
        self.add_function(b'set_IV', <emu_func_type>self.set_IV)
        self.add_function(b'get_IV', <emu_func_type>self.get_IV)
        self.add_function(b'get_Padding', <emu_func_type>self.get_Padding)
        self.add_function(b'set_Padding', <emu_func_type>self.set_Padding)
        self.add_function(b'get_Mode', <emu_func_type>self.get_Mode)
        self.add_function(b'set_Mode', <emu_func_type>self.set_Mode)

    cdef net_emulator.StackCell get_Key(self, net_emulator.StackCell * params, int nparams):
        return self.__key

    cdef net_emulator.StackCell set_Key(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray key = <DotNetArray>args[0]
        self.__key = key
        return None

    cdef net_emulator.StackCell get_IV(self, net_emulator.StackCell * params, int nparams):
        return self.__iv

    cdef net_emulator.StackCell set_IV(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray iv = <DotNetArray>args[0]
        self.__iv = iv
        return None

    cdef net_emulator.StackCell get_Padding(self, net_emulator.StackCell * params, int nparams):
        return self.__padding

    cdef net_emulator.StackCell set_Padding(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 padding = <DotNetInt32>args[0]
        self.__padding = padding
        return None

    cdef net_emulator.StackCell get_Mode(self, net_emulator.StackCell * params, int nparams):
        return self.__mode

    cdef net_emulator.StackCell set_Mode(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 mode = <DotNetInt32>args[0]
        self.__mode = mode
        return None

cdef class DotNetICryptoTransform(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

"""

cdef class DotNetDESDecryptor(DotNetICryptoTransform):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetICryptoTransform.__init__(self, emulator_obj)
        self.add_function(b'get_InputBlockSize', <emu_func_type>self.get_InputBlockSize)
        self.add_function(b'get_OutputBlockSize', <emu_func_type>self.get_OutputBlockSize)
        self.add_function(b'TransformFinalBlock', <emu_func_type>self.TransformFinalBlock)
        self.add_function(b'TransformBlock', <emu_func_type>self.TransformBlock)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        self.provider = args[0]
        self.des_object = DES.new(bytes(self.provider.get_Key([]).get_internal_array()), DES.MODE_CBC, bytes(self.provider.get_IV([]).get_internal_array()))
        return self

    cdef net_emulator.StackCell get_InputBlockSize(self, net_emulator.StackCell * params, int nparams):
        cdef int res = 8
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        result.from_int(res)
        return result

    cdef net_emulator.StackCell get_OutputBlockSize(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        cdef int res = 8
        result.from_int(res)
        return result

    cdef net_emulator.StackCell TransformBlock(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray inputBuffer = <DotNetArray>args[0]
        cdef DotNetInt32 inputOffset = <DotNetInt32>args[1]
        cdef DotNetInt32 inputCount = <DotNetInt32>args[2]
        cdef DotNetArray outputBuffer = <DotNetArray>args[3]
        cdef DotNetInt32 outputOffset = <DotNetInt32>args[4]
        cdef bytearray input_data = bytearray([0] * inputCount)
        cdef int x
        cdef bytes output_data
        cdef DotNetUInt8 num = None
        cdef unsigned char uc = 0
        for x in range(inputCount.as_int()):
            input_data[x] = inputBuffer[inputOffset.as_int() + x].as_uchar()
        
        output_data = self.des_object.decrypt(input_data)
        for x in range(inputCount.as_int()):
            uc = output_data[x]
            num = DotNetUInt8(self.get_emulator_obj(), None)
            num.from_uchar(uc)
            outputBuffer[x + outputOffset] = num

        return inputCount.duplicate()

    cdef net_emulator.StackCell TransformFinalBlock(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray inputBuffer = <DotNetArray>args[0]
        cdef DotNetInt32 inputOffset = <DotNetInt32>args[1]
        cdef DotNetInt32 inputCount = <DotNetInt32>args[2]
        cdef bytearray input_data = bytearray([0] * inputCount)
        cdef int x
        cdef bytes output_data
        cdef list usable_output
        cdef DotNetArray array
        cdef DotNetUInt8 num = None
        for x in range(inputCount.as_int()):
            input_data[x] = inputBuffer[x + inputOffset.as_int()].as_uchar()

        output_data = self.des_object.decrypt(input_data)
        usable_output = list()
        for x in range(<int>len(output_data)):
            num = DotNetUInt8(self.get_emulator_obj(), None)
            num.from_uchar(output_data[x])
            usable_output.append(num)
        array = DotNetArray(self.get_emulator_obj(), len(usable_output), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                    initialize=False)
        array.set_internal_array(usable_output)

        return array

cdef class DotNetDESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetSymmetricAlgorithm.__init__(self, emulator_obj)
        self.add_function(b'CreateDecryptor', <emu_func_type>self.CreateDecryptor)

    cdef net_emulator.StackCell CreateDecryptor(self, net_emulator.StackCell * params, int nparams):
        return DotNetDESDecryptor(self.get_emulator_obj(), self)
"""

cdef class DotNetApplication(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    cdef net_emulator.StackCell get_ProductVersion(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        return app_domain.get_emulator_obj().pack_string(DotNetString(app_domain.get_emulator_obj(), app_domain.get_executing_dotnetpe().get_product_version().encode('utf-16le')))

cdef class DotNetHashAlgorithm(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'Clear', <emu_func_type>self.Clear)
    
    cdef net_emulator.StackCell Clear(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_blanktag()

cdef class DotNetMD5CryptoServiceProvider(DotNetHashAlgorithm):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetHashAlgorithm.__init__(self, emulator_obj)
        self.add_function(b'ComputeHash', <emu_func_type>self.ComputeHash)

    cdef net_emulator.StackCell ComputeHash(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray data = <DotNetArray>args[0]
        cdef bytes internal_data = data.as_bytes()
        cdef object md5_obj = hashlib.md5()
        cdef bytes resulting_data = None
        cdef DotNetUInt8 num = None
        cdef int count
        cdef DotNetArray arr_obj
        cdef list usable_data
        cdef int x
        md5_obj.update(internal_data)
        resulting_data = md5_obj.digest()
        count = <int>len(resulting_data)

        arr_obj = DotNetArray(self.get_emulator_obj(), count, self.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(
            b'System.Byte'), initialize=False)
        usable_data = list()
        for x in range(count):
            num = DotNetUInt8(self.get_emulator_obj(), None)
            num.from_uchar(resulting_data[x])
            usable_data.append(num)

        arr_obj.set_internal_array(usable_data)
        return arr_obj
    
cdef class DotNet3DESDecryptor(DotNetICryptoTransform):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj, DotNet3DESCryptoServiceProvider provider):
        DotNetICryptoTransform.__init__(self, emulator_obj)
        self.provider = provider
        self.des_object = None

        self.add_function(b'get_InputBlocksize', <emu_func_type>self.get_InputBlockSize)
        self.add_function(b'get_OutputBlockSize', <emu_func_type>self.get_OutputBlockSize)
        self.add_function(b'TransformBlock', <emu_func_type>self.TransformBlock)
        self.add_function(b'TransformFinalBlock', <emu_func_type>self.TransformFinalBlock)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray key_val = None
        cdef DotNetInt32 mode_val = None
        self.provider = args[0]
        key_val = <DotNetArray>self.provider.get_Key([])
        mode = DES.MODE_CBC
        mode_val = self.provider.get_Mode([])
        if mode_val.as_int() == 2:
            mode = DES.MODE_ECB
        self.des_object = DES3.new(key_val.as_bytes(), mode)
        return self

    cdef net_emulator.StackCell get_InputBlockSize(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        result.from_int(8)
        return result

    cdef net_emulator.StackCell get_OutputBlockSize(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetInt32 result = DotNetInt32(self.get_emulator_obj(), None)
        result.from_int(8)
        return result

    cdef net_emulator.StackCell TransformBlock(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray inputBuffer = <DotNetArray>args[0]
        cdef DotNetInt32 inputOffset = <DotNetInt32> args[1]
        cdef DotNetInt32 inputCount = <DotNetInt32>args[2]
        cdef DotNetArray outputBuffer = <DotNetArray> args[3]
        cdef DotNetInt32 outputOffset = <DotNetInt32>args[4]
        cdef int x
        cdef bytearray input_data = bytearray([0] * inputCount.as_int())
        cdef bytes output_data
        cdef DotNetUInt8 num = None
        cdef DotNetArray key_val = None
        cdef DotNetInt32 mode_val = None
        for x in range(inputCount.as_int()):
            input_data[x] = inputBuffer[inputOffset.as_int() + x]
        if self.des_object is None:
            mode = DES.MODE_CBC
            mode_val = self.provider.get_Mode([])
            if mode_val.as_int() == 2:
                mode = DES.MODE_ECB
            key_val = <DotNetArray>self.provider.get_Key([])
            self.des_object = DES3.new(key_val.as_bytes(), mode)
        output_data = self.des_object.decrypt(input_data)
        for x in range(inputCount.as_int()):
            num = DotNetUInt8(self.get_emulator_obj(), None)
            num.from_uchar(output_data[x])
            outputBuffer[x + outputOffset.as_int()] = num

        return inputCount.duplicate()

    cdef net_emulator.StackCell TransformFinalBlock(self, net_emulator.StackCell * params, int nparams):
        cdef DotNetArray inputBuffer = <DotNetArray>args[0]
        cdef DotNetInt32 inputOffset = <DotNetInt32>args[1]
        cdef DotNetInt32 inputCount = <DotNetInt32>args[2]
        cdef bytearray input_data = bytearray([0] * inputCount.as_int())
        cdef int x
        cdef bytes output_data
        cdef list usable_output
        cdef unsigned char potential_padding
        cdef DotNetArray array
        cdef DotNetUInt8 num = None
        cdef int start_index
        cdef bint is_padded
        cdef int index
        cdef DotNetNumber current
        cdef DotNetInt32 mode_val = None
        cdef DotNetArray key_val = None
        cdef DotNetInt32 padding_val = None
        for x in range(inputCount.as_int()):
            current = <DotNetNumber>inputBuffer[x + inputOffset.as_int()]
            input_data[x] = current.as_uchar()
        if self.des_object is None:
            mode = DES.MODE_CBC
            mode_val = self.provider.get_Mode([])
            if mode_val.as_int() == 2:
                mode = DES.MODE_ECB
            key_val = <DotNetArray>self.provider.get_Key([])
            self.des_object = DES3.new(key_val.as_bytes(), mode)
        output_data = self.des_object.decrypt(input_data)
        padding_val = self.provider.get_Padding([])
        if padding_val.as_int() == 2:
            output_data = unpad(output_data, DES3.block_size)
        usable_output = list()
        for x in range(<int>len(output_data)):
            num = DotNetUInt8(self.get_emulator_obj(), None)
            num.from_uchar(output_data[x])
            usable_output.append(num)
        array = DotNetArray(self.get_emulator_obj(), len(usable_output), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                    initialize=False)
        array.set_internal_array(usable_output)

        return array

cdef class DotNet3DESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetSymmetricAlgorithm.__init__(self, emulator_obj)
        self.add_function(b'CreateDecryptor', <emu_func_type>self.CreateDecryptor)
        self.add_function(b'Clear', <emu_func_type>self.Clear)

    cdef net_emulator.StackCell CreateDecryptor(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(DotNet3DESDecryptor(self.get_emulator_obj(), self))

    cdef net_emulator.StackCell Clear(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_blanktag()

cdef class DotNetGCHandle(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.add_function(b'get_Target', <emu_func_type>self.get_Target)
        self.add_function(b'.ctor', <emu_func_type>self.ctor)

    cdef bint isinst(self, net_row_objects.TypeDefOrRef tdef):
        return tdef.get_full_name() == b'System.GCHandle'

    cdef DotNetObject duplicate(self):
        cdef DotNetGCHandle gcHandle = DotNetGCHandle(self.get_emulator_obj())
        gcHandle.__type = self.__type
        gcHandle.__target = self.__target
        return gcHandle

    cdef void duplicate_into(self, DotNetObject result):
        pass

    cdef net_emulator.StackCell ctor(self, net_emulator.StackCell * params, int nparams):
        if nparams == 0 or params[0].tag != CorElementType.ELEMENT_TYPE_OBJECT or params[0].item.ref == NULL:
            raise net_exceptions.InvalidArgumentsException()
        self.__target = <DotNetObject>params[0].item.ref
        if nparams == 2:
            if params[1].tag != CorElementType.ELEMENT_TYPE_I4:
                raise net_exceptions.InvalidArgumentsException()
            self.__type = params[1].item.i4
        else:
            self.__type = 0
        return self.get_emulator_obj().pack_object(self)

    cdef net_emulator.StackCell get_Target(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_object(self.__target)

    @staticmethod
    cdef net_emulator.StackCell Alloc(net_emulator.EmulatorAppDomain app_domain, net_emulator.StackCell * params, int nparams):
        cdef DotNetGCHandle gcHandle = DotNetGCHandle(app_domain.get_emulator_obj())
        gcHandle.ctor(params, nparams)
        return app_domain.get_emulator_obj().pack_object(gcHandle)

cdef class DotNetVersion(DotNetObject):
    def __init__(self, net_emulator.DotNetEmulator emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.__major_version = 3
        self.add_function(b'get_Major', <emu_func_type>self.get_Major)

    cdef net_emulator.StackCell get_Major(self, net_emulator.StackCell * params, int nparams):
        return self.get_emulator_obj().pack_i4(self.__major_version)

cdef DotNetObject New_ConcurrentDictionary(net_emulator.DotNetEmulator emulator_obj):
    return DotNetConcurrentDictionary(emulator_obj)

cdef DotNetObject New_Dictionary(net_emulator.DotNetEmulator emulator_obj):
    return DotNetDictionary(emulator_obj)

cdef DotNetObject New_SortedList(net_emulator.DotNetEmulator emulator_obj):
    return DotNetSortedList(emulator_obj)

cdef DotNetObject New_String(net_emulator.DotNetEmulator emulator_obj):
    return DotNetString(emulator_obj, None, 'utf-16le')

cdef DotNetObject New_StringBuilder(net_emulator.DotNetEmulator emulator_obj):
    return DotNetStringBuilder(emulator_obj)

cdef DotNetObject New_List(net_emulator.DotNetEmulator emulator_obj):
    return DotNetList(emulator_obj)

cdef DotNetObject New_StackTrace(net_emulator.DotNetEmulator emulator_obj):
    return DotNetStackTrace(emulator_obj)

cdef DotNetObject New_Stream(net_emulator.DotNetEmulator emulator_obj):
    return DotNetStream(emulator_obj)

cdef DotNetObject New_Thread(net_emulator.DotNetEmulator emulator_obj):
    return DotNetThread(emulator_obj)

cdef DotNetObject New_MemoryStream(net_emulator.DotNetEmulator emulator_obj):
    return DotNetMemoryStream(emulator_obj)

cdef DotNetObject New_MD5CryptoServiceProvider(net_emulator.DotNetEmulator emulator_obj):
    return DotNetMD5CryptoServiceProvider(emulator_obj)

cdef DotNetObject New_TripleDESCryptoServiceProvider(net_emulator.DotNetEmulator emulator_obj):
    return DotNet3DESCryptoServiceProvider(emulator_obj)

cdef DotNetObject New_MulticastDelegate(net_emulator.DotNetEmulator emulator_obj):
    return DotNetMulticastDelegate(emulator_obj)

cdef DotNetObject New_Object(net_emulator.DotNetEmulator emulator_obj):
    cdef DotNetObject obj = DotNetObject(emulator_obj)
    obj.initialize_type(emulator_obj.get_method_obj().get_dotnetpe().get_typeref_by_full_name(b'System.Object'))
    return obj

cdef DotNetObject New_StackFrame(net_emulator.DotNetEmulator emulator_obj):
    return DotNetStackFrame(emulator_obj)

cdef DotNetObject New_BinaryReader(net_emulator.DotNetEmulator emulator_obj):
    return DotNetBinaryReader(emulator_obj)

cdef DotNetObject New_ResolveEventHandler(net_emulator.DotNetEmulator emulator_obj):
    return DotNetResolveEventHandler(emulator_obj)

cdef DotNetObject New_Comparison(net_emulator.DotNetEmulator emulator_obj):
    return DotNetComparison(emulator_obj)

cdef NewobjFuncMapping NET_EMULATE_TYPE_REGISTRATIONS[19]
NET_EMULATE_TYPE_REGISTRATIONS[0].name = 'System.Collections.Concurrent.ConcurrentDictionary'
NET_EMULATE_TYPE_REGISTRATIONS[0].func_ptr = <newobj_func_type>&New_ConcurrentDictionary
NET_EMULATE_TYPE_REGISTRATIONS[1].name = 'System.Collections.Generic.Dictionary'
NET_EMULATE_TYPE_REGISTRATIONS[1].func_ptr = <newobj_func_type>&New_Dictionary
NET_EMULATE_TYPE_REGISTRATIONS[2].name = 'System.Collections.SortedList'
NET_EMULATE_TYPE_REGISTRATIONS[2].func_ptr = <newobj_func_type>&New_SortedList
NET_EMULATE_TYPE_REGISTRATIONS[3].name = 'System.String'
NET_EMULATE_TYPE_REGISTRATIONS[3].func_ptr = <newobj_func_type>&New_String
NET_EMULATE_TYPE_REGISTRATIONS[4].name = 'System.Text.StringBuilder'
NET_EMULATE_TYPE_REGISTRATIONS[4].func_ptr = <newobj_func_type>&New_StringBuilder
NET_EMULATE_TYPE_REGISTRATIONS[5].name = 'System.Collections.Generic.List'
NET_EMULATE_TYPE_REGISTRATIONS[5].func_ptr = <newobj_func_type>&New_List
NET_EMULATE_TYPE_REGISTRATIONS[6].name = 'System.Diagnostics.StackTrace'
NET_EMULATE_TYPE_REGISTRATIONS[6].func_ptr = <newobj_func_type>&New_StackTrace
NET_EMULATE_TYPE_REGISTRATIONS[7].name = 'System.IO.Stream'
NET_EMULATE_TYPE_REGISTRATIONS[7].func_ptr = <newobj_func_type>&New_Stream
NET_EMULATE_TYPE_REGISTRATIONS[8].name = 'System.Threading.Thread'
NET_EMULATE_TYPE_REGISTRATIONS[8].func_ptr = <newobj_func_type>&New_Thread
NET_EMULATE_TYPE_REGISTRATIONS[9].name = 'System.IO.MemoryStream'
NET_EMULATE_TYPE_REGISTRATIONS[9].func_ptr = <newobj_func_type>&New_MemoryStream
NET_EMULATE_TYPE_REGISTRATIONS[10].name = 'System.Object'
NET_EMULATE_TYPE_REGISTRATIONS[10].func_ptr = <newobj_func_type>&New_Object
NET_EMULATE_TYPE_REGISTRATIONS[11].name = 'System.Security.Cryptography.MD5CryptoServiceProvider'
NET_EMULATE_TYPE_REGISTRATIONS[11].func_ptr = <newobj_func_type>&New_MD5CryptoServiceProvider
NET_EMULATE_TYPE_REGISTRATIONS[12].name = 'System.Security.Cryptography.TripleDESCryptoServiceProvider'
NET_EMULATE_TYPE_REGISTRATIONS[12].func_ptr = <newobj_func_type>&New_TripleDESCryptoServiceProvider
NET_EMULATE_TYPE_REGISTRATIONS[13].name = 'System.MulticastDelegate'
NET_EMULATE_TYPE_REGISTRATIONS[13].func_ptr = <newobj_func_type>&New_MulticastDelegate
NET_EMULATE_TYPE_REGISTRATIONS[14].name = 'System.Collections.Hashtable' #hashtable can be dropped in with dict, I think that works well enough.
NET_EMULATE_TYPE_REGISTRATIONS[14].func_ptr = <newobj_func_type>&New_Dictionary
NET_EMULATE_TYPE_REGISTRATIONS[15].name = 'System.IO.BinaryReader'
NET_EMULATE_TYPE_REGISTRATIONS[15].func_ptr = <newobj_func_type>&New_BinaryReader
NET_EMULATE_TYPE_REGISTRATIONS[16].name = 'System.Diagnostics.StackFrame'
NET_EMULATE_TYPE_REGISTRATIONS[16].func_ptr = <newobj_func_type>&New_StackFrame
NET_EMULATE_TYPE_REGISTRATIONS[17].name = 'System.ResolveEventHandler'
NET_EMULATE_TYPE_REGISTRATIONS[17].func_ptr = <newobj_func_type>&New_ResolveEventHandler
NET_EMULATE_TYPE_REGISTRATIONS[18].name = 'System.Comparison'
NET_EMULATE_TYPE_REGISTRATIONS[18].func_ptr = <newobj_func_type>&New_Comparison

cdef EmuFuncMapping NET_EMULATE_STATIC_FUNC_REGISTRATIONS[40]
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[0].name = 'System.Type.op_Equality'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[0].func_ptr = <static_func_type>&DotNetType.op_Equality
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[1].name = 'System.Type.op_Inequality'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[1].func_ptr = <static_func_type>&DotNetType.op_Inequality
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[2].name = 'System.Console.WriteLine'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[2].func_ptr = <static_func_type>&DotNetConsole.WriteLine
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[3].name = 'System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[3].func_ptr = <static_func_type>&DotNetRuntimeHelpers.InitializeArray
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[4].name = 'System.Reflection.Assembly.GetExecutingAssembly'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[4].func_ptr = <static_func_type>&DotNetAssembly.GetExecutingAssembly
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[5].name = 'System.Array.Clear'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[5].func_ptr = <static_func_type>&DotNetArray.Clear
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[6].name = 'System.Math.Max'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[6].func_ptr = <static_func_type>&DotNetMath.Max
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[7].name = 'System.Buffer.BlockCopy'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[7].func_ptr = <static_func_type>&DotNetBuffer.BlockCopy
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[8].name = 'System.Convert.ToString'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[8].func_ptr = <static_func_type>&DotNetConvert.ToString
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[9].name = 'System.String.Concat'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[9].func_ptr = <static_func_type>&DotNetString.Concat
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[10].name = 'System.UIntPtr.op_Explicit'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[10].func_ptr = <static_func_type>&DotNetUIntPtr.op_Explicit
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[11].name = 'System.Runtime.InteropServices.GCHandle.Alloc'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[11].func_ptr = <static_func_type>&DotNetGCHandle.Alloc
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[12].name = 'System.Convert.FromBase64String'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[12].func_ptr = <static_func_type>&DotNetConvert.FromBase64String
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[13].name = 'System.String.Empty'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[13].func_ptr = <static_func_type>&DotNetString.Empty
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[14].name = 'System.Text.Encoding.get_UTF8'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[14].func_ptr = <static_func_type>&DotNetEncoding.get_UTF8
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[15].name = 'System.Windows.Forms.Application.get_ProductVersion'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[15].func_ptr = <static_func_type>&DotNetApplication.get_ProductVersion
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[16].name = 'System.String.Intern'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[16].func_ptr = <static_func_type>&DotNetString.Intern
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[17].name = 'System.BitConverter.IsLittleEndian'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[17].func_ptr = <static_func_type>&DotNetBitConverter.IsLittleEndian
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[18].name = 'System.BitConverter.ToInt32'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[18].func_ptr = <static_func_type>&DotNetBitConverter.ToInt32
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[19].name = 'System.Array.Reverse'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[19].func_ptr = <static_func_type>&DotNetArray.Reverse
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[20].name = 'System.Reflection.Assembly.GetCallingAssembly'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[20].func_ptr = <static_func_type>&DotNetAssembly.GetCallingAssembly
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[21].name = 'System.GC.Collect'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[21].func_ptr = <static_func_type>&DotNetGC.Collect
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[22].name = 'System.Environment.GetFolderPath'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[22].func_ptr = <static_func_type>&DotNetEnvironment.GetFolderPath
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[23].name = 'System.IO.Path.Combine'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[23].func_ptr = <static_func_type>&DotNetPath.Combine
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[24].name = 'System.Console.Write'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[24].func_ptr = <static_func_type>&DotNetConsole.Write
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[25].name = 'System.Threading.Monitor.Enter'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[25].func_ptr = <static_func_type>&DotNetMonitor.Enter
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[26].name = 'System.Threading.Monitor.Exit'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[26].func_ptr = <static_func_type>&DotNetMonitor.Exit
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[27].name = 'System.Type.GetTypeFromHandle'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[27].func_ptr = <static_func_type>&DotNetType.GetTypeFromHandle
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[28].name = 'System.Text.Encoding.get_Unicode'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[28].func_ptr = <static_func_type>&DotNetEncoding.get_Unicode
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[29].name = 'System.Threading.Thread.get_CurrentThread'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[29].func_ptr = <static_func_type>&DotNetThread.get_CurrentThread
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[30].name = 'System.IntPtr.Zero'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[30].func_ptr = <static_func_type>&DotNetIntPtr.Zero
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[31].name = 'System.Security.Cryptography.RSACryptoServiceProvider.set_UseMachineKeyStore'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[31].func_ptr = <static_func_type>&DotNetRSACryptoServiceProvider.set_UseMachineKeyStore
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[32].name = 'System.Reflection.MethodInfo.op_Equality'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[32].func_ptr = <static_func_type>&DotNetMethodBase.op_Equality
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[33].name = 'System.Reflection.MethodInfo.op_Inequality'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[33].func_ptr = <static_func_type>&DotNetMethodBase.op_Inequality
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[34].name = 'System.Reflection.Assembly.op_Inequality'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[34].func_ptr = <static_func_type>&DotNetAssembly.op_Inequality
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[35].name = 'System.Array.Copy'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[35].func_ptr = <static_func_type>&DotNetArray.Copy
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[36].name = 'System.BitConverter.GetBytes'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[36].func_ptr = <static_func_type>&DotNetBitConverter.GetBytes
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[37].name = 'System.AppDomain.get_CurrentDomain'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[37].func_ptr = <static_func_type>&DotNetAppDomain.get_CurrentDomain
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[38].name = 'System.Reflection.Assembly.Load'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[38].func_ptr = <static_func_type>&DotNetAssembly.Load
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[39].name = 'System.Environment.get_Version'
NET_EMULATE_STATIC_FUNC_REGISTRATIONS[39].func_ptr = <static_func_type>&DotNetEnvironment.get_Version