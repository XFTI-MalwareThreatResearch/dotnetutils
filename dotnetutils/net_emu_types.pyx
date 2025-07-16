#cython: language_level=3
import cython
import io
import sys
import base64
import hashlib
import math
import threading
import binascii
import functools
import ntpath
import numpy
import zlib
from enum import IntEnum
from collections import defaultdict
from Crypto.Cipher import DES, DES3
from dotnetutils import net_exceptions
from dotnetutils cimport net_row_objects
from dotnetutils import net_utils, net_structs, net_opcodes, net_cil_disas

from dotnetutils cimport dotnetpefile

from dotnetutils cimport net_emulator
from dotnetutils import net_emu_coretypes

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

# FIXME: add all cor sigs to these methods
cdef get_cor_type_name(element_type):
    if element_type == net_structs.CorElementType.ELEMENT_TYPE_I1:
        return b'System.Int8'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U1:
        return b'System.UInt8'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I2:
        return b'System.Int16'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U2:
        return b'System.UInt16'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I4:
        return b'System.Int32'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U4:
        return b'System.UInt32'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I8:
        return b'System.Int64'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U8:
        return b'System.UInt64'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_R4:
        return b'System.Single'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_R8:
        return b'System.Double'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_STRING:
        return b'System.String'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_VOID:
        return b'System.Void'
    raise net_exceptions.OperationNotSupportedException()


cpdef get_cor_type_from_name(type_name):
    if type_name == b'System.Void':
        return net_utils.get_CorSig_Void()
    elif type_name == b'System.Int8':
        return net_utils.get_CorSig_SByte()
    elif type_name == b'System.UInt8':
        return net_utils.get_CorSig_Byte()
    elif type_name == b'System.Int16':
        return net_utils.get_CorSig_Int16()
    elif type_name == b'System.UInt16':
        return net_utils.get_CorSig_UInt16()
    elif type_name == b'System.Int32':
        return net_utils.get_CorSig_Int32()
    elif type_name == b'System.UInt32':
        return net_utils.get_CorSig_UInt32()
    elif type_name == b'System.Int64':
        return net_utils.get_CorSig_Int64()
    elif type_name == b'System.UInt64':
        return net_utils.get_CorSig_UInt64()
    elif type_name == b'System.Single':
        return net_utils.get_CorSig_Single()
    elif type_name == b'System.Double':
        return net_utils.get_CorSig_Double()
    elif type_name == b'System.String':
        return net_utils.get_CorSig_String()
    return None

cdef class DotNetObject:
    def __init__(self, emulator_obj):
        if emulator_obj == None:
            raise Exception 
        self.__emulator_obj = emulator_obj
        self.fields = dict()
        self.type_obj = None
        self.type_sig_obj = None
        self.initialized_fields = list()
        self.__initialized = False

    cpdef net_emulator.DotNetEmulator get_emulator_obj(self):
        return self.__emulator_obj

    cpdef void set_field(self, unsigned long idno, object val):
        self.fields[idno] = val

    cpdef object get_field(self, unsigned long idno):
        if idno not in self.fields:
            self.__initialize_field(idno)
        return self.fields[idno]

    cpdef net_row_objects.TypeDefOrRef get_type_obj(self):
        return self.type_obj

    cpdef void set_type_obj(self, net_row_objects.TypeDefOrRef type_obj):
        self.type_obj = type_obj

    cpdef net_utils.TypeSig get_type_sig_obj(self):
        return self.type_sig_obj

    cpdef void set_type_sig_obj(self, net_utils.TypeSig type_sig_obj):
        self.type_sig_obj = type_sig_obj

    cpdef void __initialize_field(self, unsigned long field_rid):
        cdef DotNetNull null_obj
        field_obj = self.get_emulator_obj().get_method_obj().get_dotnetpe().get_metadata_table('Field').get(field_rid)
        field_sig: net_utils.FieldSig = field_obj.get_field_signature()
        if not isinstance(field_sig, net_utils.FieldSig):
            raise net_exceptions.ObjectTypeException
        type_sig = field_sig.get_type_sig()
        if isinstance(type_sig, net_utils.CorLibTypeSig):
            if type_sig.get_element_type() == net_structs.ELEMENT_TYPE_I:
                self.set_field(field_rid, net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_I1:
                self.set_field(field_rid, net_emu_coretypes.DotNetInt8(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_I2:
                self.set_field(field_rid, net_emu_coretypes.DotNetInt16(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_I4:
                self.set_field(field_rid, net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_I8:
                self.set_field(field_rid, net_emu_coretypes.DotNetInt64(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_U:
                self.set_field(field_rid, net_emu_coretypes.DotNetUInt32(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_U1:
                self.set_field(field_rid, net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_U2:
                self.set_field(field_rid, net_emu_coretypes.DotNetUInt16(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_U4:
                self.set_field(field_rid, net_emu_coretypes.DotNetUInt32(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_U8:
                self.set_field(field_rid, net_emu_coretypes.DotNetUInt64(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_R4:
                self.set_field(field_rid, net_emu_coretypes.DotNetSingle(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_R8:
                self.set_field(field_rid, net_emu_coretypes.DotNetDouble(self.get_emulator_obj(), 0))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_STRING:
                self.set_field(field_rid, DotNetString.Empty(self.get_emulator_obj().get_appdomain()))
            elif type_sig.get_element_type() == net_structs.ELEMENT_TYPE_BOOLEAN:
                self.set_field(field_rid, net_emu_coretypes.DotNetBoolean(self.get_emulator_obj(), False))
            else:
                raise Exception('unknown corlibtype for initialize_field: {}'.format(type_sig.get_element_type()))
        else:
            if isinstance(type_sig, net_utils.ClassSig):
                null_obj = DotNetNull(self.get_emulator_obj())
                self.set_field(field_rid, null_obj)
            elif isinstance(type_sig, net_utils.ValueTypeSig):
                self.set_field(field_rid, DotNetObject(self.get_emulator_obj())) #ValueTypes are similar enough to objects it seems where this should be proper.
                #valuetypes are weird - seems the most prominent is basically enums which should be treated as numbers.  This might need to be adjusted eventually.
                #structs can also be valuetypes - we need dotnetobject() here.
            elif isinstance(type_sig, net_utils.SZArraySig):
                null_obj = DotNetNull(self.get_emulator_obj())
                self.set_field(field_rid, null_obj) #DotNetNull() should work fine here since any arrays are going to be initialized by a newarr anyway.
            else:
                raise Exception('unknown sigtype for initialize_field {}'.format(type(type_sig)))


    cpdef initialize_type(self, type_obj):  
        self.type_obj = type_obj
        """if isinstance(type_obj, net_row_objects.TypeDef):
            if not self.__initialized:
                self.__initialized = True
                for field_obj in type_obj['FieldList'].get_formatted_value():
                    # if field_obj.get_rid() in self.initialized_fields:
                    #    continue
                    if field_obj.is_static():
                        continue
                    sig_obj = field_obj.get_field_signature()
                    if not isinstance(sig_obj, net_utils.FieldSig):
                        raise net_exceptions.ObjectTypeException
                    if isinstance(sig_obj.get_type_sig(), net_utils.CorLibTypeSig):
                        self.set_field(field_obj.get_rid(), net_emu_coretypes.DotNetInt32(0))
                    else:
                        if isinstance(sig_obj.get_type_sig(), net_utils.TypeDefOrRefSig):
                            obj = DotNetObject(self.get_emulator_obj())
                            obj.initialize_type(sig_obj.get_type_sig().get_type())
                            self.set_field(field_obj.get_rid(), obj)
                    # self.initialized_fields.append(field_obj.get_rid())"""

    cpdef get_type(self):
        return type(self)

    def __gt__(self, other):
        if isinstance(other, DotNetNull):
            return True
        else:
            return self > other

    def __str__(self):
        if self.get_type_obj():
            if len(self.fields.keys()) > 0:
                str_val = object.__str__(self) + ',type_obj={}:{}, fields='.format(self.get_type_obj().get_table_name(),
                                                                                  self.get_type_obj().get_rid())
                str_val += '{'
                for key, value_obj in self.fields.items():
                    str_val += str(key) + ': ' + str(value_obj) + ','
                str_val = str_val.rstrip(',') + '}'
                return str_val                
            return object.__str__(self) + ',type_obj={}:{}'.format(self.get_type_obj().get_table_name(), self.get_type_obj().get_rid())
        else:
            if len(self.fields.keys()) > 0:
                str_val = object.__str__(self) + ',fields={'
                for key, value_obj in self.fields.items():
                    str_val += str(key) + ': ' + str(value_obj) + ','
                str_val = str_val.rstrip(',') + '}'
                return str_val                
            return object.__str__(self)

cdef class DotNetNull(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    def __eq__(self, other):
        return isinstance(other, DotNetNull)

    def __str__(self):
        return 'null'

    # for math purposes, DotNetNull should be treated as zero.
    def __gt__(self, other):
        if isinstance(other, DotNetNull):
            return False
        return 0 > other

    def __lt__(self, other):
        if isinstance(other, DotNetNull):
            return False
        return 0 < other


cdef class DotNetType(DotNetObject):
    def __init__(self, emulator_obj, type_handle, sig_obj=None):
        DotNetObject.__init__(self, emulator_obj)
        if isinstance(type_handle, net_row_objects.TypeDef) or isinstance(type_handle, net_row_objects.TypeRef):
            self.type_handle = type_handle
        elif isinstance(type_handle, net_row_objects.TypeSpec):
            self.type_handle = type_handle.get_type()
        else:
            self.type_handle = type_handle.get_internal_typedef()
        self.sig_obj = sig_obj

    cpdef get_type_handle(self):
        return self.type_handle

    def get_IsByRef(self):
        return isinstance(self.sig_obj, net_utils.ByRefSig)

    #def GetElementType(self):
    #    pass #TODO

    @staticmethod
    def op_Equality(app_domain, obj1, obj2):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), obj1 == obj2)

    @staticmethod
    def op_Inequality(app_domain, obj1, obj2):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), obj1 != obj2)

    @staticmethod
    def GetTypeFromHandle(app_domain, obj):
        obj2 = DotNetType(app_domain.get_emulator_obj(), obj)
        obj2.set_type_obj(app_domain.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(b'System.Type'))
        return obj2

    def get_Module(self):
        if not isinstance(self.type_handle, net_row_objects.TypeDef):
            raise net_exceptions.ObjectTypeException
        #There is going to have to be a ton of reimplementation to support this for TypeRefs.
        assembly = DotNetAssembly.GetExecutingAssembly(self.get_emulator_obj().get_appdomain())
        return DotNetModule(self.get_emulator_obj(), assembly.get_module())

    def GetFields(self, binding_flags=None):
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
            result_array.set_internal_array(field_objs)
            return result_array
        else:
            raise net_exceptions.OperationNotSupportedException()

    def get_MetadataToken(self):
        coded_token = self.get_type_handle().get_token()
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), coded_token)

    def __eq__(self, other):
        return isinstance(other, DotNetType) and self.get_type_handle() == other.get_type_handle()

    def get_Assembly(self):
        module_obj = self.get_type_handle().get_dotnetpe().get_metadata_table('Assembly').get(0)
        return DotNetAssembly(self.get_emulator_obj(), module_obj)


cdef class DotNetMonitor(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def Enter(app_domain, obj, lockTaken=False):
        """
        System.Threading.Monitor.Enter
        Doesnt appear to do anything emulatable
        """
        pass

    @staticmethod
    def Exit(app_domain, obj):
        # same as above
        pass

cdef class DotNetDictionary(DotNetObject):
    def __init__(self, emulator_obj, capacity=0): #Capacity probably doesnt actually matter.
        DotNetObject.__init__(self, emulator_obj)
        self.__internal_dict = dict()

    def TryGetValue(self, param1, param2):
        if param1 in self.__internal_dict:
            value1 = self.__internal_dict[param1]
            param2.array = [value1]
            param2.index = 0
            return True
        return False

    def set_Item(self, param1, param2):
        self.__internal_dict[param1] = param2

    def Add(self, param1, param2):
        self.__internal_dict[param1] = param2

    def ContainsKey(self, kv):
        return kv in self.__internal_dict

    def get_Count(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), len(self.__internal_dict))



cdef class DotNetConcurrentDictionary(DotNetDictionary):
    def __init__(self, emulator_obj):
        DotNetDictionary.__init__(self, emulator_obj)

cdef class DotNetStringBuilder(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.char_array = bytes()
        self.is_wide = False

    def Append(self, number):
        if isinstance(number, net_emu_coretypes.DotNetInt16) or isinstance(number, net_emu_coretypes.DotNetUInt16):
            to_add = int.to_bytes(number.item(), 2, 'little')
            self.is_wide = True
        else:
            to_add = int.to_bytes(number.item(), 1, 'little')
        self.char_array += to_add
        return self

    def ToString(self):
        if self.is_wide:
            return DotNetString(self.get_emulator_obj(), self.char_array, str_encoding='utf-16le')
        return DotNetString(self.get_emulator_obj(), self.char_array, str_encoding='utf-8')


cdef class DotNetStream(DotNetObject):
    def __init__(self, emulator_obj, rsrc_data):
        DotNetObject.__init__(self, emulator_obj)
        if isinstance(rsrc_data, DotNetArray):
            self.rsrc_stream = io.BytesIO(bytes(rsrc_data.get_internal_array()))
        else:
            if isinstance(rsrc_data, DotNetStream):
                self.rsrc_stream = rsrc_data.get_rsrc_stream()
            else:
                self.rsrc_stream = io.BytesIO(rsrc_data)

    def get_rsrc_stream(self):
        return self.rsrc_stream

    def Read(self, buffer, offset, count):
        for x in range(count):
            buffer[offset + x] = self.ReadByte()
        return count

    def set_Position(self, pos):
        self.rsrc_stream.seek(pos, io.SEEK_SET)

    def get_Position(self):
        return net_emu_coretypes.DotNetInt64(self.get_emulator_obj(), self.rsrc_stream.tell())

    def ReadByte(self):
        return net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), self.rsrc_stream.read(1)[0])

    def get_Length(self):
        return net_emu_coretypes.DotNetInt64(self.get_emulator_obj(), self.rsrc_stream.getbuffer().nbytes)

    def Write(self, buffer, offset, count):
        self.rsrc_stream.write(buffer[offset:offset + count])

    cpdef DotNetArray ReadBytes(self, object count):
        cdef DotNetArray arr_obj
        cdef bytes raw_obj
        cdef list actual_obj
        cdef Py_ssize_t x
        arr_obj = DotNetArray(self.get_emulator_obj(), count, DotNetAssembly.GetExecutingAssembly(self.get_emulator_obj().get_appdomain()).get_module().get_dotnetpe().get_type_by_full_name(
            b'System.Byte'), initialize=False)
        raw_obj = self.rsrc_stream.read(count)
        actual_obj = list()
        for x in range(len(raw_obj)):
            item = raw_obj[x]
            actual_obj.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), item))
        arr_obj.set_internal_array(actual_obj)
        return arr_obj

    def Close(self):
        self.rsrc_stream.close()

    def __str__(self):
        return 'DotNetStream: length={}, position={}, buffer={}'.format(self.get_Length(), self.get_Position(), self.rsrc_stream)


cdef class DotNetMemoryStream(DotNetObject):
    def __init__(self, emulator_obj, data, writeable=True):
        DotNetObject.__init__(self, emulator_obj)
        if not isinstance(data, net_emu_coretypes.DotNetInt32):
            self.internal_data = data
            self.writeable = writeable
            self.position = 0
        else:
            self.position = 0
            self.writeable = True
            self.internal_data = bytearray()

    def get_rsrc_stream(self):
        return io.BytesIO(self.internal_data)

    cpdef object Read(self, DotNetArray buffer, object offset, object count):
        cdef Py_ssize_t x
        for x in range(count):
            buffer[offset + x] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), self.internal_data[self.position + x])
        self.position += count
        return count

    def set_Position(self, pos):
        self.position = pos

    def get_Position(self):
        return net_emu_coretypes.DotNetInt64(self.get_emulator_obj(), self.position)

    def get_Length(self):
        return net_emu_coretypes.DotNetInt64(self.get_emulator_obj(), len(self.internal_data))

    def ReadByte(self):
        result = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), self.internal_data[self.position])
        self.position += 1
        return result

    cpdef void Write(self, DotNetArray buffer, object offset, object count) except *:
        # expand the array if needed.
        cdef Py_ssize_t amount_needed
        cdef Py_ssize_t x
        if len(self.internal_data) < (count + self.position):
            amt_needed = (count + self.position) - len(self.internal_data)
            self.internal_data = self.internal_data + bytearray([0] * amt_needed)
        for x in range(count):
            self.internal_data[self.position + x] = buffer[offset + x]
        self.position += count

    cpdef DotNetArray ToArray(self):
        cdef list internal_data
        cdef Py_ssize_t x
        cdef DotNetArray array
        internal_data = list(self.internal_data)
        for x in range(len(internal_data)):
            internal_data[x] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), internal_data[x])
        array = DotNetArray(self.get_emulator_obj(), len(internal_data), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                            initialize=False)
        array.set_internal_array(internal_data)
        return array

    def __str__(self):
        return str(self.internal_data[:50]) + ' Object: ' + DotNetObject.__str__(self) + ' position: {}'.format(
            self.position)


cdef class DotNetAssemblyName(DotNetObject):
    def __init__(self, emulator_obj, name, assembly):
        DotNetObject.__init__(self, emulator_obj)
        self.name = name
        self.assembly = assembly
        if self.name.endswith(b'.exe'):
            self.name = self.name.rstrip(b'.exe')
        elif self.name.endswith(b'.dll'):
            self.name = self.name.rstrip(b'.dll')

    def GetPublicKeyToken(self):
        module_obj = self.assembly.get_module().get_dotnetpe().get_metadata_table(
            'Assembly').get(0)

        if module_obj['PublicKey'].get_raw_value() == 0:
            #If raw value is 0, return a empty array.
            return DotNetArray(self.get_emulator_obj(), 0, self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'))
        public_key = module_obj['PublicKey'].get_value()

        sha_hash = hashlib.sha1()
        sha_hash.update(public_key)
        hashed_key = sha_hash.digest()
        public_key_token = list(hashed_key[-8:][::-1])
        for x in range(len(public_key_token)):
            public_key_token[x] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), public_key_token[x])
        array = DotNetArray(self.get_emulator_obj(), len(public_key_token), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                            initialize=False)
        array.set_internal_array(list(public_key_token))
        return array

    def get_Name(self):
        return DotNetString(self.get_emulator_obj(), self.name, 'utf-8')


cdef class DotNetManifestModule(DotNetObject):
    def __init__(self, emulator_obj, dnassembly):
        DotNetObject.__init__(self, emulator_obj)
        self.dnassembly = dnassembly


cdef class DotNetAssembly(DotNetObject):
    """
    This class is meant to fool checks to ensure that
    Deobfuscation methods are being executed by their assembly.
    """
    def __init__(self, emulator_obj, module):
        DotNetObject.__init__(self, emulator_obj)
        self.module = module

    cpdef get_module(self):
        return self.module

    def get_ManifestModule(self):
        return DotNetManifestModule(self.get_emulator_obj(), self)

    def get_EntryPoint(self):
        return DotNetMemberInfo(self.get_emulator_obj(), self.get_module().get_dotnetpe().get_entry_point())

    def get_FullName(self):
        dpe = self.get_module().get_dotnetpe()
        assembly_obj = dpe.get_metadata_table('Assembly').get(0)
        name = assembly_obj['Name'].get_value().decode('utf-8')
        version = '{}.{}.{}'.format(assembly_obj['MajorVersion'].get_value(), assembly_obj['MinorVersion'].get_value(), assembly_obj['BuildNumber'].get_value())

        assembly_name = self.GetName()
        assembly_token = assembly_name.GetPublicKeyToken()
        pkeytoken = binascii.hexlify(bytes(assembly_token.get_internal_array())).decode()
        string_name = '{}, Version={}, Culture=neutral, PublicKeyToken={}'.format(name, version, pkeytoken)
        return DotNetString(self.get_emulator_obj(), string_name.encode('utf-16le'))

    def get_Location(self):
        """
        Some DotNetReactor tamper checks use this. 
        Can be fooled due to the way its structured
        It throws an exception if it detects tampering with the binary, but it wont throw that exception if it cant get the location.
        Return a blank string to fool these checks.  Of note: this may need to be changed eventually if a binary comes along that actually requires this method to work. 
        """
        return DotNetString.Empty(self.get_emulator_obj().get_appdomain())

    @staticmethod
    def GetExecutingAssembly(app_domain):
        dotnetassembly = DotNetAssembly(app_domain.get_emulator_obj(),
            app_domain.get_executing_dotnetpe().get_metadata_table('Assembly').get(0))
        dotnetassembly.set_type_obj(app_domain.get_executing_dotnetpe().get_type_by_full_name(
            b'System.Reflection.Assembly'))
        return dotnetassembly

    @staticmethod
    def GetCallingAssembly(app_domain):
        dotnetassembly = DotNetAssembly(app_domain.get_emulator_obj(), app_domain.get_calling_dotnetpe().get_metadata_table('Assembly').get(0))
        dotnetassembly.set_type_obj(app_domain.get_calling_dotnetpe().get_type_by_full_name(b'System.Reflection.Assembly'))
        return dotnetassembly

    def GetManifestResourceStream(self, name):
        resource_data = self.get_emulator_obj().get_appdomain().get_resource_by_name(name)
        if not resource_data:
            obj = DotNetNull(self.get_emulator_obj())
            return obj

        obj = DotNetStream(self.get_emulator_obj(), resource_data)
        obj.set_type_obj(self.get_module().get_dotnetpe().get_type_by_full_name(
            b'System.IO.Stream'))
        return obj

    def GetManifestResourceNames(self):
        resources = self.get_module().get_dotnetpe().get_metadata_table('ManifestResource')
        result = list()
        if resources:
            for item in resources:
                dns = DotNetString(self.get_emulator_obj(), item['Name'].get_value(), 'utf-8')
                result.append(dns)
        
        results = DotNetArray(self.get_emulator_obj(), len(result), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.String'),
                    initialize=False)
        results.set_internal_array(result)
        return results

    def GetName(self):
        obj = DotNetAssemblyName(self.get_emulator_obj(), self.get_module()['Name'].get_value(), self)
        obj.set_type_obj(self.get_module().get_dotnetpe().get_type_by_full_name(
            b'System.Reflection.AssemblyName'))
        return obj

    def GetModules(self):
        modules = self.get_module().get_dotnetpe().get_metadata_table('Module')
        result = DotNetArray(self.get_emulator_obj(), len(modules), self.get_module().get_dotnetpe().get_type_by_full_name(
            b'System.Reflection.Module'))
        for x in range(len(modules)):
            result[x] = DotNetModule(self.get_emulator_obj(), modules.get(x))
        return result

    def Equals(self, other):
        return net_emu_coretypes.DotNetBoolean(self.get_emulator_obj(), self.__eq__(other))

    @staticmethod
    def op_Inequality(app_domain, param1, other):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), not param1.Equals(other))

    @staticmethod
    def Load(app_domain, binary_data):
        if isinstance(binary_data, DotNetArray):
            byte_obj = bytes(binary_data.get_internal_array())
            return app_domain.load_assembly_from_bytes(byte_obj)
        elif isinstance(binary_data, DotNetString):
            #For now dont search the filesystem for assemblies, only the current loaded stuff.
            result = app_domain.get_assembly_by_name(binary_data)
            if result == None:
                obj = DotNetNull(app_domain.get_emulator_obj())
                return obj
            return result
        else:
            raise net_exceptions.InvalidArgumentsException()

    def __eq__(self, other):
        return isinstance(other, DotNetAssembly) and self.get_module() == other.get_module()


cdef class DotNetList(DotNetObject):
    def __init__(self, emulator_obj, initial_capacity=0):
        DotNetObject.__init__(self, emulator_obj)
        self.internal = list([DotNetNull(emulator_obj)] * initial_capacity) #NOTE: this may cause some problems.  Initial values here may need to be reworked.

    def AddRange(self, range_obj):
        for item in range_obj:
            self.internal.append(item)

    def Add(self, item):
        self.internal.append(item)

    def Count(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), len(self.internal))

    def get_Count(self):
        return self.Count()

    def get_Item(self, index):
        return self.internal[index]

    def set_Item(self, index, value1):
        self.internal[index] = value1

    def Sort(self, comparison):
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

        def python_sort_runner(item1, item2):
            nonlocal self
            nonlocal compare_method
            nonlocal comparison
            method_params = [item1, item2]
            if not compare_method.is_static_method():
                method_params.insert(0, comparison)
            else:
                method_params.insert(0, self.get_emulator_obj().get_appdomain())
            emu_obj = self.get_emulator_obj().spawn_new_emulator(compare_method, method_params=method_params, start_offset=0, end_offset=-1, caller=None, end_method_rid=0, end_eip=-1)
            emu_obj.run_function()
            result = emu_obj.get_stack().pop()
            return result

        self.internal.sort(key=functools.cmp_to_key(python_sort_runner))

    def __getitem__(self, item):
        return self.internal[item]

    def __str__(self):
        return str(self.internal) + ' Count={}'.format(self.get_Count())

cdef class DotNetArray(DotNetObject):
    def __init__(self, emulator_obj, size, type_obj=None, initialize=True):
        DotNetObject.__init__(self, emulator_obj)
        self.set_type_obj(type_obj)
        #If I change how this is set up, it will save a literal ton of time.
        self.internal_array = []
        if initialize:
            self.setup_default_value(0, int(size), True)

    cpdef list get_internal_array(self):
        return self.internal_array

    cpdef void set_internal_array(self, list int_array) except *:
        if len(int_array) > 0:
            if isinstance(int_array[0], int):
                raise Exception()
        self.internal_array = int_array

    cpdef void setup_default_value(self, unsigned long index, unsigned long size, bint init):
        cdef DotNetObject dno
        cdef Py_ssize_t x
        if not init:
            if self.get_type_obj().get_full_name() == b'System.Byte':
                for x in range(size):
                    self.internal_array[x + index] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), 0)
            else:
                for x in range(size):
                    dno = DotNetObject(self.get_emulator_obj())
                    dno.initialize_type(self.get_type_obj())
                    self.internal_array[x + index] = dno
        else:
            if self.get_type_obj().get_full_name() == b'System.Byte':
                for x in range(size):
                    self.internal_array.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), 0))
            else:
                for x in range(size):
                    dno = DotNetNull(self.get_emulator_obj()) #If this is system.object it could mess up some null checks.
                    dno.initialize_type(self.get_type_obj())
                    self.internal_array.append(dno)

        
    @staticmethod
    def Copy(app_domain, src, srcIndex, dst, dstIndex, amt):
        for x in range(amt):
            dst[dstIndex + x] = src[srcIndex + x]

    @staticmethod
    def Clear(app_domain, array_obj, index, length):
        array_obj.setup_default_value(index, length, False)

    def reverse_internal(self):
        self.internal_array = self.internal_array[::-1]

    @staticmethod
    def Reverse(app_domain, array):
        array.reverse_internal()

    def __getitem__(self, item):
        obj_ref = item
        if isinstance(item, ArrayAddress):
            obj_ref = item.get_obj_ref()
        return self.internal_array[obj_ref]

    def __setitem__(self, key, newvalue):
        if isinstance(key, ArrayAddress):
            self.internal_array[key.get_obj_ref()] = newvalue
            return
        self.internal_array[key] = newvalue

    def __len__(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), len(self.internal_array))

    def __add__(self, other):
        new_obj = DotNetArray(self.get_emulator_obj(), 1, initialize=False)
        new_obj.set_type_obj(self.get_type_obj())
        new_obj.internal_array = self.internal_array + other.internal_array
        return new_obj

    def __str__(self):
        if isinstance(self.internal_array, bytearray) or isinstance(self.internal_array, bytes):
            array_str = str(list(self.internal_array))
        else:
            array_str = str(self.internal_array)
        if len(array_str) > 250:
            if self.get_type_obj() != None:
                type_rid = self.get_type_obj().get_rid()
                type_name = self.get_type_obj().get_table_name()
            else:
                type_rid = 'unkown_rid'
                type_name = 'unknown_table_name'
            int_len = len(self.internal_array)
            begin = array_str[:50]
            end = array_str[-50:]
            return 'DotNetArray: type_obj={}:{}, len={}, begin={}, end={}'.format(type_name,
                                                                                  type_rid,
                                                                                  int_len,
                                                                                  begin, end)
        return 'DotnetArray: type_obj={}:{} len={}, content={}'.format(self.get_type_obj().get_table_name(), self.get_type_obj().get_rid(),
                                                                       len(self.internal_array), array_str)

cdef class DotNetStackTrace(DotNetObject):
    def __init__(self, emulator_obj, skipFrames=0, fNeedFileInfo=False):
        DotNetObject.__init__(self, emulator_obj)
        self.skipFrames = skipFrames
        self.fNeedFileInfo = fNeedFileInfo

    def GetFrame(self, number):
        emulator_list = list()
        # first generate the list of emulators
        emulator_ptr = self.get_emulator_obj()
        while emulator_ptr:
            emulator_list.insert(0, emulator_ptr)
            emulator_ptr = emulator_ptr.get_caller()
        sf_obj = DotNetStackFrame(self.get_emulator_obj())
        sf_obj.set_type_obj(self.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(
            b'System.Diagnostics.StackFrame'))
        sf_obj.current_emulator = emulator_list[number]
        return sf_obj

cdef class DotNetStackFrame(DotNetObject):
    def __init__(self, emulator_obj, skip_frames=0):
        DotNetObject.__init__(self, emulator_obj)
        self.current_emulator = None
        self.skip_frames = skip_frames

    def GetMethod(self):
        emulator_obj = self.get_emulator_obj()
        for x in range(self.skip_frames):
            emulator_obj = emulator_obj.get_caller()
        obj = DotNetMemberInfo(self.get_emulator_obj(), emulator_obj.get_method_obj())
        obj.set_type_obj(emulator_obj.get_method_obj().get_dotnetpe().get_type_by_full_name(
            b'System.Reflection.MemberInfo'))
        return obj

cdef class DotNetMemberInfo(DotNetObject):
    def __init__(self, emulator_obj, internal_method):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_method = internal_method

    def get_DeclaringType(self):
        return DotNetType(self.get_emulator_obj(), self.internal_method.get_parent_type())

cdef class DotNetConsole(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
    #we probably dont need these methods to actually do anything for our purposes.
    @staticmethod
    def WriteLine(app_domain, item):
        #print(item)
        pass

    @staticmethod
    def Write(app_domain, item):
        #print(item)
        pass

def dne_thread_runner(dnfunc):
    dnfunc.Invoke()

cdef class DotNetThread(DotNetObject):
    def __init__(self, emulator_obj, thread_start=None):
        DotNetObject.__init__(self, emulator_obj)
        #DotNetThread.__identifier should increment on each new thread.  Going to need to work on this a bit. TODO
        self.__identifier = net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 1)
        self.__thread_start = thread_start
        self.__internal_thread = None

    cpdef set_identifier(self, int identifier):
        self.__identifier = net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), identifier)

    def Start(self):
        if not isinstance(self.__thread_start, DotNetThreadStart):
            raise net_exceptions.InvalidArgumentsException()
        nobj = DotNetNull(self.get_emulator_obj())
        dnfunc = DotNetFunc(self.get_emulator_obj(), nobj, self.__thread_start.get_method_object())
        self.__internal_thread = threading.Thread(target=dne_thread_runner, args=[dnfunc])
        self.__internal_thread.start()

    def Join(self):
        if self.__internal_thread == None:
            raise net_exceptions.InvalidArgumentsException()
        self.__internal_thread.join()

    @staticmethod
    def get_CurrentThread(app_domain):
        # Emulator doesnt support threads so just return a fake object.
        obj = DotNetThread(app_domain.get_emulator_obj())
        obj.set_type_obj(app_domain.get_executing_dotnetpe().get_type_by_full_name(
            b'System.Threading.Thread'))
        return obj

    @staticmethod
    def Sleep(app_domain, amt_of_time):
        pass # For now, just ignore sleeps.  I have not seen an obfuscator attempt to detect this.

    def get_ManagedThreadId(self):
        return self.__identifier

cdef void initialize_array_helper(DotNetArray arr, net_row_objects.RowObject runtime_handle) except *:
    cdef net_row_objects.Field field_obj
    cdef Py_ssize_t x
    cdef Py_ssize_t type_size
    cdef Py_ssize_t curr_index
    cdef bytes type_name
    cdef bytes data
    if isinstance(runtime_handle, net_row_objects.Field):
        field_obj = <net_row_objects.Field> runtime_handle
        data = field_obj.get_data()
        type_name = arr.get_type_obj()['TypeName'].get_value()
        if type_name == b'UInt32':
            type_size = 4
            curr_index = 0
            for x in range(len(arr)):
                arr[x] = net_emu_coretypes.DotNetUInt32(arr.get_emulator_obj(), int.from_bytes(
                    data[curr_index:curr_index + type_size], 'little', signed=False))
                curr_index += type_size

        elif type_name == b'Int32':
            type_size = 4
            curr_index = 0
            for x in range(len(arr)):
                arr[x] = net_emu_coretypes.DotNetInt32(arr.get_emulator_obj(), int.from_bytes(
                    data[curr_index:curr_index + type_size], 'little', signed=True))
                curr_index += type_size

        elif type_name == b'Char':
            type_size = 2
            curr_index = 0
            for x in range(len(arr)):
                arr[x] = net_emu_coretypes.DotNetInt16(arr.get_emulator_obj(), int.from_bytes(
                    data[curr_index:curr_index + type_size], 'little', signed=False))
                curr_index += type_size

        elif type_name == b'Byte':
            curr_index = 0
            for x in range(len(arr)):
                arr[x] = net_emu_coretypes.DotNetUInt8(arr.get_emulator_obj(), data[curr_index])
                curr_index += 1

        else:
            raise Exception()  # FIXME: change
    else:
        raise Exception()  # FIXME: change

cdef class DotNetRuntimeHelpers(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def InitializeArray(app_domain, arr, runtime_handle):
        #static methods cant be cdef but we should take advantage of loop speeds.
        initialize_array_helper(arr, runtime_handle)

cdef class ArrayAddress:
    def __init__(self, array, index):
        if isinstance(array, DotNetArray):
            self.__internal_arrayaddr_array = array.get_internal_array()
        else:
            self.__internal_arrayaddr_array = array
        self.__internal_arrayaddr_index = index

    """def __getattribute__(self, __name: str):
        if __name.startswith('_ArrayAddress'):
            return super().__getattribute__(__name)
        #first check to see if the internal object has the attribute.
        #NOTE: because this goes through __class__ it will mess up isinstance.
        obj = self.__internal_arrayaddr_array[int(self.__internal_arrayaddr_index)]
        if hasattr(obj, __name):
            return getattr(obj, __name)
        else:
            return super().__getattribute__(__name)"""

    cpdef get_obj_ref(self):
        return self.__internal_arrayaddr_array[self.__internal_arrayaddr_index]

    cpdef set_obj_ref(self, obj_ref):
        self.__internal_arrayaddr_array[self.__internal_arrayaddr_index] = obj_ref

    def __str__(self):
        return 'ArrayAddress - index {} with value {}'.format(self.__internal_arrayaddr_index,
                                                              self.__internal_arrayaddr_array[
                                                                  self.__internal_arrayaddr_index])

cdef class DotNetMath(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def Max(app_domain, value1, value2):
        val_obj = numpy.max([value1, value2])
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)

    @staticmethod
    def Abs(app_domain, value1):
        val_obj = numpy.absolute(value1)
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)

    @staticmethod
    def Exp(app_domain, value1):
        val_obj = numpy.exp(value1)
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)

    @staticmethod
    def Cos(app_domain, value1):
        val_obj = numpy.cos(value1)
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)

    @staticmethod
    def Sin(app_domain, value1):
        val_obj = numpy.sin(value1)
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)

    @staticmethod
    def Tan(app_domain, value1):
        val_obj = numpy.tan(value1)
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)
    
    @staticmethod
    def Log(app_domain, value1):
        val_obj = numpy.log(value1)
        return net_emu_coretypes.DotNetNumber(app_domain.get_emulator_obj(), val_obj.dtype, val_obj)


cdef class DotNetBitConverter(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def IsLittleEndian(app_domain):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), sys.byteorder == 'little')

    @staticmethod
    def ToInt32(app_domain, obj, start_index=None):
        usable_obj = obj
        if start_index is not None:
            usable_obj = usable_obj[start_index:]
        if isinstance(usable_obj, list):
            # force the list to be uint8
            usable_bytes = list()
            for usable in usable_obj:
                usable_bytes.append(net_emu_coretypes.DotNetUInt8(app_domain.get_emulator_obj(), usable))
            p_int = int.from_bytes(bytes(usable_bytes), 'little', signed=True)
            return net_emu_coretypes.DotNetInt32(app_domain.get_emulator_obj(), p_int & 0xFFFFFFFF)
        else:
            return net_emu_coretypes.DotNetInt32(app_domain.get_emulator_obj(), usable_obj)

    @staticmethod
    def GetBytes(app_domain, value1):
        if not hasattr(value1, 'dtype'):
            raise net_exceptions.ObjectTypeException

        dnr = DotNetArray(app_domain.get_emulator_obj(), value1.dtype.itemsize,
                          DotNetAssembly.GetExecutingAssembly(app_domain).get_module().get_dotnetpe().get_type_by_full_name(b'System.Byte'),
                          initialize=False)
        b_data = list(int.to_bytes(value1.item(), length=value1.dtype.itemsize, byteorder='little', signed=value1.dtype.kind != 'u'))
        for x in range(len(b_data)):
            b_data[x] = net_emu_coretypes.DotNetUInt8(app_domain.get_emulator_obj(), b_data[x])
        dnr.set_internal_array(b_data)
        return dnr

cdef void blockcopy_helper(DotNetArray src, object srcOffset, DotNetArray dst, object dstOffset, object count) except *:
    cdef Py_ssize_t x
    for x in range(count):
        dst[dstOffset + x] = src[srcOffset + x]


cdef class DotNetBuffer(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def BlockCopy(app_domain, src, srcOffset, dst, dstOffset, count):
        if not isinstance(src, DotNetArray) or not isinstance(dst, DotNetArray):
            raise net_exceptions.ObjectTypeException
        blockcopy_helper(src, srcOffset, dst, dstOffset, count)

cdef class DotNetAppDomain(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def get_CurrentDomain(app_domain):
        return DotNetAppDomain(app_domain.get_emulator_obj())

    def add_AssemblyResolve(self, obj):
        self.get_emulator_obj().get_appdomain().add_assembly_handler(obj.get_method_obj())

    def add_ResourceResolve(self, obj):
        self.get_emulator_obj().get_appdomain().add_resource_handler(obj.get_method_obj())

cdef class DotNetResolveEventHandler(DotNetObject):
    def __init__(self, emulator_obj, arg1, arg2):
        DotNetObject.__init__(self, emulator_obj)
        self.__method_object = arg2

    cpdef net_row_objects.MethodDefOrRef get_method_obj(self):
        return self.__method_object

cdef class DotNetEncoding(DotNetObject):
    def __init__(self, emulator_obj, name):
        DotNetObject.__init__(self, emulator_obj)
        self.name = name

    @staticmethod
    def get_UTF8(app_domain):
        return DotNetEncoding(app_domain.get_emulator_obj(), 'utf-8')

    @staticmethod
    def get_Unicode(app_domain):
        return DotNetEncoding(app_domain.get_emulator_obj(), 'utf-16le')

    def GetString(self, data, index=0, count=-1):
        if isinstance(data, DotNetString):
            return data.Substring(index, index + count)
        if count >= 0:
            return DotNetString(self.get_emulator_obj(), data[index:index + count], self.name)
        else:
            return DotNetString(self.get_emulator_obj(), data[index:], self.name)

    def GetBytes(self, str_obj):
        if not isinstance(str_obj, DotNetString):
            raise net_exceptions.ObjectTypeException
        raw_bytes = str_obj.get_str_data_as_bytes().decode(str_obj.get_str_encoding()).encode(self.name)
        result = DotNetArray(self.get_emulator_obj(), len(raw_bytes),
                             self.get_emulator_obj().get_method_obj().get_dotnetpe().get_type_by_full_name(b'System.Byte'))
        for x in range(len(raw_bytes)):
            result[x] = net_emu_coretypes.DotNetInt8(self.get_emulator_obj(), raw_bytes[x])
        return result

cdef class DotNetString(DotNetObject):
    def __init__(self, emulator_obj, str_data, str_encoding='utf-16le'):
        DotNetObject.__init__(self, emulator_obj)
        self.str_encoding = str_encoding
        self.str_data = self.__sanitize_data(str_data)

    cpdef str get_str_data_as_str(self):
        return self.get_str_data_as_bytes().decode(self.get_str_encoding())
    
    cdef list __sanitize_data(self, str_data):
        """
        Prevent typing issues by forcing all str_data to be a list of uint8s.
        """
        cdef Py_ssize_t x
        cdef bint is_list_of_dtypes
        cdef list usable_data
        cdef object item
        cdef bytes b_data
        cdef bint skip_next_value
        if isinstance(str_data, DotNetArray) or isinstance(str_data, list) or isinstance(str_data, bytes) or isinstance(str_data, bytearray):
            usable_data = list()
            if isinstance(str_data, bytes) or isinstance(str_data, bytearray):
                #convert all bytes to net_emu_coretypes.DotNetChar or net_emu_coretypes.DotNetUInt8 according to encoding.
                if self.is_encoding_wide():
                    for x in range(0, len(str_data), 2):
                        item = net_emu_coretypes.DotNetChar(self.get_emulator_obj(), int.from_bytes(str_data[x:x+2], 'little', signed=True))
                        usable_data.append(item)
                else:
                    for x in range(len(str_data)):
                        item = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), str_data[x])
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
                    if not hasattr(item, 'dtype'):
                        raise net_exceptions.InvalidArgumentsException(type(item)) #its impossible to figure out whether its a list of int8s or uint8s for this really.
                    if self.is_encoding_wide():
                        if item.dtype.itemsize == 2:
                            usable_data.append(item)
                        else:
                            b_data = bytes([item.item(), str_data[x+1]])
                            usable_data.append(net_emu_coretypes.DotNetChar(self.get_emulator_obj(), int.from_bytes(b_data, 'little', signed=True)))
                            skip_next_value = True
                    else:
                        if item.dtype.itemsize == 2:
                            b_data = int.to_bytes(item.item(), byteorder='little', length=2, signed=item.dtype.kind != 'u')
                            usable_data.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), b_data[0]))
                            usable_data.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), b_data[1]))
                        else:
                            usable_data.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), item))
                return usable_data         
        else:
            raise net_exceptions.InvalidArgumentsException()

    cpdef bytes get_str_data_as_bytes(self):
        cdef bytearray result
        cdef object item
        cdef bytes b_data
        cdef Py_ssize_t x
        result = bytearray()
        for x in range(len(self.str_data)):
            item = self.str_data[x]
            if item.dtype.itemsize == 2:
                b_data = int.to_bytes(item.item(), byteorder='little', length=2, signed=item.dtype.kind != 'u')
                result += b_data
            else:
                result += bytes([item.item()])
        return bytes(result)

    cpdef list get_str_data(self):
        return self.str_data 

    cpdef str get_str_encoding(self):
        return self.str_encoding

    @staticmethod
    def Empty(app_domain):
        return DotNetString(app_domain.get_emulator_obj(), bytes(), 'utf-16le')

    @staticmethod
    def Intern(app_domain, str_obj):
        return str_obj

    @staticmethod
    def Concat(app_domain, array, arg2=None, arg3=None):
        if isinstance(array, DotNetNull):
            array = DotNetString.Empty(app_domain)
        if arg2 == None:
            if isinstance(array, DotNetArray):
                base_str = bytearray()
                base_encoding = ''
                for element in array.get_internal_array():
                    if not isinstance(element, DotNetString):
                        raise net_exceptions.ObjectTypeException
                    if base_encoding != '':
                        if not element.get_str_encoding() == base_encoding:
                            raise net_exceptions.EncodingMismatchException
                    else:
                        base_encoding = element.get_str_encoding()
                    base_str += element.get_str_data()
                return DotNetString(app_domain.get_emulator_obj(), base_str, base_encoding)

            else:
                raise net_exceptions.InvalidArgumentsException('DotNetArray', type(array))
        else:
            #3 objects calling convention
            if arg2 != None and arg3 != None:
                finished_str = DotNetString.Concat(app_domain, DotNetString.Concat(app_domain, array.ToString(), arg2.ToString()), arg3.ToString())
                return finished_str
            
            #I dont really like this, but it should work for now. FIXME - this could fail with weird parameters (non byte array)
            if isinstance(arg2, net_emu_coretypes.DotNetNumber) and (arg2.is_uint16() or arg2.is_int16()):
                result = DotNetString(app_domain.get_emulator_obj(), array.get_str_data() + [net_emu_coretypes.DotNetChar(app_domain.get_emulator_obj(), arg2)], array.get_str_encoding())
            elif isinstance(arg2, DotNetString):
                if not arg2.get_str_encoding() == array.get_str_encoding():
                    raise net_exceptions.EncodingMismatchException
                result = DotNetString(app_domain.get_emulator_obj(), array.get_str_data() + arg2.get_str_data(), array.get_str_encoding())
            elif isinstance(arg2, net_emu_coretypes.DotNetChar):
                result = DotNetString.Concat(app_domain, array, arg2.ToString())
            else:
                raise net_exceptions.InvalidArgumentsException(type(arg2))
            return result

    cpdef object IndexOf(self, object char_val):
        cdef Py_ssize_t x
        for x in range(len(self.get_str_data())):
            item = self.str_data[x]
            if item == char_val:
                return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), x)
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), -1)
    
    def StartsWith(self, string):
        if self.get_str_data_as_bytes().startswith(string.get_str_data_as_bytes()):
            return net_emu_coretypes.DotNetBoolean(self.get_emulator_obj(), True)
        return net_emu_coretypes.DotNetBoolean(self.get_emulator_obj(), False)

    def Replace(self, old_char, new_char):
        if not self.get_str_encoding() == old_char.get_str_encoding() == new_char.get_str_encoding():
            raise net_exceptions.EncodingMismatchException

        new_str_data = self.get_str_data_as_bytes().replace(old_char.get_str_data_as_bytes(), new_char.get_str_data_as_bytes())
        return DotNetString(self.get_emulator_obj(), new_str_data, self.get_str_encoding())

    def get_Length(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), len(self.get_str_data()))

    cpdef bint is_encoding_wide(self):
        cdef str str_encoding
        str_encoding = self.get_str_encoding()
        if str_encoding == 'ascii' or str_encoding == 'utf-8':
            return False
        return True

    def EndsWith(self, param1):
        return self.get_str_data_as_bytes().endswith(param1.get_str_data_as_bytes())

    def __len__(self):
        return self.get_Length()

    def get_Chars(self, index):
        return self.str_data[index]

    def Substring(self, start, stop=-1):

        start_index = start
        if stop == -1:
            end_index = len(self.get_str_data())
        else:
            end_index = stop

        return DotNetString(self.get_emulator_obj(), self.get_str_data()[start_index:end_index], self.get_str_encoding())

    def Split(self, char_array):
        if not isinstance(char_array, DotNetArray):
            raise net_exceptions.ObjectTypeException

        #first get the result in terms of python
        #assume utf-16le for now
        if not self.get_str_encoding() == 'utf-16le':
            raise net_exceptions.EncodingMismatchException

        python_data = self.get_str_data_as_bytes()

        split_by = bytearray()
        for item in char_array.get_internal_array():
            b_data = int.to_bytes(item.item(), length=item.dtype.itemsize, byteorder='little', signed=item.dtype.kind != 'u')
            split_by += b_data

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
    def op_Equality(app_domain, obj1, obj2):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), obj1 == obj2)

    def __str__(self):
        return 'string={}, encoding={}, hexlified={}, decoded={}'.format(self.get_str_data().__str__()[:50], self.get_str_encoding(), binascii.hexlify(self.get_str_data_as_bytes())[:50], self.get_str_data_as_bytes().decode(self.get_str_encoding(), errors='ignore')[:50])

    def ToString(self):
        return self

    def __hash__(self):
        full_val = bytes(self.get_str_data_as_bytes() + self.get_str_encoding().encode('ascii'))
        return hash(full_val)

cdef class DotNetModule(DotNetObject):
    def __init__(self, emulator_obj, internal_module):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_module = internal_module

    def get_ModuleHandle(self):
        return DotNetModuleHandle(self.get_emulator_obj(), self.internal_module)

    def ResolveMethod(self, method_token):
        return DotNetMethodBase(self.get_emulator_obj(), self.internal_module.get_dotnetpe().get_token_value(method_token))

    def ResolveType(self, type_token):
        return DotNetType(self.get_emulator_obj(), self.internal_module.get_dotnetpe().get_token_value(type_token))

    def ResolveField(self, field_token):
        return DotNetFieldInfo(self.get_emulator_obj(), self.internal_module.get_dotnetpe().get_token_value(field_token))

cdef class DotNetModuleHandle(DotNetObject):
    def __init__(self, emulator_obj, internal_module):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_module = internal_module

    def ResolveTypeHandle(self, type_token):
        if isinstance(self, ArrayAddress):
            usable_ref = self.get_obj_ref()
        else:
            usable_ref = self
        tdef = self.get_dotnetpe().get_token_value(type_token)
        return DotNetRuntimeTypeHandle(self.get_emulator_obj(), tdef)

    def ResolveMethodHandle(self, method_token):
        tdef = self.get_dotnetpe().get_token_value(method_token)
        return DotNetRuntimeMethodHandle(self.get_emulator_obj(), tdef)

    def GetRuntimeTypeHandleFromMetadataToken(self, value1):
        tdef = self.get_dotnetpe().get_token_value(value1)
        return DotNetRuntimeTypeHandle(tdef)

cdef class DotNetRuntimeTypeHandle(DotNetObject):
    def __init__(self, emulator_obj, internal_typedef):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_typedef = internal_typedef

    cpdef get_internal_typedef(self):
        return self.internal_typedef

    def __str__(self):
        return 'DotNetRuntimeTypeHandle: {}-{} - {}'.format(self.internal_typedef.get_table_name(), self.internal_typedef.get_rid(),
                                                            self.internal_typedef.get_full_name())

cdef class DotNetRuntimeMethodHandle(DotNetObject):
    def __init__(self, emulator_obj, internal_method):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_method = internal_method

cdef class DotNetFieldInfo(DotNetObject):
    def __init__(self, emulator_obj, internal_field):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_field = internal_field

    def get_FieldType(self):
        type_obj = DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(
            self.internal_field.get_parent_type()))
        return type_obj

    def SetValue(self, obj, value_obj):
        if self.internal_field.is_static():
            self.get_emulator_obj().set_static_field(self.internal_field.get_rid(), value_obj)
        else:
            obj.set_field(self.internal_field.get_rid(), value_obj)

    def get_Name(self):
        return DotNetString(self.get_emulator_obj(), self.internal_field['Name'].get_value(), 'ascii')

    def __str__(self):
        return 'DotNetFieldInfo: Field-{}, {}'.format(self.internal_field.get_rid(), self.internal_field['Name'].get_value())

cdef class DotNetMethodInfo(DotNetMethodBase):
    def __init__(self, emulator_obj, internal_method):
        DotNetMethodBase.__init__(self, emulator_obj, internal_method)

    def get_ReturnType(self):
        return_sig = self.internal_method.get_method_signature().get_return_type()

        if isinstance(return_sig, net_utils.CorLibTypeSig):
            type_name = get_cor_type_name(return_sig.get_element_type())
            type_obj = self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(type_name)
            if type_name and not type_obj:
                type_obj = NameOnlyTypeRef(type_name)
            return DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(type_obj))
        else:
            if isinstance(return_sig, net_utils.TypeDefOrRefSig) and return_sig.get_type() is not None:
                return DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(return_sig.get_type()))
        raise net_exceptions.OperationNotSupportedException()

    def __str__(self):
        return 'DotNetMethodInfo: {}:{} Name:{}'.format(self.internal_method.get_table_name(), self.internal_method.get_rid(),
                                                        self.internal_method.get_full_name())

cdef class DotNetParameterInfo(DotNetObject):
    def __init__(self, emulator_obj, internal_param):
        DotNetObject.__init__(self, emulator_obj)
        self.internal_param = internal_param

    def get_ParameterType(self):
        if isinstance(self.internal_param, net_utils.CorLibTypeSig):
            type_name = get_cor_type_name(self.internal_param.get_element_type())
            return DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(type_name)), self.internal_param)
        elif isinstance(self.internal_param, net_utils.SZArraySig):
            return DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Array')), self.internal_param) #NOTE: this might not account for generics.
        elif isinstance(self.internal_param, net_utils.ClassSig):
            return DotNetType(self.get_emulator_obj(), DotNetRuntimeTypeHandle(self.internal_param.get_type()), self.internal_param)
        raise net_exceptions.OperationNotSupportedException()

cdef class DotNetMethodBase(DotNetMemberInfo):
    def __init__(self, emulator_obj, internal_method):
        DotNetMemberInfo.__init__(self, emulator_obj, internal_method)

    @staticmethod
    def GetMethodFromHandle(app_domain, method_handle):
        return DotNetMethodInfo(app_domain.get_emulator_obj(), method_handle.internal_method)

    def get_IsStatic(self):
        # TODO: does this work?
        return not self.internal_method.method_has_this()

    def GetParameters(self):
        param_list = self.internal_method.get_param_types()
        result = DotNetArray(self.get_emulator_obj(), len(param_list),
                             self.internal_method.get_dotnetpe().get_type_by_full_name(b'System.Reflection.ParameterInfo'))
        for x in range(len(param_list)):
            result[x] = DotNetParameterInfo(self.get_emulator_obj(), param_list[x])
        return result

    @staticmethod
    def op_Equality(app_domain, obj1, obj2):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), obj1 == obj2)

    @staticmethod
    def op_Inequality(app_domain, obj1, obj2):
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), obj1 != obj2)

cdef class DotNetDelegate(DotNetObject):
    def __init__(self, emulator_obj, dn_type, dn_methodinfo):
        DotNetObject.__init__(self, emulator_obj)
        if not isinstance(dn_type, DotNetNull):
            self.dn_type = dn_type
        else:
            self.dn_type = None
        if isinstance(dn_methodinfo, DotNetMethodInfo):
            self.dn_methodinfo = dn_methodinfo
        else:
            self.dn_methodinfo = DotNetMethodInfo(emulator_obj, dn_methodinfo)

    @staticmethod
    def CreateDelegate(app_domain, dotnet_type, dotnet_methodinfo):
        del_obj = DotNetDelegate(app_domain.get_emulator_obj(), dotnet_type.get_emulator_obj(), dotnet_type, dotnet_methodinfo)
        return del_obj

    #TODO: can this be optimized?
    def Invoke(self, *method_args):
        if isinstance(self.dn_methodinfo, DotNetDynamicMethod):
            method_obj = self.dn_methodinfo
        else:
            method_obj = self.dn_methodinfo.internal_method
        # well guess im basically copying the code from the call instruction on this one.
        if isinstance(method_obj, net_row_objects.MethodDef) or isinstance(method_obj, DotNetDynamicMethod):
            if isinstance(method_obj, net_row_objects.MethodDef):
                cctor_method = method_obj.get_parent_type().get_cctor_method()
                if isinstance(cctor_method,
                              net_row_objects.MethodDef) and self.get_emulator_obj().get_executed_cctors().can_execute(
                    cctor_method):
                    new_emu = self.get_emulator_obj().spawn_new_emulator(
                        cctor_method, method_params=method_args, start_offset=0, caller=None, end_offset=-1, end_method_rid=0, end_eip=-1)
                    new_emu.run_function()
            new_emu = self.get_emulator_obj().spawn_new_emulator(
                method_obj, start_offset=0, method_params=method_args, caller=None, end_offset=-1, end_method_rid=0, end_eip=-1)
            new_emu.run_function()
            if method_obj.has_return_value():
                return new_emu.stack.pop()
            # the handler for ret instruction handles cleaning up the stack after this.
        elif isinstance(method_obj, net_row_objects.MemberRef):
            type_full_name = remove_generics_from_name(method_obj.get_parent_type().get_full_name().decode('ascii'))
            method_name = method_obj['Name'].get_value().decode('ascii')
            if type_full_name not in NET_EMULATE_TYPE_REGISTRATIONS:
                raise net_exceptions.EmulatorTypeNotFoundException(
                    type_full_name)

            emulated_type = NET_EMULATE_TYPE_REGISTRATIONS[type_full_name]
            emu_method = None
            if method_name == '.ctor':
                emu_method = emulated_type
            else:
                emu_method = None
                if hasattr(emulated_type, method_name):
                    emu_method = getattr(emulated_type, method_name)
                else:
                    raise net_exceptions.EmulatorMethodNotFoundException(
                        method_obj.get_full_name())

            if not emu_method:
                raise net_exceptions.OperationNotSupportedException
            actual_method_args = list(method_args)
            if method_obj.is_static_method():
                actual_method_args.insert(0, self.get_emulator_obj().get_appdomain())
            ret_val = emu_method(*actual_method_args)

            if method_obj.has_return_value():
                return ret_val
        else:
            raise net_exceptions.OperationNotSupportedException()

    def __str__(self):
        if isinstance(self.dn_methodinfo, DotNetDynamicMethod):
            return 'Delegate: DynamicMethod'
        else:
            return 'Delegate: {}'.format(self.dn_methodinfo.internal_method.get_full_name())

cdef class DotNetMulticastDelegate(DotNetDelegate):
    def __init__(self, emulator_obj, dn_type, dn_methodinfo):
        DotNetDelegate.__init__(self, emulator_obj, dn_type, dn_methodinfo)

cdef class DotNetConvert(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def ToInt32(app_domain, string):
        if isinstance(string, bytes) or isinstance(string, bytearray):
            result = net_emu_coretypes.DotNetInt32(app_domain.get_emulator_obj(), int(string.decode('utf-16le')))
            return result
        else:
            result = net_emu_coretypes.DotNetInt32(app_domain.get_emulator_obj(), string)
            return result

    @staticmethod
    def FromBase64String(app_domain, string):
        str_data = string.get_str_data_as_bytes()
        new_str_data = base64.b64decode(bytes(str_data))
        dnarray = DotNetArray(app_domain.get_emulator_obj(), len(new_str_data), DotNetAssembly.GetExecutingAssembly(app_domain).get_module().get_dotnetpe().get_type_by_full_name(
            b'System.Byte'), initialize=False)
        int_array = list()
        for x in range(len(new_str_data)):
            int_array.append(net_emu_coretypes.DotNetUInt8(app_domain.get_emulator_obj(), new_str_data[x]))
        dnarray.set_internal_array(int_array)
        return dnarray

    @staticmethod
    def ToChar(app_domain, value1):
        return net_emu_coretypes.DotNetUInt16(app_domain.get_emulator_obj(), value1)


cdef class DotNetOpCode(DotNetObject):
    def __init__(self, emulator_obj, stringname, pop, push, operand, op_type, size, s1, s2, ctrl, endsjmpblk, stack):
        DotNetObject.__init__(self, emulator_obj)
        self.stringname = stringname
        self.pop = pop
        self.push = push
        self.operand = operand
        self.op_type = op_type
        self.size = size
        self.s1 = s1
        self.s2 = s2
        self.ctrl = ctrl
        self.endsjmpblk = endsjmpblk
        self.stack = stack

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

    @staticmethod
    def Nop(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "nop", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                        DotNetOpCodeType.Primitive, 1, 255, 0, DotNetFlowControl.Next, False, 0)
    
    @staticmethod
    def Break(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "break", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                         DotNetOpCodeType.Primitive, 1, 255, 1, DotNetFlowControl.Break, False, 0)

    @staticmethod
    def Ldarg_0(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.0", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 2, DotNetFlowControl.Next,
                           False, 1)
    
    @staticmethod
    def Ldarg_1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 3, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    def Ldarg_2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 4, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    def Ldarg_3(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 5, DotNetFlowControl.Next,
                           False, 1)
    @staticmethod
    def Ldloc_0(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.0", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 6, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    def Ldloc_1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 7, DotNetFlowControl.Next,
                           False, 1)
    @staticmethod
    def Ldloc_2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 8, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    def Ldloc_3(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 9, DotNetFlowControl.Next,
                           False, 1)

    @staticmethod
    def Stloc_0(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.0", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xA, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    def Stloc_1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xB, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    def Stloc_2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xC, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    def Stloc_3(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.3", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0xD, DotNetFlowControl.Next,
                           False, -1)
    @staticmethod
    def Ldarg_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0xE,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldarga_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarga.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0xF,
                            DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Starg_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "starg.s", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x10,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldloc_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x11,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldloca_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloca.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x12,
                            DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Stloc_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc.s", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                           DotNetOperandType.ShortInlineVar, DotNetOpCodeType.Macro, 1, 255, 0x13,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldnull(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldnull", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushref,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x14,
                          DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldc_I4_M1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.m1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x15, DotNetFlowControl.Next,
                             False, 1)
    @staticmethod
    def Ldc_I4_0(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.0", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x16, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x17, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x18, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_3(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x19, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1A, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_5(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.5", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1B, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_6(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.6", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1C, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_7(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.7", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1D, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.8", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Macro, 1, 255, 0x1E, DotNetFlowControl.Next,
                            False, 1)
    @staticmethod
    def Ldc_I4_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.ShortInlineI, DotNetOpCodeType.Macro, 1, 255, 0x1F,
                            DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldc_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineI,
                          DotNetOpCodeType.Primitive, 1, 255, 0x20, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldc_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.i8", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi8, DotNetOperandType.InlineI8,
                          DotNetOpCodeType.Primitive, 1, 255, 0x21, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldc_R4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.r4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushr4,
                          DotNetOperandType.ShortInlineR, DotNetOpCodeType.Primitive, 1, 255, 0x22,
                          DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldc_R8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldc.r8", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushr8, DotNetOperandType.InlineR,
                          DotNetOpCodeType.Primitive, 1, 255, 0x23, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Dup(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "dup", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push1_push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x25, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Pop(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "pop", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x26, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Jmp(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "jmp", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineMethod,
                       DotNetOpCodeType.Primitive, 1, 255, 0x27, DotNetFlowControl.Call, True, 0)
    @staticmethod
    def Call(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "call", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Varpush,
                        DotNetOperandType.InlineMethod, DotNetOpCodeType.Primitive, 1, 255, 0x28,
                        DotNetFlowControl.Call, False, 0)
    @staticmethod
    def Calli(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "calli", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Varpush,
                         DotNetOperandType.InlineSig, DotNetOpCodeType.Primitive, 1, 255, 0x29, DotNetFlowControl.Call,
                         False, 0)
    @staticmethod
    def Ret(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ret", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x2A, DotNetFlowControl.Return, True, 0)
    @staticmethod
    def Br_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "br.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                        DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2B,
                        DotNetFlowControl.Branch, True, 0)
    @staticmethod
    def BrFalse_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brFalse.s", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2C,
                             DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    def BrTrue_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brTrue.s", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2D,
                            DotNetFlowControl.Cond_Branch, False, -1)

    @staticmethod
    def Beq_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "beq.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2E,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bge_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x2F,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bgt_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x30,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Ble_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x31,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Blt_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x32,
                         DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bne_Un_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bne.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x33,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bge_Un_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x34,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bgt_Un_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x35,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Ble_Un_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x36,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Blt_Un_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt.un.s", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                            DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x37,
                            DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Br(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "br", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0, DotNetOperandType.InlineBrTarget,
                      DotNetOpCodeType.Primitive, 1, 255, 0x38, DotNetFlowControl.Branch, True, 0)
    @staticmethod
    def BrFalse(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brFalse", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0x39,
                           DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    def BrTrue(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "brTrue", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0x3A,
                          DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    def Beq(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "beq", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3B,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bge(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3C,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bgt(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3D,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Ble(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3E,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Blt(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                       DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x3F,
                       DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bne_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bne.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x40,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bge_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bge.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x41,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Bgt_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "bgt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x42,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Ble_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ble.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x43,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Blt_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "blt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Macro, 1, 255, 0x44,
                          DotNetFlowControl.Cond_Branch, False, -2)
    @staticmethod
    def Switch(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "switch", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineSwitch, DotNetOpCodeType.Primitive, 1, 255, 0x45,
                          DotNetFlowControl.Cond_Branch, False, -1)
    @staticmethod
    def Ldind_I1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i1", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x46,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_U1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.u1", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x47,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_I2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i2", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x48,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_U2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.u2", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x49,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i4", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4A,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_U4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.u4", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4B,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i8", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi8,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4C,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_I(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.i", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4D,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_R4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.r4", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushr4,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4E,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_R8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.r8", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushr8,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x4F,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldind_Ref(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldind.ref", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushref,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x50,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Stind_Ref(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.ref", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x51,
                             DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Stind_I1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i1", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x52,
                            DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Stind_I2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i2", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x53,
                            DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Stind_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i4", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x54,
                            DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Stind_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i8", DotNetStackBehaviour.Popi_popi8, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x55,
                            DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Stind_R4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.r4", DotNetStackBehaviour.Popi_popr4, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x56,
                            DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Stind_R8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.r8", DotNetStackBehaviour.Popi_popr8, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x57,
                            DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Add(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "add", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x58, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Sub(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sub", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x59, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Mul(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mul", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5A, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Div(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "div", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5B, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Div_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "div.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x5C,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Rem(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "rem", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5D, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Rem_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "rem.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x5E,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    def And(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "and", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x5F, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Or(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "or", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                      DotNetOpCodeType.Primitive, 1, 255, 0x60, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Xor(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "xor", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x61, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Shl(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "shl", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x62, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Shr(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "shr", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x63, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Shr_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "shr.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x64,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Neg(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "neg", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x65, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Not(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "not", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push1, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 1, 255, 0x66, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_I1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x67,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_I2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x68,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x69,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6A,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_R4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.r4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr4,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6B,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_R8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.r8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr8,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6C,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_U4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6D,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_U8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x6E,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Callvirt(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "callvirt", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Varpush,
                            DotNetOperandType.InlineMethod, DotNetOpCodeType.Objmodel, 1, 255, 0x6F,
                            DotNetFlowControl.Call, False, 0)
    @staticmethod
    def Cpobj(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cpobj", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x70, DotNetFlowControl.Next,
                         False, -2)
    @staticmethod
    def Ldobj(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldobj", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push1, DotNetOperandType.InlineType,
                         DotNetOpCodeType.Objmodel, 1, 255, 0x71, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldstr(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldstr", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushref,
                         DotNetOperandType.InlineString, DotNetOpCodeType.Objmodel, 1, 255, 0x72,
                         DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Newobj(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "newobj", DotNetStackBehaviour.Varpop, DotNetStackBehaviour.Pushref,
                          DotNetOperandType.InlineMethod, DotNetOpCodeType.Objmodel, 1, 255, 0x73,
                          DotNetFlowControl.Call, False, 1)
    @staticmethod
    def Castclass(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "castclass", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushref,
                             DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x74,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Isinst(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "isinst", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x75, DotNetFlowControl.Next,
                          False, 0)
    @staticmethod
    def Conv_R_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.r.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr8,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x76,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Unbox(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "unbox", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineType,
                         DotNetOpCodeType.Primitive, 1, 255, 0x79, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Throw(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "throw", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Push0, DotNetOperandType.InlineNone,
                         DotNetOpCodeType.Objmodel, 1, 255, 0x7A, DotNetFlowControl.Throw, True, -1)
    @staticmethod
    def Ldfld(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldfld", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Push1,
                         DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7B, DotNetFlowControl.Next,
                         False, 0)
    @staticmethod
    def Ldflda(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldflda", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7C,
                          DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Stfld(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stfld", DotNetStackBehaviour.Popref_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7D, DotNetFlowControl.Next,
                         False, -2)
    @staticmethod
    def Ldsfld(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldsfld", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7E,
                          DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldsflda(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldsflda", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x7F,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Stsfld(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stsfld", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineField, DotNetOpCodeType.Objmodel, 1, 255, 0x80,
                          DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Stobj(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stobj", DotNetStackBehaviour.Popi_pop1, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineType, DotNetOpCodeType.Primitive, 1, 255, 0x81, DotNetFlowControl.Next,
                         False, -2)
    @staticmethod
    def Conv_Ovf_I1_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i1.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x82,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I2_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i2.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x83,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I4_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i4.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x84,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I8_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i8.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x85,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U1_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u1.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x86,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U2_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u2.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x87,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U4_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u4.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x88,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U8_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u8.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                                  DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x89,
                                  DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                 DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x8A,
                                 DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u.un", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                                 DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0x8B,
                                 DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Box(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "box", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushref, DotNetOperandType.InlineType,
                       DotNetOpCodeType.Primitive, 1, 255, 0x8C, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Newarr(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "newarr", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushref,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x8D, DotNetFlowControl.Next,
                          False, 0)
    @staticmethod
    def Ldlen(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldlen", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                         DotNetOpCodeType.Objmodel, 1, 255, 0x8E, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldelema(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelema", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0x8F,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_I1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i1", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x90,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_U1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.u1", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x91,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_I2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i2", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x92,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_U2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.u2", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x93,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i4", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x94,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_U4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.u4", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x95,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i8", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi8,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x96,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_I(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.i", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x97,
                            DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_R4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.r4", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushr4,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x98,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_R8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.r8", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushr8,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x99,
                             DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldelem_Ref(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem.ref", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Pushref,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9A,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Stelem_I(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9B,
                            DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_I1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i1", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9C,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_I2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i2", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9D,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i4", DotNetStackBehaviour.Popref_popi_popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9E,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.i8", DotNetStackBehaviour.Popref_popi_popi8, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0x9F,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_R4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.r4", DotNetStackBehaviour.Popref_popi_popr4, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0xA0,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_R8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.r8", DotNetStackBehaviour.Popref_popi_popr8, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0xA1,
                             DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Stelem_Ref(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem.ref", DotNetStackBehaviour.Popref_popi_popref, DotNetStackBehaviour.Push0,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 1, 255, 0xA2,
                              DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Ldelem(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldelem", DotNetStackBehaviour.Popref_popi, DotNetStackBehaviour.Push1,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0xA3, DotNetFlowControl.Next,
                          False, -1)
    @staticmethod
    def Stelem(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stelem", DotNetStackBehaviour.Popref_popi_pop1, DotNetStackBehaviour.Push0,
                          DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0xA4, DotNetFlowControl.Next,
                          False, 0)
    @staticmethod
    def Unbox_Any(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "unbox.any", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Push1,
                             DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 1, 255, 0xA5,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB3,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB4,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB5,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB6,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB7,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u4", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB8,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xB9,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U8(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u8", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi8,
                               DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xBA,
                               DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Refanyval(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "refanyval", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineType, DotNetOpCodeType.Primitive, 1, 255, 0xC2,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ckfinite(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ckfinite", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushr8,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xC3,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Mkrefany(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mkrefany", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push1,
                            DotNetOperandType.InlineType, DotNetOpCodeType.Primitive, 1, 255, 0xC6,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldtoken(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldtoken", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineTok, DotNetOpCodeType.Primitive, 1, 255, 0xD0,
                           DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Conv_U2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u2", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD1,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_U1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u1", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD2,
                           DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_I(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.i", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                          DotNetOpCodeType.Primitive, 1, 255, 0xD3, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_I(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.i", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD4,
                              DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Conv_Ovf_U(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.ovf.u", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD5,
                              DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Add_Ovf(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "add.ovf", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD6,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Add_Ovf_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "add.ovf.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD7,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Mul_Ovf(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mul.ovf", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD8,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Mul_Ovf_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "mul.ovf.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xD9,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Sub_Ovf(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sub.ovf", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDA,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Sub_Ovf_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sub.ovf.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Push1,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDB,
                              DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Endfinally(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "endfinally", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDC,
                              DotNetFlowControl.Return, True, 0)
    @staticmethod
    def Leave(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "leave", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0xDD,
                         DotNetFlowControl.Branch, True, 0)
    @staticmethod
    def Leave_S(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "leave.s", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.ShortInlineBrTarget, DotNetOpCodeType.Primitive, 1, 255, 0xDE,
                           DotNetFlowControl.Branch, True, 0)
    @staticmethod
    def Stind_I(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stind.i", DotNetStackBehaviour.Popi_popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 1, 255, 0xDF,
                           DotNetFlowControl.Next, False, -2)
    @staticmethod
    def Conv_U(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "conv.u", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                          DotNetOpCodeType.Primitive, 1, 255, 0xE0, DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Prefix7(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix7", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xF8, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefix6(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix6", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xF9, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefix5(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix5", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFA, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefix4(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix4", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFB, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefix3(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix3", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFC, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefix2(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix2", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFD, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefix1(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefix1", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 0xFE, DotNetFlowControl.Meta,
                           False, 0)
    @staticmethod
    def Prefixref(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "prefixref", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Nternal, 1, 255, 255,
                             DotNetFlowControl.Meta, False, 0)
    @staticmethod
    def Arglist(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "arglist", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0, DotNetFlowControl.Next,
                           False, 1)
    @staticmethod
    def Ceq(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ceq", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 2, 0xFE, 1, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Cgt(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cgt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 2, 0xFE, 2, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Cgt_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cgt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 3, DotNetFlowControl.Next,
                          False, -1)
    @staticmethod
    def Clt(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "clt", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineNone,
                       DotNetOpCodeType.Primitive, 2, 0xFE, 4, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Clt_Un(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "clt.un", DotNetStackBehaviour.Pop1_pop1, DotNetStackBehaviour.Pushi,
                          DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 5, DotNetFlowControl.Next,
                          False, -1)
    @staticmethod
    def Ldftn(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldftn", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineMethod,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 6, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldvirtftn(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldvirtftn", DotNetStackBehaviour.Popref, DotNetStackBehaviour.Pushi,
                             DotNetOperandType.InlineMethod, DotNetOpCodeType.Primitive, 2, 0xFE, 7,
                             DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Ldarg(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarg", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 9, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldarga(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldarga", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineVar,
                          DotNetOpCodeType.Primitive, 2, 0xFE, 0xA, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Starg(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "starg", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 0xB, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Ldloc(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloc", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push1, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 0xC, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Ldloca(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "ldloca", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineVar,
                          DotNetOpCodeType.Primitive, 2, 0xFE, 0xD, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Stloc(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "stloc", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Push0, DotNetOperandType.InlineVar,
                         DotNetOpCodeType.Primitive, 2, 0xFE, 0xE, DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Localloc(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "localloc", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Pushi,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0xF,
                            DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Endfilter(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "endfilter", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                             DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x11,
                             DotNetFlowControl.Return, True, -1)
    @staticmethod
    def Unaligned(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "unaligned.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                             DotNetOperandType.ShortInlineI, DotNetOpCodeType.Prefix, 2, 0xFE, 0x12,
                             DotNetFlowControl.Meta, False, 0)
    @staticmethod
    def Volatile(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "volatile.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Prefix, 2, 0xFE, 0x13,
                            DotNetFlowControl.Meta, False, 0)
    @staticmethod
    def Tailcall(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "tail.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Prefix, 2, 0xFE, 0x14,
                            DotNetFlowControl.Meta, False, 0)
    @staticmethod
    def Initobj(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "initobj", DotNetStackBehaviour.Popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineType, DotNetOpCodeType.Objmodel, 2, 0xFE, 0x15,
                           DotNetFlowControl.Next, False, -1)
    @staticmethod
    def Constrained(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "constrained.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                               DotNetOperandType.InlineType, DotNetOpCodeType.Prefix, 2, 0xFE, 0x16,
                               DotNetFlowControl.Meta, False, 0)
    @staticmethod
    def Cpblk(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "cpblk", DotNetStackBehaviour.Popi_popi_popi, DotNetStackBehaviour.Push0,
                         DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x17,
                         DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Initblk(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "initblk", DotNetStackBehaviour.Popi_popi_popi, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x18,
                           DotNetFlowControl.Next, False, -3)
    @staticmethod
    def Rethrow(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "rethrow", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                           DotNetOperandType.InlineNone, DotNetOpCodeType.Objmodel, 2, 0xFE, 0x1A,
                           DotNetFlowControl.Throw, True, 0)
    @staticmethod
    def Sizeof(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "sizeof", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Pushi, DotNetOperandType.InlineType,
                          DotNetOpCodeType.Primitive, 2, 0xFE, 0x1C, DotNetFlowControl.Next, False, 1)
    @staticmethod
    def Refanytype(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "refanytype", DotNetStackBehaviour.Pop1, DotNetStackBehaviour.Pushi,
                              DotNetOperandType.InlineNone, DotNetOpCodeType.Primitive, 2, 0xFE, 0x1D,
                              DotNetFlowControl.Next, False, 0)
    @staticmethod
    def Readonly(app_domain):
        return DotNetOpCode(app_domain.get_emulator_obj(), "readonly.", DotNetStackBehaviour.Pop0, DotNetStackBehaviour.Push0,
                            DotNetOperandType.InlineNone, DotNetOpCodeType.Prefix, 2, 0xFE, 0x1E,
                            DotNetFlowControl.Meta, False, 0)

    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def TakesSingleByteArgument(app_domain, opcode):
        if opcode.operand == DotNetOperandType.ShortInlineBrTarget:
            return True
        elif opcode.operand == DotNetOperandType.ShortInlineI:
            return True
        elif opcode.operand == DotNetOperandType.ShortInlineVar:
            return True
        return False

cdef class DotNetILGenerator(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.method_body = bytes()

    cpdef __internal_emit_noargs(self, opcode):
        if opcode.size == 1:
            self.method_body += bytes([opcode.s2])
        else:
            self.method_body += bytes([opcode.s1, opcode.s2])

    cpdef __internal_emit_call(self, opcode, method_obj):
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
    def Emit(self, *args):
        opcode = args[0]
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
            self.__internal_emit_call(opcode, *other_stuff)
        elif opcode == DotNetOpCodes.Call:
            self.__internal_emit_call(opcode, *other_stuff)
        elif opcode == DotNetOpCodes.Ret:
            self.__internal_emit_noargs(opcode)
        else:
            raise net_exceptions.OperationNotSupportedException()


cdef class NameOnlyTypeRef():
    def __init__(self, name):
        self.name = name

    cpdef get_full_name(self):
        return self.name


cdef class DotNetDynamicMethod(DotNetObject):
    def __init__(self, emulator_obj, name, return_type, parameter_types, owner, skip_visibility):
        DotNetObject.__init__(self, emulator_obj)
        self.name = name
        self.return_type = return_type
        self.parameter_types = parameter_types
        self.skip_visibility = skip_visibility
        self.il_generator = DotNetILGenerator(self.get_emulator_obj())
        self.parent_type = owner
        self.sig_obj = None
        self.static = True
        # FIXME: technically this can have a cctor?

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
            return_sig = net_utils.TypeDefOrRefSig(None, typedef_obj)
        param_sigs = list()
        for param in self.parameter_types:
            ptype_obj = param.get_type_handle()
            param_sig = get_cor_type_from_name(ptype_obj.get_full_name())
            if not param_sig:
                param_sig = net_utils.TypeDefOrRefSig(None, ptype_obj)
            param_sigs.append(param_sig)
        self.sig_obj = net_utils.MethodSig(net_structs.CallingConvention_Default, bytes(), None, param_sigs, 0, 0, 0,
                                           return_sig)
        return self.sig_obj

    cpdef method_has_this(self):
        return False

    cpdef is_static(self):
        return self.static

    cpdef has_return_value(self):
        type_obj = self.return_type.get_type_handle()
        return type_obj.get_full_name() != b'System.Void'


cdef class DotNetIntPtr(DotNetObject):
    def __init__(self, emulator_obj, _value):
        DotNetObject.__init__(self, emulator_obj)
        self.value = _value

    @staticmethod
    def Zero(app_domain):
        return DotNetIntPtr(app_domain.get_emulator_obj(), net_emu_coretypes.DotNetInt32(app_domain.get_emulator_obj(), 0))


cdef class DotNetSortedList(DotNetList):
    pass


cdef class DotNetHashTable(DotNetConcurrentDictionary):
    def __init__(self, emulator_obj):
        DotNetConcurrentDictionary.__init__(self, emulator_obj)


cdef class DotNetRSACryptoServiceProvider(DotNetObject):
    use_machine_key_store = False

    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def set_UseMachineKeyStore(app_domain, new_val):
        use_machine_key_store = new_val


cdef class DotNetBinaryReader(DotNetObject):
    def __init__(self, emulator_obj, stream):
        if not (isinstance(stream, DotNetStream) or isinstance(stream, DotNetMemoryStream)):
            raise net_exceptions.ObjectTypeException
        DotNetObject.__init__(self, emulator_obj)
        self.stream = stream

    def get_BaseStream(self):
        return self.stream

    def ReadBytes(self, count):
        return self.stream.ReadBytes(count)

    def ReadByte(self):
        return self.stream.ReadByte()

    def Close(self):
        self.stream.Close()


cdef class DotNetMarshal(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def ReadIntPtr(app_domain, intptr, offset):
        if isinstance(intptr, DotNetIntPtr):
            return intptr.value
        raise Exception()

    @staticmethod
    def ReadInt32(app_domain, intptr, offset):
        if isinstance(intptr, DotNetIntPtr):
            if offset == 0:
                return net_emu_coretypes.DotNetInt32(app_domain.get_emulator_obj(), 0)
        raise Exception()

    @staticmethod
    def ReadInt64(app_domain, intptr, offset):
        if isinstance(intptr, DotNetIntPtr):
            if offset == 0:
                return net_emu_coretypes.DotNetInt64(app_domain.get_emulator_obj(), 0)
        raise Exception()

    @staticmethod
    def WriteIntPtr(app_domain, obj1, obj2, obj3):
        if obj3.value == 0:
            return
        raise Exception()

    @staticmethod
    def WriteInt32(app_domain, obj1, obj2, obj3):
        if obj3 == 0:
            return
        raise Exception()

    @staticmethod
    def WriteInt64(app_domain, obj1, obj2, obj3):
        if obj3 == 0:
            return
        raise Exception()


cdef class DotNetGCHandle(DotNetObject):
    def __init__(self, emulator_obj, target, _type=None):
        DotNetObject.__init__(self, emulator_obj)
        self.__target = target
        self.__type = _type

    def get_Target(self):
        ref = self
        if isinstance(ref, ArrayAddress):
            ref = ref.get_obj_ref()
        return ref.__target

    @staticmethod
    def Alloc(app_domain, target, _type=None):
        return DotNetGCHandle(app_domain.get_emulator_obj(), target, _type)

cdef class DotNetWaitCallback(DotNetObject):
    def __init__(self, emulator_obj, _object, method_object):
        DotNetObject.__init__(self, emulator_obj)
        self.__method_object = method_object
        self.__object = _object

cdef class DotNetFunc(DotNetObject):
    def __init__(self, emulator_obj, _object, method_object):
        DotNetObject.__init__(self, emulator_obj)
        self.__method_object = method_object
        self.__object = _object

    #TODO: can this be optimized?
    def Invoke(self, *method_args):
        method_obj = self.__method_object
        # well guess im basically copying the code from the call instruction on this one.
        if isinstance(method_obj, net_row_objects.MethodDef) or isinstance(method_obj, DotNetDynamicMethod):
            if isinstance(method_obj, net_row_objects.MethodDef):
                cctor_method = method_obj.get_parent_type().get_cctor_method()
                if isinstance(cctor_method,
                              net_row_objects.MethodDef) and self.get_emulator_obj().get_executed_cctors().can_execute(
                    cctor_method):
                    new_emu = self.get_emulator_obj().spawn_new_emulator(
                        cctor_method, start_offset=0, method_params=method_args, caller=None, end_offset=-1, end_method_rid=0, end_eip=-1)
                    new_emu.run_function()
            new_emu = self.get_emulator_obj().spawn_new_emulator(
                method_obj, method_params=method_args, start_offset=0, caller=None, end_offset=-1, end_method_rid=0, end_eip=-1)
            new_emu.run_function()
            if method_obj.has_return_value():
                return new_emu.stack.pop()
            # the handler for ret instruction handles cleaning up the stack after this.
        elif isinstance(method_obj, net_row_objects.MemberRef):
            type_full_name = method_obj.get_parent_type().get_full_name().decode('ascii')
            method_name = method_obj['Name'].get_value().decode('ascii')
            if type_full_name not in NET_EMULATE_TYPE_REGISTRATIONS:
                raise net_exceptions.EmulatorTypeNotFoundException(
                    type_full_name)

            emulated_type = NET_EMULATE_TYPE_REGISTRATIONS[type_full_name]
            emu_method = None
            if method_name == '.ctor':
                emu_method = emulated_type
            else:
                emu_method = None
                if hasattr(emulated_type, method_name):
                    emu_method = getattr(emulated_type, method_name)
                else:
                    raise net_exceptions.EmulatorMethodNotFoundException(
                        method_obj.get_full_name())

            if not emu_method:
                raise net_exceptions.OperationNotSupportedException
            actual_method_args = list(method_args)
            if method_obj.is_static_method():
                actual_method_args.insert(0, self.get_emulator_obj().get_appdomain())

            ret_val = emu_method(*actual_method_args)

            if method_obj.has_return_value():
                return ret_val
        else:
            raise net_exceptions.OperationNotSupportedException()

cdef class DotNetThreadPool(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def QueueUserWorkItem(app_domain, wait_callback):
        """
        Samples of a possibly newer dotnetreactor version seem to have some junk calls of this function.
        No need to actually emulate it yet.
        """
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), True)

cdef class DotNetThreadStart(DotNetObject):
    def __init__(self, emulator_obj, _object, method_object):
        DotNetObject.__init__(self, emulator_obj)
        self.__object = _object
        self.__method_object = method_object

    cpdef get_method_object(self):
        return self.__method_object

cdef class DotNetDebugger(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def get_IsAttached(app_domain):
        """
        Dont want any obfuscators thinking were debugging.
        """
        return net_emu_coretypes.DotNetBoolean(app_domain.get_emulator_obj(), False)


cdef class DotNetComparison(DotNetObject):
    def __init__(self, emulator_obj, _object, method_object):
        DotNetObject.__init__(self)
        self.__object = _object
        self.__method_object = method_object

    cpdef get_method_object(self):
        return self.__method_object

cdef class DotNetGC(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self)

    @staticmethod
    def Collect(app_domain):
        pass

cdef class DotNetPath(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def GetTempPath(app_domain):
        return DotNetString(app_domain.get_emulator_obj(), '%Temp%'.encode('utf-16le'))

    @staticmethod
    def Combine(app_domain, path_one, path_two):
        str_one = path_one.get_str_data_as_bytes().decode(path_one.get_str_encoding())
        str_two = path_two.get_str_data_as_bytes().decode(path_two.get_str_encoding())

        #for now assume windows
        combined = ntpath.join(str_one, str_two)
        return DotNetString(app_domain.get_emulator_obj(), combined.encode('utf-16le'))

cdef class DotNetEnvironment(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
    
    @staticmethod
    def GetFolderPath(app_domain, folder_enum):
        if folder_enum == 28:
            return DotNetString(app_domain.get_emulator_obj(), '%LocalAppData%'.encode('utf-16le'))
        raise net_exceptions.OperationNotSupportedException()

cdef class DotNetResolveEventArgs(DotNetObject):
    def __init__(self, emulator_obj, DotNetString name):
        DotNetObject.__init__(self, emulator_obj)
        self.__name = name

    def get_Name(self):
        return self.__name


cdef class DotNetDeflateStream(DotNetObject):
    def __init__(self, emulator_obj, original_stream, mode):
        DotNetObject.__init__(self, emulator_obj)
        #for simplicity just grab the entire buffer and decompress it here.
        rsrc_stream = original_stream.get_rsrc_stream()
        decom = zlib.decompressobj(-15)
        #FIXME: this doesnt really operate in a stream fashion and could cause issues if original_stream is eventually reused.
        self.decompressed_buffer = decom.decompress(rsrc_stream.read())
        self.__decompress = mode == 0
        self.position = 0

    cpdef object Read(self, DotNetArray buffer, object offset, object count):
        cdef Py_ssize_t amt_written
        cdef Py_ssize_t x
        amt_written = 0
        for x in range(count):
            if (self.position + x) >= len(self.decompressed_buffer):
                break
            amt_written += 1
            buffer[offset + x] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), self.decompressed_buffer[x + self.position])

        self.position += amt_written
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), amt_written)

cdef class DotNetSymmetricAlgorithm(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
        self.__key = None
        self.__iv = None

    def get_Key(self):
        return self.__key

    def set_Key(self, key):
        self.__key = key

    def get_IV(self):
        return self.__iv

    def set_IV(self, iv):
        self.__iv = iv

    def get_Padding(self):
        return self.__padding

    def set_Padding(self, padding):
        self.__padding = padding

    def get_Mode(self):
        return self.__mode

    def set_Mode(self, mode):
        self.__mode = mode

cdef class DotNetICryptoTransform(DotNetObject):
    def __init__(self, emulator_obj, provider):
        DotNetObject.__init__(self, emulator_obj)
        self.provider = provider

    def get_InputBlockSize(self):
        raise Exception()

    def get_OutputBlockSize(self):
        raise Exception()

    def TransformBlock(self, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset):
        raise Exception()

    def TransformFinalBlock(self, inputBuffer, inputOffset, inputCount):
        raise Exception()

cdef class DotNetDESDecryptor(DotNetICryptoTransform):
    def __init__(self, emulator_obj, provider):
        DotNetICryptoTransform.__init__(self, emulator_obj, provider)
        #CBC mode is default in c#
        self.des_object = DES.new(bytes(self.provider.get_Key().get_internal_array()), DES.MODE_CBC, bytes(self.provider.get_IV().get_internal_array()))

    def get_InputBlockSize(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 8)

    def get_OutputBlockSize(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 8)

    def TransformBlock(self, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset):
        input_data = bytearray([0] * inputCount)
        for x in range(inputCount):
            input_data[x] = inputBuffer[inputOffset + x]
        
        output_data = self.des_object.decrypt(input_data)
        for x in range(inputCount):
            outputBuffer[x + outputOffset] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), output_data[x])

        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), inputCount)

    def TransformFinalBlock(self, inputBuffer, inputOffset, inputCount):
        input_data = bytearray([0] * inputCount)
        for x in range(inputCount):
            input_data[x] = inputBuffer[x + inputOffset]

        output_data = self.des_object.decrypt(input_data)
        usable_output = list()
        for x in range(len(output_data)):
            usable_output.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), output_data[x]))
        array = DotNetArray(self.get_emulator_obj(), len(usable_output), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                    initialize=False)
        array.set_internal_array(usable_output)

        return array

cdef class DotNetDESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    def __init__(self, emulator_obj):
        DotNetSymmetricAlgorithm.__init__(self, emulator_obj)

    def set_IV(self, iv):
        super().set_IV(iv)

    def set_Key(self, key):
        super().set_Key(key)

    def get_IV(self):
        return super().get_IV()

    def get_Key(self):
        return super().get_Key()

    def CreateDecryptor(self):
        return DotNetDESDecryptor(self.get_emulator_obj(), self)

cdef class DotNetApplication(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)

    @staticmethod
    def get_ProductVersion(app_domain):
        return DotNetString(app_domain.get_emulator_obj(), app_domain.get_executing_dotnetpe().get_productversion().encode('utf-16le'))

cdef class DotNetHashAlgorithm(DotNetObject):
    def __init__(self, emulator_obj):
        DotNetObject.__init__(self, emulator_obj)
    
    def Clear(self):
        pass

    def ComputeHash(self, data):
        raise Exception()

cdef class DotNetMD5CryptoServiceProvider(DotNetHashAlgorithm):
    def __init__(self, emulator_obj):
        DotNetHashAlgorithm.__init__(self, emulator_obj)

    def ComputeHash(self, data):
        internal_data = bytes(data.get_internal_array())
        md5_obj = hashlib.md5()
        md5_obj.update(internal_data)
        resulting_data = md5_obj.digest()
        count = len(resulting_data)
        arr_obj = DotNetArray(self.get_emulator_obj(), count, DotNetAssembly.GetExecutingAssembly(self.get_emulator_obj().get_appdomain()).get_module().get_dotnetpe().get_type_by_full_name(
            b'System.Byte'), initialize=False)
        usable_data = list()
        for x in range(len(resulting_data)):
            usable_data.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), resulting_data[x]))

        arr_obj.set_internal_array(usable_data)
        return arr_obj
    
cdef class DotNet3DESDecryptor(DotNetICryptoTransform):
    def __init__(self, emulator_obj, provider):
        DotNetICryptoTransform.__init__(self, emulator_obj, provider)
        #CBC mode is default in c#
        mode = DES.MODE_CBC
        if self.provider.get_Mode() == 2:
            mode = DES.MODE_ECB
        self.des_object = DES3.new(bytes(self.provider.get_Key().get_internal_array()), mode)

    def get_InputBlockSize(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 8)

    def get_OutputBlockSize(self):
        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), 8)

    def TransformBlock(self, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset):
        input_data = bytearray([0] * inputCount)
        for x in range(inputCount):
            input_data[x] = inputBuffer[inputOffset + x]
        
        output_data = self.des_object.decrypt(input_data)
        for x in range(inputCount):
            outputBuffer[x + outputOffset] = net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), output_data[x])

        return net_emu_coretypes.DotNetInt32(self.get_emulator_obj(), inputCount)

    def TransformFinalBlock(self, inputBuffer, inputOffset, inputCount):
        input_data = bytearray([0] * inputCount)
        for x in range(inputCount):
            input_data[x] = inputBuffer[x + inputOffset]

        output_data = self.des_object.decrypt(input_data)
        usable_output = list()
        for x in range(len(output_data)):
            usable_output.append(net_emu_coretypes.DotNetUInt8(self.get_emulator_obj(), output_data[x]))
        #handle pkcs7 padding:
        if self.provider.get_Padding() == 2:
            potential_padding = usable_output[-1]
            #'hello\x03\x03\0x03'
            if len(usable_output) >= potential_padding:
                start_index = len(usable_output) - potential_padding
                is_padded = True
                for index in range(start_index, len(usable_output)):
                    if usable_output[index] != potential_padding:
                        is_padded = False
                        break
                if is_padded:
                    usable_output = usable_output[:start_index]

        array = DotNetArray(self.get_emulator_obj(), len(usable_output), self.get_emulator_obj().get_appdomain().get_executing_dotnetpe().get_type_by_full_name(b'System.Byte'),
                    initialize=False)
        array.set_internal_array(usable_output)

        return array

cdef class DotNet3DESCryptoServiceProvider(DotNetSymmetricAlgorithm):
    def __init__(self, emulator_obj):
        DotNetSymmetricAlgorithm.__init__(self, emulator_obj)

    def set_IV(self, iv):
        super().set_IV(iv)

    def set_Key(self, key):
        super().set_Key(key)

    def get_IV(self):
        return super().get_IV()

    def get_Key(self):
        return super().get_Key()

    def set_Padding(self, padding):
        super().set_Padding(padding)
        
    def get_Padding(self):
        return super().get_Padding()

    def get_Mode(self):
        return super().get_Mode()

    def set_Mode(self, mode):
        return super().set_Mode(mode)

    def CreateDecryptor(self):
        return DotNet3DESDecryptor(self.get_emulator_obj(), self)

    def Clear(self):
        pass
    
"""
Register new types here.
"""

cdef NET_EMULATE_TYPE_REGISTRATIONS = {
    'System.Threading.Monitor': DotNetMonitor,
    'System.Collections.Concurrent.ConcurrentDictionary': DotNetConcurrentDictionary,
    'System.Collections.Generic.Dictionary': DotNetDictionary,
    'System.Collections.Hashtable': DotNetHashTable,
    'System.Collections.SortedList': DotNetSortedList,
    'System.String': DotNetString,
    'System.Text.StringBuilder': DotNetStringBuilder,
    'System.Reflection.Assembly': DotNetAssembly,
    'System.Collections.Generic.List': DotNetList,
    'System.Type': DotNetType,
    'System.Diagnostics.StackTrace': DotNetStackTrace,
    'System.Diagnostics.StackFrame': DotNetStackFrame,
    'System.Reflection.MemberInfo': DotNetMemberInfo,
    'System.Reflection.MethodBase': DotNetMethodBase,
    'System.Reflection.AssemblyName': DotNetAssemblyName,
    'System.Console': DotNetConsole,
    'System.Object': DotNetObject,
    'System.IO.Stream': DotNetStream,
    'System.Threading.Thread': DotNetThread,
    'System.Runtime.CompilerServices.RuntimeHelpers': DotNetRuntimeHelpers,
    'System.IO.MemoryStream': DotNetMemoryStream,
    'System.Math': DotNetMath,
    'System.BitConverter': DotNetBitConverter,
    'System.Buffer': DotNetBuffer,
    'System.AppDomain': DotNetAppDomain,
    'System.ResolveEventHandler': DotNetResolveEventHandler,
    'System.Text.Encoding': DotNetEncoding,
    'System.Reflection.Module': DotNetModule,
    'System.ModuleHandle': DotNetModuleHandle,
    'System.RuntimeTypeHandle': DotNetRuntimeTypeHandle,
    'System.Reflection.FieldInfo': DotNetFieldInfo,
    'System.Delegate': DotNetDelegate,
    'System.MulticastDelegate': DotNetMulticastDelegate,
    'System.Convert': DotNetConvert,
    'System.Reflection.ParameterInfo': DotNetParameterInfo,
    'System.Reflection.MethodInfo': DotNetMethodInfo,
    'System.Reflection.Emit.DynamicMethod': DotNetDynamicMethod,
    'System.Reflection.Emit.ILGenerator': DotNetILGenerator,
    'System.Reflection.Emit.OpCodes': DotNetOpCodes,
    'System.IntPtr': DotNetIntPtr,
    'System.Security.Cryptography.RSACryptoServiceProvider': DotNetRSACryptoServiceProvider,
    'System.IO.BinaryReader': DotNetBinaryReader,
    'System.Array': DotNetArray,
    'System.Runtime.InteropServices.Marshal': DotNetMarshal,
    'System.Runtime.InteropServices.GCHandle': DotNetGCHandle,
    'System.Threading.WaitCallback': DotNetWaitCallback,
    'System.Threading.ThreadPool': DotNetThreadPool,
    'System.Func': DotNetFunc,
    'System.Threading.ThreadStart': DotNetThreadStart,
    'System.Diagnostics.Debugger' : DotNetDebugger,
    'System.Comparison' : DotNetComparison,
    'System.Int8': net_emu_coretypes.DotNetInt8,
    'System.Int16': net_emu_coretypes.DotNetInt16,
    'System.Int32': net_emu_coretypes.DotNetInt32,
    'System.Int64': net_emu_coretypes.DotNetInt64,
    'System.UInt8': net_emu_coretypes.DotNetUInt8,
    'System.UInt16': net_emu_coretypes.DotNetUInt16,
    'System.UInt32': net_emu_coretypes.DotNetUInt32,
    'System.UInt64': net_emu_coretypes.DotNetUInt64,
    'System.Single': net_emu_coretypes.DotNetSingle,
    'System.Double': net_emu_coretypes.DotNetDouble,
    'System.Boolean': net_emu_coretypes.DotNetBoolean,
    'System.Void': net_emu_coretypes.DotNetVoid,
    'System.Char': net_emu_coretypes.DotNetChar,
    'System.GC' : DotNetGC,
    'System.IO.Path': DotNetPath,
    'System.Environment' : DotNetEnvironment,
    'System.ResolveEventArgs': DotNetResolveEventArgs,
    'System.IO.Compression.DeflateStream': DotNetDeflateStream,
    'System.Security.Cryptography.DESCryptoServiceProvider': DotNetDESCryptoServiceProvider,
    'System.Security.Cryptography.ICryptoTransform': DotNetICryptoTransform,
    'System.Security.Cryptography.SymmetricAlgorithm': DotNetSymmetricAlgorithm,
    'System.Windows.Forms.Application': DotNetApplication,
    'System.Security.Cryptography.MD5CryptoServiceProvider': DotNetMD5CryptoServiceProvider,
    'System.Security.Cryptography.TripleDESCryptoServiceProvider': DotNet3DESCryptoServiceProvider,
    'System.Security.Cryptography.HashAlgorithm': DotNetHashAlgorithm
}