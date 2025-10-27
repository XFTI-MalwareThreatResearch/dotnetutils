#cython: language_level=3
#distutils: language=c++


import ctypes
import io
import re
from dotnetutils import net_exceptions

import binascii

cdef class DotNetDataReader:
    """ A specialized reader with utilities to read popular .NET formats.

        Mostly for internal use, functions very similar to a IO Stream with seek(), read() etc.
    """
    def __init__(self, bytes data):
        self.__data = data
        self.__current_pos = 0
        self.__data_len = <int>len(data)

    cpdef bint is_end(self):
        return self.tell() >= self.__data_len

    cpdef void seek(self, int offset, int where):
        cdef int new_pos
        new_pos = 0
        if where == 0:
            new_pos = new_pos + offset
        elif where == 1:
            new_pos = self.__current_pos + offset
        elif where == 2:
            new_pos = self.__data_len + offset
        else:
            raise net_exceptions.InvalidArgumentsException()
        
        if new_pos < 0 or new_pos > self.__data_len:
            raise net_exceptions.DotNetIOException()

        self.__current_pos = new_pos

    cpdef int tell(self):
        return self.__current_pos

    cpdef unsigned char read_byte(self):
        return <unsigned char>self.read_single_byte()

    cpdef char read_sbyte(self):
        return <char>self.read_single_byte()

    cpdef short read_int16(self):
        return <short>int.from_bytes(self.read(2), 'little', signed=True)

    cpdef int64_t read_int64(self):
        return <int64_t>int.from_bytes(self.read(8), 'little', signed=True)

    cpdef unsigned short read_uint16(self):
        return <unsigned short>int.from_bytes(self.read(2), 'little', signed=False)

    cpdef uint64_t read_uint64(self):
        return <uint64_t>int.from_bytes(self.read(8), 'little', signed=False)

    cpdef list read_decimal(self):
        cdef int one
        cdef int two
        cdef int three
        cdef int four
        one = self.read_int32()
        two = self.read_int32()
        three = self.read_int32()
        four = self.read_int32()
        return [one, two, three, four]

    cpdef float read_single(self):
        cdef bytes data
        data = self.read(4)
        return <float>int.from_bytes(data, 'little', signed=True)

    cpdef double read_double(self):
        cdef bytes data
        data = self.read(8)
        return <double>int.from_bytes(data, 'little', signed=True)
    
    cpdef bint read_boolean(self):
        return self.read_byte() != 0

    cpdef unsigned short read_char(self):
        return self.read_uint16()

    cpdef str read_serialized_string(self, encoding='utf-8'):
        cdef unsigned int length
        cdef bytes str_data
        length = self.read_encoded_uint32()
        if length <= 0:
            return None
        str_data = self.read(length)
        return str_data.decode(encoding)

    cpdef int read_int32(self):
        cdef bytes data
        data = self.read(4)
        return <int>int.from_bytes(data, 'little', signed=True)

    cpdef unsigned int read_uint32(self):
        cdef bytes data
        data = self.read(4)
        return <unsigned int>int.from_bytes(data, 'little', signed=False)

    cpdef unsigned int read_encoded_uint32(self):
        cdef unsigned int val
        cdef int bits
        cdef int x
        cdef int b
        val = 0
        bits = 0
        for x in range(5):
            b = self.read(1)[0]
            val |= (<unsigned int>(b & 0x7f)) << bits
            if ((b & 0x80) == 0):
                return val
            bits += 7
        raise net_exceptions.DotNetIOException
    
    cpdef unsigned int read_compressed_uint(self):
        cdef unsigned int num
        cdef int shift
        cdef int read_val
        num = 0
        shift = 0
        while True:
            read_val = self.read(1)[0]
            num |= (read_val & 0x7f) << shift
            shift += 7
            if (read_val & 0x80) == 0:
                break
        return num

    cpdef int read_encoded_int32(self):
        cdef int val
        cdef int bits
        cdef int b
        cdef int x
        val = 0
        bits = 0
        for x in range(5):
            b = self.read(1)[0]
            val |= (<int>(b & 0x7f)) << bits
            if ((b & 0x80) == 0):
                return val
            bits += 7
        raise net_exceptions.DotNetIOException
    
    cpdef bytes read(self, int amt=-1):
        cdef bytes result
        cdef int end_pos
        #first check if we are at EOF, if so return empty bytes.
        if self.is_end():
            return bytes()
        if amt == -1:
            result = self.__data[self.__current_pos:]
            self.__current_pos = self.__data_len
        elif amt == 1:
            result = bytes([self.__data[self.__current_pos]])
            self.__current_pos += 1
        else:
            if amt <= 0:
                raise net_exceptions.InvalidArgumentsException()
            end_pos = self.__current_pos + amt
            if end_pos > self.__data_len:
                end_pos = self.__data_len #only read until the end, not further.
            result = self.__data[self.__current_pos:end_pos]
            self.__current_pos += amt
        #make sure self.__current_pos doesnt go past end.
        if self.__current_pos > self.__data_len:
            self.__current_pos = self.__data_len
        return result            
    
    cpdef bytes read_all(self):
        return self.read(-1)
    
    cpdef int read_single_byte(self):
        cdef bytes res
        res = self.read(1)
        if len(res) != 1:
            raise net_exceptions.DotNetIOException()
        return res[0]


class DotNetResource:
    """
    Represents a raw DotNetResource.  This is the lowest object in the tree.
    """
    def __init__(self):
        self.__data = None
        self.__name = None

    def _set_data(self, data):
        self.__data = data

    def _set_name(self, name):
        self.__name = name

    def get_name(self):
        """ Get the resources name.
        """
        return self.__name

    def get_data(self):
        """ Get the resource's data.
        """
        return self.__data


class DotNetResourceInfo:
    def __init__(self, name, offset):
        self.name = name
        self.offset = offset

    def __str__(self):
        return 'DotNetResourceInfo: name={}, offset={}'.format(self.name, self.offset)


#various serialization types

class SerializationHeaderRecord:
    def __init__(self, root_id, header_id, major_version, minor_version):
        self.__root_id = root_id
        self.__header_id = header_id
        self.__major_version = major_version
        self.__minor_version = minor_version

    def get_root_id(self):
        return self.__root_id
    
    def get_header_id(self):
        return self.__header_id
    
    def get_major_version(self):
        return self.__major_version
    
    def get_minor_version(self):
        return self.__minor_version
    
class ClassWithIdRecord:
    def __init__(self, object_id, metadata_id):
        self.__object_id = object_id
        self.__metadata_id = metadata_id

    def get_object_id(self):
        return self.__object_id
    
    def get_metadata_id(self):
        return self.__metadata_id
    
class BinaryLibraryRecord:
    def __init__(self, library_id, library_name):
        self.__library_id = library_id
        self.__library_name = library_name

    def get_library_id(self):
        return self.__library_id
    
    def get_library_name(self):
        return self.__library_name
    
class ClassInfoStructure:
    def __init__(self, object_id, name, member_count, member_names):
        self.__object_id = object_id
        self.__name = name
        self.__member_count = member_count
        self.__member_names = member_names
    
    def get_object_id(self):
        return self.__object_id
    
    def get_name(self):
        return self.__name
    
    def get_member_count(self):
        return self.__member_count
    
    def get_member_names(self):
        return self.__member_names
    
class MemberTypeInfoStructure:
    def __init__(self, binary_type_enums, additional_infos):
        self.__binary_type_enums = binary_type_enums
        self.__additional_infos = additional_infos

    def get_binary_type_enums(self):
        return self.__binary_type_enums
    
    def get_additional_infos(self):
        return self.__additional_infos
    
class ClassTypeInfoStructure:
    def __init__(self, type_name, library_id):
        self.__type_name = type_name
        self.__library_id = library_id

    def get_type_name(self):
        return self.__type_name
    
    def get_library_id(self):
        return self.__library_id
    
class ArrayInfoStructure:
    def __init__(self, object_id, length):
        self.__object_id = object_id
        self.__length = length

    def get_object_id(self):
        return self.__object_id

    def get_length(self):
        return self.__length
    
class ClassWithMembersAndTypesRecord:
    def __init__(self, class_info, member_type_info, library_id):
        self.__class_info = class_info
        self.__member_type_info = member_type_info
        self.__library_id = library_id

    def get_class_info(self):
        return self.__class_info
    
    def get_member_type_info(self):
        return self.__member_type_info
    
    def get_library_id(self):
        return self.__library_id
    
class MemberReferenceRecord:
    def __init__(self, id_ref):
        self.__id_ref = id_ref

    def get_id_ref(self):
        return self.__id_ref
    
class ArraySinglePrimitiveRecord:
    def __init__(self, array_info, primitive_type_enum):
        self.__array_info = array_info
        self.__primitive_type_enum = primitive_type_enum

    def get_array_info(self):
        return self.__array_info
    
    def get_primitive_type_enum(self):
        return self.__primitive_type_enum

class DotNetResourceSerializedData:
    def __init__(self, records, data):
        self.__records = records
        self.__data = data
    
    def get_records(self):
        return self.__records
    
    def get_data(self):
        return self.__data

class DotNetResourceSet:
    """ Represents a set of DotNetResources.
        Utilities for parsing and representing various types of ManifestResources that dotnet may use.
    """
    def __init__(self, data, dotnetpe, force_name=None, debug=False):
        self.__reader = DotNetDataReader(data)
        self.__data_len = len(data)
        self.__resources = list()
        self.__debug = debug
        if DotNetResourceSet.is_resource(data):
            self.__parse_header_from_bytes()
            self.__parse_resource_data()
        else:
            # treat it as bytes
            dnr = DotNetResource()
            dnr._set_name(force_name)
            dnr._set_data(self.__reader.read_all())
            self.__resources.append(dnr)
            self.__version = None
            self.__resource_count = 1
            self.__user_types = list()
            self.__hashes = list()
            self.__name_offsets = list()
            self.__base_offset = 0

    
    def get_version(self):
        return self.__version
    
    def get_user_types(self):
        return self.__user_types
    
    def get_hashes(self):
        return self.__hashes
    
    def __parse_header(self):
        header_version = self.__reader.read_int32()
        if not header_version == 1:
            raise net_exceptions.InvalidHeaderException
        header_size = self.__reader.read_int32()
        if not header_size >= 0:
            raise net_exceptions.InvalidHeaderException
        reader_type_name = self.__reader.read_serialized_string()
        reader_set_type = self.__reader.read_serialized_string()
        self.__header_version = header_version
        self.__header_size = header_size
        self.__reader_type_name = reader_type_name
        self.__reader_set_type_name = reader_set_type
        self.__deserializing_reader = False
        self.__regular_reader = False
        #figure out if its deserializing or not
        deserializing_regex = r"^System\.Resources\.Extensions\.DeserializingResourceReader,\s*System\.Resources\.Extensions"
        reader_regex = r"^System\.Resources\.ResourceReader,\s*mscorlib"
        if re.match(reader_regex, self.__reader_type_name) != None:
            self.__regular_reader = True
        elif re.match(deserializing_regex, self.__reader_type_name) != None:
            self.__deserializing_reader = True
        else:
            raise net_exceptions.InvalidAssemblyException()

    def __parse_header_from_bytes(self):
        magic = self.__reader.read_uint32() # correct
        if not magic == 0xBEEFCACE:  # if this isnt true its not a valid resource
            raise net_exceptions.InvalidHeaderException
        self.__parse_header()
        version = self.__reader.read_int32()
        if not (version == 1 or version == 2):
            raise net_exceptions.InvalidHeaderException
        resource_count = self.__reader.read_int32()
        if not resource_count >= 0:
            raise net_exceptions.InvalidHeaderException
        user_type_count = self.__reader.read_int32()
        if not user_type_count >= 0:
            raise net_exceptions.InvalidHeaderException
        user_types = list()
        for x in range(user_type_count):
            user_types.append(self.__reader.read_serialized_string())
        self.__reader.seek((self.__reader.tell() + 7) & ~7, io.SEEK_SET) # up to here is correct.
        hashes = list()
        for x in range(resource_count):
            hashes.append(self.__reader.read_int32())

        name_offsets = list()
        for x in range(resource_count):
            name_offsets.append(self.__reader.read_int32())
        base_offset = self.__reader.tell()
        data_base_offset = self.__reader.read_int32()
        name_base_offset = self.__reader.tell()

        self.__version = version
        self.__resource_count = resource_count
        self.__user_types = user_types
        self.__hashes = hashes
        self.__name_offsets = name_offsets
        self.__base_offset = base_offset
        self.__data_base_offset = data_base_offset
        self.__name_base_offset = name_base_offset

    def __parse_resource_data(self):
        name_base_offset = self.__name_base_offset
        end = self.__data_len
        self.__resource_infos = list()
        for x in range(self.__resource_count):
            new_pos = name_base_offset + self.__name_offsets[x]
            self.__reader.seek(new_pos, io.SEEK_SET)
            name = self.__reader.read_serialized_string('utf-16le')
            offset = self.__data_base_offset + self.__reader.read_int32()
            self.__resource_infos.append(DotNetResourceInfo(name, offset))

        #sort resource infos by offset
        def rinfo_sort_func(e):
            return e.offset

        self.__resource_infos.sort(key=rinfo_sort_func)

        for x in range(self.__resource_count):
            info = self.__resource_infos[x]
            element = DotNetResource()
            element._set_name(info.name)
            self.__reader.seek(info.offset, io.SEEK_SET)
            next_data_offset = 0
            if x == (self.__resource_count - 1):
                next_data_offset = end
            else:
                next_data_offset = self.__resource_infos[x + 1].offset
            size = next_data_offset - info.offset
            if self.__version == 1:
                element._set_data(self.__parse_resource_data_v1(self.__user_types, size))
            else:
                element._set_data(self.__parse_resource_data_v2(self.__user_types, size))

            self.__resources.append(element)

    def get_resources(self):
        """
        Return any DotNetResources within the set.
        """
        return self.__resources

    def __read_serialized_data(self, endPos):
        if self.__regular_reader:
            data = self.__reader.read(endPos - self.__reader.tell())
        else:
            #TODO: more work might need to be done here
            #raise net_exceptions.OperationNotSupportedException()
            serialized_format = self.__read_encoded_int32()
            length = self._read_encoded_int32()
            data = self.__reader.read(length)
        #return self.__parse_dotnet_serialization_object(data)
        return data
    
    def __parse_dotnet_serialization_object(self, serialized_data):
        reader = DotNetDataReader(serialized_data)

        def __serialization_parse_header():
            nonlocal reader
            offset = reader.tell()
            record_type_enum = reader.read_byte()
            if not record_type_enum == 0:
                raise net_exceptions.InvalidHeaderException
            root_id = reader.read_int32()
            header_id = reader.read_int32()
            major_version = reader.read_int32()
            minor_version = reader.read_int32()
            if not (major_version == 1 and minor_version == 0):
                raise net_exceptions.InvalidHeaderException
            return SerializationHeaderRecord(root_id, header_id, major_version, minor_version)
        
        def __parse_classinfo_structure():
            nonlocal reader
            offset = reader.tell()
            object_id = reader.read_int32()
            name = reader.read_serialized_string()
            member_count = reader.read_int32()
            names = list()
            for x in range(member_count):
                names.append(reader.read_serialized_string())
            return ClassInfoStructure(object_id, name, member_count, names)
        
        def __parse_classtypeinfo_structure():
            nonlocal reader
            offset = reader.tell()
            type_name = reader.read_serialized_string()
            library_id = reader.read_int32()
            return ClassTypeInfoStructure(type_name, library_id)
        
        def __parse_membertypeinfo_structure(class_info_struct: ClassInfoStructure):
            nonlocal reader
            BinaryTypeEnum_Primitive = 0
            BinaryTypeEnum_SystemClass = 3
            BinaryTypeEnum_Class = 4
            BinaryTypeEnum_PrimitiveArray = 7
            binary_type_enums = list()
            additional_infos = list()
            offset = reader.tell()
            for x in range(class_info_struct.get_member_count()):
                binary_type_enums.append(reader.read_byte())

            for binary_type in binary_type_enums:
                if binary_type == BinaryTypeEnum_Primitive:
                    additional_infos.append(reader.read_byte())
                elif binary_type == BinaryTypeEnum_SystemClass:
                    additional_infos.append(reader.read_serialized_string())
                elif binary_type == BinaryTypeEnum_Class:
                    additional_infos.append(__parse_classtypeinfo_structure())
                elif binary_type == BinaryTypeEnum_PrimitiveArray:
                    additional_infos.append(reader.read_byte())
            return MemberTypeInfoStructure(binary_type_enums, additional_infos)
        
        def __parse_arrayinfo_structure():
            nonlocal reader
            offset = reader.tell()
            object_id = reader.read_int32()
            length = reader.read_int32()
            return ArrayInfoStructure(object_id, length)

        def __parse_class_with_id():
            nonlocal reader
            offset = reader.tell()
            object_id = reader.read_int32()
            metadata_id = reader.read_int32()
            return ClassWithIdRecord(object_id, metadata_id)
        
        def __parse_system_class_with_members():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException() # TODO: add support.

        def __parse_class_with_members():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()

        def __parse_system_class_with_members_and_types():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_class_with_members_and_types():
            nonlocal reader
            offset = reader.tell()
            class_info = __parse_classinfo_structure()
            member_type_info = __parse_membertypeinfo_structure(class_info)
            library_id = reader.read_int32()
            return ClassWithMembersAndTypesRecord(class_info, member_type_info, library_id)
        
        def __parse_binary_object_string():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_binary_array():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_member_primitive_typed():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_member_reference():
            nonlocal reader
            offset = reader.tell()
            id_ref = reader.read_int32()
            return MemberReferenceRecord(id_ref)
        
        def __parse_object_null():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()

        def __parse_binary_library():
            nonlocal reader
            offset = reader.tell()
            library_id = reader.read_int32()
            library_name = reader.read_serialized_string()
            return BinaryLibraryRecord(library_id, library_name)
        
        def __parse_object_null_multiple_256():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_object_null_multiple():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_array_single_primitive():
            nonlocal reader
            offset = reader.tell()
            array_info = __parse_arrayinfo_structure()
            type_enum = reader.read_byte()
            return ArraySinglePrimitiveRecord(array_info, type_enum)
        
        def __parse_array_single_object():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_array_single_string():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_method_call():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()
        
        def __parse_method_return():
            nonlocal reader
            raise net_exceptions.OperationNotSupportedException()

        records = list()
        record = __serialization_parse_header() # For the most part I dont think theres anything from the header we actually need to keep.
        records.append(record)
        #assuming everything was good with the header, parse the rest of the records.
        while True:
            ident = reader.read_byte()
            record = None
            if ident == SerializedStreamHeader:
                raise net_exceptions.InvalidAssemblyException() #We already parsed this header.
            elif ident == CorRecordTypeEnumeration.ClassWithId:
                record = __parse_class_with_id()
            elif ident == CorRecordTypeEnumeration.SystemClassWithMembers:
                record = __parse_system_class_with_members()
            elif ident == CorRecordTypeEnumeration.ClassWithMembers:
                record = __parse_class_with_members()
            elif ident == CorRecordTypeEnumeration.SystemClassWithMembersAndTypes:
                record = __parse_system_class_with_members_and_types()
            elif ident == CorRecordTypeEnumeration.ClassWithMembersAndTypes:
                record = __parse_class_with_members_and_types()
            elif ident == CorRecordTypeEnumeration.BinaryObjectString:
                record = __parse_binary_object_string()
            elif ident == CorRecordTypeEnumeration.BinaryArray:
                record = __parse_binary_array()
            elif ident == CorRecordTypeEnumeration.MemberPrimitiveTyped:
                record = __parse_member_primitive_typed()
            elif ident == CorRecordTypeEnumeration.MemberReference:
                record = __parse_member_reference()
            elif ident == CorRecordTypeEnumeration.ObjectNull:
                record = __parse_object_null()
            elif ident == CorRecordTypeEnumeration.MessageEnd:
                break
            elif ident == CorRecordTypeEnumeration.BinaryLibrary:
                record = __parse_binary_library()
            elif ident == CorRecordTypeEnumeration.ObjectNullMultiple256:
                record = __parse_object_null_multiple_256()
            elif ident == CorRecordTypeEnumeration.ObjectNullMultiple:
                record = __parse_object_null_multiple()
            elif ident == CorRecordTypeEnumeration.ArraySinglePrimitive:
                record = __parse_array_single_primitive()
            elif ident == CorRecordTypeEnumeration.ArraySingleObject:
                record = __parse_array_single_object()
            elif ident == CorRecordTypeEnumeration.ArraySingleString:
                record = __parse_array_single_string()
            elif ident == CorRecordTypeEnumeration.MethodCall:
                record = __parse_method_call()
            elif ident == CorRecordTypeEnumeration.MethodReturn:
                record = __parse_method_return()
            else:
                raise net_exceptions.OperationNotSupportedException()
                #break #TODO: THis probably isnt correct - there has to be a way to identify the actual end somehow when a MessageEnd isnt present.
            
            if record is None:
                raise net_exceptions.DeserializationException
            records.append(record)
        return DotNetResourceSerializedData(records, reader.read_all())

    def __parse_resource_data_v1(self, user_types, size):
        end_pos = self.__reader.tell() + size
        type_index = self.__reader.read_encoded_int32()
        if type_index == -1:
            return None
        type_len, type_name = user_types[type_index]
        comma_index = type_name.split(b',')
        actual_name = None
        if comma_index == -1:
            actual_name = type_name
        else:
            actual_name = type_name.replace(b',', b'')
        if actual_name == b'System.String':
            return self.__reader.read_serialized_string()
        elif actual_name == b'System.Int32':
            return self.__reader.read_int32()
        elif actual_name == b'System.Byte':
            return self.__reader.read_byte()
        elif actual_name == b'System.SByte':
            return self.__reader.read_sbyte()
        elif actual_name == b'System.Int16':
            return self.__reader.read_int16()
        elif actual_name == b'System.Int64':
            return self.__reader.read_int64()
        elif actual_name == b'System.UInt16':
            return self.__reader.read_uint16()
        elif actual_name == b'System.UInt32':
            return self.__reader.read_uint32()
        elif actual_name == b'System.UInt64':
            return self.__reader.read_uint64()
        elif actual_name == b'System.Single':
            return self.__reader.read_single()
        elif actual_name == b'System.Double':
            return self.__reader.read_double()
        elif actual_name == b'System.DateTime':
            return self.__reader.read_int64()
        elif actual_name == b'System.TimeSpan':
            return self.__reader.read_int64()
        elif actual_name == b'System.Decimal':
            return self.__reader.read_decimal()
        else:
            return self.__read_serialized_data(end_pos)

    def __parse_resource_data_v2(self, user_types, size):
        end_pos = self.__reader.tell() + size
        code = self.__reader.read_encoded_uint32()
        #NOTE: offset up to here is correct.  So how do we read this serialized data??
        if code == CorResourceTypeCode.Null:
            return None
        elif code == CorResourceTypeCode.String:
            return self.__reader.read_serialized_string()
        elif code == CorResourceTypeCode.Boolean:
            return self.__reader.read_boolean()
        elif code == CorResourceTypeCode.Char:
            return self.__reader.read_char()
        elif code == CorResourceTypeCode.Byte:
            return self.__reader.read_byte()
        elif code == CorResourceTypeCode.SByte:
            return self.__reader.read_sbyte()
        elif code == CorResourceTypeCode.Int16:
            return self.__reader.read_int16()
        elif code == CorResourceTypeCode.UInt16:
            return self.__reader.read_uint16()
        elif code == CorResourceTypeCode.UInt32:
            return self.__reader.read_uint32()
        elif code == CorResourceTypeCode.Int32:
            return self.__reader.read_int32()
        elif code == CorResourceTypeCode.Uint64:
            return self.__reader.read_uint64()
        elif code == CorResourceTypeCode.Int64:
            return self.__reader.read_int64()
        elif code == CorResourceTypeCode.Single:
            return self.__reader.read_single()
        elif code == CorResourceTypeCode.Double:
            return self.__reader.read_double()
        elif code == CorResourceTypeCode.Decimal:
            return self.__reader.read_decimal()
        elif code == CorResourceTypeCode.DateTime:
            return self.__reader.read_int64()
        elif code == CorResourceTypeCode.TimeSpan:
            return self.__reader.read_int64()
        elif code == CorResourceTypeCode.ByteArray:
            length = self.__reader.read_int32()
            return self.__reader.read(length)
        elif code == CorResourceTypeCode.Stream:
            length = self.__reader.read_int32()
            return self.__reader.read(length)
        else:
            return self.__read_serialized_data(end_pos)

    @staticmethod
    def is_resource(data):
        """
        Used to check if a data could belong to a formatted .NET Resource.
        """
        reader = io.BytesIO(data)
        magic = int.from_bytes(reader.read(4), 'little', signed=False)
        return magic == 0xBEEFCACE