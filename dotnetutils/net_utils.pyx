#cython: language_level=3
#distutils: language=c++


from dotnetutils import net_exceptions
from dotnetutils cimport net_tokens
from dotnetutils cimport net_structs
from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_row_objects
from dotnetutils.net_structs cimport CorElementType
from libc.stdint cimport uintptr_t
from cpython.bytes cimport PyBytes_FromStringAndSize


cdef bytes convert_pointer_to_bytes(uintptr_t address, unsigned long size):
    return PyBytes_FromStringAndSize(<char*>address, <Py_ssize_t>size)

cdef int get_size_of_cortype(CorElementType cor_type, bint is_64bit):
    """ Obtain the size of a CorElementType.

    Returns:
        int: the size in bytes of an instance of CorElementType.

    Raises:
        net_exceptions.InvalidArgumentsException: unsupported type.
    """
    if cor_type == CorElementType.ELEMENT_TYPE_I or cor_type == CorElementType.ELEMENT_TYPE_U:
        if is_64bit:
            return 8
        return 4
    elif cor_type == CorElementType.ELEMENT_TYPE_U1 or cor_type == CorElementType.ELEMENT_TYPE_I1:
        return 1
    elif cor_type == CorElementType.ELEMENT_TYPE_U2 or cor_type == CorElementType.ELEMENT_TYPE_I2 or cor_type == CorElementType.ELEMENT_TYPE_CHAR:
        return 2
    elif cor_type == CorElementType.ELEMENT_TYPE_BOOLEAN:
        return sizeof(bint)
    elif cor_type == CorElementType.ELEMENT_TYPE_I4 or cor_type == CorElementType.ELEMENT_TYPE_U4 or cor_type == CorElementType.ELEMENT_TYPE_R4:
        return 4
    elif cor_type == CorElementType.ELEMENT_TYPE_I8 or cor_type == CorElementType.ELEMENT_TYPE_U8 or cor_type == CorElementType.ELEMENT_TYPE_R8:
        return 8
    raise net_exceptions.InvalidArgumentsException()

cdef bytes get_cor_type_name(net_structs.CorElementType element_type):
    """ obtain the name in bytes of a CorElementType

    Returns:
        bytes: utf-8 encoded string representing the name.

    Raises:
        net_exceptions.InvalidArgumentsException: Unsupported type.
    """
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
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_CHAR:
        return b'System.Char'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_BOOLEAN:
        return b'System.Boolean'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_OBJECT:
        return b'System.Object'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_I:
        return b'System.IntPtr'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_U:
        return b'System.UIntPtr'
    elif element_type == net_structs.CorElementType.ELEMENT_TYPE_BYREF:
        return b'ELEMENT_TYPE_BYREF'
    raise net_exceptions.InvalidArgumentsException(actual=element_type)

cdef bint is_cortype_number(CorElementType etype):
    """ Returns True if the cortype represents a number, False otherwise.
    """
    return etype == CorElementType.ELEMENT_TYPE_I or etype == CorElementType.ELEMENT_TYPE_U or etype == CorElementType.ELEMENT_TYPE_BOOLEAN or \
    etype == CorElementType.ELEMENT_TYPE_CHAR or etype == CorElementType.ELEMENT_TYPE_I1 or etype == CorElementType.ELEMENT_TYPE_U1 or \
    etype == CorElementType.ELEMENT_TYPE_U2 or etype == CorElementType.ELEMENT_TYPE_I2 or etype == CorElementType.ELEMENT_TYPE_U4 or etype == CorElementType.ELEMENT_TYPE_I4 or \
    etype == CorElementType.ELEMENT_TYPE_I8 or etype == CorElementType.ELEMENT_TYPE_U8 or etype == CorElementType.ELEMENT_TYPE_R4 or etype == CorElementType.ELEMENT_TYPE_R8

cdef bint is_cortype_signed(CorElementType etype):
    """ Returns True if the cortype represents a signed number, False otherwise.
    """
    return etype == CorElementType.ELEMENT_TYPE_I or etype == CorElementType.ELEMENT_TYPE_I1 or etype == CorElementType.ELEMENT_TYPE_I4 or etype == CorElementType.ELEMENT_TYPE_I8 or etype == CorElementType.ELEMENT_TYPE_I2

cdef bint is_cortype_unsigned(CorElementType etype):
    """ Returns True if a cortype represents an unsigned number, False otherwise.
    """
    return etype == CorElementType.ELEMENT_TYPE_U or etype == CorElementType.ELEMENT_TYPE_U1 or etype == CorElementType.ELEMENT_TYPE_U4 or etype == CorElementType.ELEMENT_TYPE_U8 or etype == CorElementType.ELEMENT_TYPE_U2 or etype == CorElementType.ELEMENT_TYPE_CHAR

cpdef net_sigs.CorLibTypeSig get_cor_type_from_name(bytes type_name):
    """ Obtain the CorLibTypeSig of a type from its name.

    Returns:
        net_sigs.CorLibTypeSig: The cortypesig corresponding to type_name or None if not supported.
    """
    if type_name == b'System.Void':
        return net_sigs.get_CorSig_Void()
    elif type_name == b'System.Int8':
        return net_sigs.get_CorSig_SByte()
    elif type_name == b'System.UInt8':
        return net_sigs.get_CorSig_Byte()
    elif type_name == b'System.Int16':
        return net_sigs.get_CorSig_Int16()
    elif type_name == b'System.UInt16':
        return net_sigs.get_CorSig_UInt16()
    elif type_name == b'System.Int32':
        return net_sigs.get_CorSig_Int32()
    elif type_name == b'System.UInt32':
        return net_sigs.get_CorSig_UInt32()
    elif type_name == b'System.Int64':
        return net_sigs.get_CorSig_Int64()
    elif type_name == b'System.UInt64':
        return net_sigs.get_CorSig_UInt64()
    elif type_name == b'System.Single':
        return net_sigs.get_CorSig_Single()
    elif type_name == b'System.Double':
        return net_sigs.get_CorSig_Double()
    elif type_name == b'System.String':
        return net_sigs.get_CorSig_String()
    elif type_name == b'System.Boolean':
        return net_sigs.get_CorSig_Boolean()
    elif type_name == b'System.Byte':
        return net_sigs.get_CorSig_Byte()
    elif type_name == b'System.Object':
        return net_sigs.get_CorSig_Object()
    return None