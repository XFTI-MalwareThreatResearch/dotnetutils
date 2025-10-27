#cython: language_level=3
#distutils: language=c++

from libc.stdint cimport uint64_t, uint32_t, int32_t, int64_t
from cpython.ref cimport PyObject

""" Used to store ELEMENT_TYPE_BYREF objects.

Attributes:
    kind (int): The type of ref.  1 is ldloca, 2 is ldsflda, 3 is ldelema, 4 is ldflda, 5 is ldarga
    idx (int64_t): the index or RID of the reference.
    owner (void*): For ldloca it will be a DotNetEmulator object, for ldsflda it will be a DotNetEmulator object, for ldsfld it will be a SlimObject*, for ldloca it will be a DotNetEmulator object.
"""
cdef struct ByRefItem:
    int kind
    int64_t idx
    void * owner

""" Used to represent objects which dont require any additional methods (TypeDefs usually).
    Takes up a lot less memory than DotNetObject

Attributes:
    type_token (int): The token of the type (TypeDefOrRef token)
    fields (StackCell *) An array which represents the fields that an object has.
    num_fields (int): The number of fields the object has.
    refs (int): A reference counter for the object.  Prevents early frees.
"""
cdef struct SlimObject:
    int type_token
    StackCell * fields
    int num_fields
    int refs

""" A union which represents all possible values for a stack cell.
    i1 (char): ELEMENT_TYPE_I1
    i2 (short): ELEMENT_TYPE_I2
    i4 (int32_t): ELEMENT_TYPE_I4 / ELEMENT_TYPE_I
    u1 (unsigned char): ELEMENT_TYPE_U1
    u2 (unsigned short): ELEMENT_TYPE_U2 / ELEMENT_TYPE_CHAR
    u4 (uint32_t): ELEMENT_TYPE_U4 / ELEMENT_TYPE_U
    i8 (int64_t): ELEMENT_TYPE_I8 / ELEMENT_TYPE_I
    u8 (uint64_t): ELEMENT_TYPE_U8 / ELEMENT_TYPE_U
    r4 (float): ELEMENT_TYPE_R4
    r8 (double): ELEMENT_TYPE_R8
    b (bint): ELEMENT_TYPE_BOOLEAN
    ref (PyObject*): ELEMENT_TYPE_OBJECT / ELEMENT_TYPE_STRING, usually TypeRef or boxed values.
    byref (ByRefItem): ELEMENT_TYPE_BYREF
    slim_object (SlimObject*): ELEMENT_TYPE_OBJECT, usually TypeDefs.
"""
cdef union StackCellItem:
    char i1
    short i2
    int32_t i4
    unsigned char u1
    unsigned short u2
    uint32_t u4
    int64_t i8
    uint64_t u8
    float r4
    double r8
    bint b
    PyObject * ref
    ByRefItem byref
    SlimObject * slim_object

""" A slimmed down version of StackCell for storage where extra fields arent required.

Attributes:
    tag (char): The CorElementType tag.
    is_slim_object (char): 1 if the cell is a slim object, 0 otherwise.
    item (StackCellItem): The item the slim stack cell represents.
"""
cdef struct SlimStackCell:
    char tag
    char is_slim_object
    StackCellItem item

""" Used to represent all sorts of .NET CIL objects.

Attributes:
    tag (char): The CorElementType tag.
    rid (int): Used to store the field's rid when stored in a field.  For internal use.
    item (StackCellItem): The item the slim stack cell represents.
    emulator_obj (PyObject*): Stores the emulator object that created the StackCell
    extra_data (void*) for internal use, currently used for List.Sort().
    is_slim_object (char): 1 if the cell is a slim object, 0 otherwise.
"""
cdef struct StackCell:
    char tag
    int rid
    StackCellItem item
    PyObject * emulator_obj
    void * extra_data
    char is_slim_object