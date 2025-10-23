#cython: language_level=3
#distutils: language=c++

from libc.stdint cimport uint64_t, uint32_t, int32_t, int64_t
from cpython.ref cimport PyObject


cdef struct ByRefItem:
    int kind
    int64_t idx
    void * owner

cdef struct SlimObject:
    int type_token
    StackCell * fields
    int num_fields
    int refs

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
    void * vt_data
    PyObject * vt_layout
    SlimObject * slim_object

#For instances where the extra information is not needed.
cdef struct SlimStackCell:
    char tag
    char is_slim_object
    StackCellItem item

cdef struct StackCell:
    char tag
    int rid
    StackCellItem item
    PyObject * emulator_obj
    void * extra_data
    char is_slim_object