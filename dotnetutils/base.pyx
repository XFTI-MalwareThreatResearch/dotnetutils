#cython: language_level=3
#distutils: language=c++


cdef class DotNetUtilsBaseType:
    """
    This type is used to avoid Cython circular dependency warnings in pxd files.
    """
    pass

cdef class DotNetUtilsPeFileBaseType:
    """
    This type is used to avoid Cython circular dependency warnings in pxd files.
    """
    pass
