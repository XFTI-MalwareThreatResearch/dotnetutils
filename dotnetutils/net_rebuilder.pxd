#cython: language_level=3
#distutils: language=c++
from dotnetutils.dotnetpefile import DotNetPeFile, PeFile

cdef class NetRebuilder:
    cdef DotNetPeFile __dpefile
    cdef PeFile __pe

    cdef bytes rebuild(self)