#cython: language_level=3

import numpy
from dotnetutils cimport net_emu_types


#some base types.  Might need to rework by making them also support DotNetObject. TODO - check if this should be done.
#I cant really think of a good way to rework dotnetobjects into this or make it into a C type right now.  For now leave it and see what the performance hit is.
class DotNetInt8(numpy.int8):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetInt16(numpy.int16):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetInt32(numpy.int32):
    def CompareTo(self, other):
        return DotNetInt32(self - other)

    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetInt64(numpy.int64):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetUInt8(numpy.uint8):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetUInt16(numpy.uint16):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetUInt32(numpy.uint32):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetUInt64(numpy.uint64):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))
class DotNetSingle(numpy.float32):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetDouble(numpy.float64):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetBoolean(numpy.bool_):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetVoid(numpy.void):
    def ToString(self):
        return net_emu_types.DotNetString(str(self).encode('utf-16le'))

class DotNetChar(numpy.int16):
    def ToString(self):
        b_data = int.to_bytes(self.item(), length=2, byteorder='little', signed=True)
        string = net_emu_types.DotNetString(b_data)
        return string
