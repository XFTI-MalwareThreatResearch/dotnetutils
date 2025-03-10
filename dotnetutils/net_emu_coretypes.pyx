#cython: language_level=3

import numpy
from dotnetutils cimport net_emu_types


#some base types.  Might need to rework by making them also support DotNetObject. TODO - check if this should be done.
#I cant really think of a good way to rework dotnetobjects into this or make it into a C type right now.  For now leave it and see what the performance hit is.

class DotNetNumber:
    def __init__(self, emulator_obj, numpy_dtype, value_obj):
        self.__emulator_obj = emulator_obj
        self.__numpy_dtype = numpy_dtype
        self.__value = numpy_dtype(value_obj)

    def get_value(self):
        return self.__value

    def get_numpy_dtype(self):
        return self.__numpy_dtype

    def get_emulator_obj(self):
        return self.__emulator_obj

    def __str__(self):
        return str(self.__value)

    def __lt__(self, other):
        if isinstance(other, DotNetNumber):
            return self.__value < other.__value
        return self.__value < other

    def __le__(self, other):
        if isinstance(other, DotNetNumber):
            return self.__value <= other.__value
        return self.__value <= other

    def _eq__(self, other):
        if isinstance(other, DotNetNumber):
            return self.__value == other.__value
        return self.__value == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __gt__(self, other):
        if isinstance(other, DotNetNumber):
            return self.__value > other.__value
        return self.__value > other

    def __ge__(self, other):
        if isinstance(other, DotNetNumber):
            return self.__value >= other.__value
        return self.__value >= other

    def __hash__(self):
        return hash(self.__value)

    def __getattr__(self, name):
        if hasattr(self.__value, name):
            return getattr(self.__value, name)
        raise AttributeError

    def __add__(self, other):
        val_obj = self.__value + other.__value
        print('add val obj {} {}'.format(type(val_obj), val_obj))
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __sub__(self, other):
        val_obj = self.__value - other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __mul__(self, other):
        val_obj = self.__value * other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __matmul__(self, other):
        val_obj = self.__value @ other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __truediv__(self, other):
        val_obj = self.__value / other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __floordiv__(self, other):
        val_obj = self.__value // other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __mod__(self, other):
        val_obj = self.__value % other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __divmod__(self, other):
        quotient, remainder = divmod(self.__value, other.__value)
        return DotNetNumber(self.get_emulator_obj(), quotient.dtype, quotient), DotNetNumber(self.get_emulator_obj(), remainder.dtype, remainder)

    def __pow__(self, other, mod=None):
        result = pow(self.__value, other.__value, mod)
        return DotNetNumber(self.get_emulator_obj(), result.dtype, result)

    def __lshift__(self, other):
        val_obj = self.__value << other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __rshift__(self, other):
        val_obj = self.__value >> other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __and__(self, other):
        val_obj = self.__value & other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __xor__(self, other):
        val_obj = self.__value ^ other.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __or__(self, other):
        result = self.__value | other.__value
        return DotNetNumber(self.get_emulator_obj(), result.dtype, result)

    def __iadd__(self, other):
        val_obj = self.__value + other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __isub__(self, other):
        val_obj = self.__value - other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __imul__(self, other):
        val_obj = self.__value * other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __imatmul__(self, other):
        val_obj = self.__value @ other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __itruediv__(self, other):
        val_obj = self.__value / other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __ifloordiv__(self, other):
        val_obj = self.__value // other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __imod__(self, other):
        val_obj = self.__value % other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __ipow__(self, other, mod=None):
        val_obj = pow(self.__value, other.__value, mod)
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __ilshift__(self, other):
        val_obj = self.__value << other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __irshift__(self, other):
        val_obj = self.__value >> other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __iand__(self, other):
        val_obj = self.__value & other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __ixor__(self, other):
        val_obj = self.__value ^ other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __ior__(self, other):
        val_obj = self.__value | other.__value
        self.__value = val_obj
        self.__numpy_dtype = val_obj.dtype
        return self

    def __neg__(self):
        val_obj = -self.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __pos__(self):
        val_obj = +self.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __abs__(self):
        val_obj = abs(self.__value)
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __invert__(self):
        val_obj = ~self.__value
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

    def __round__(self, ndigits=None):
        val_obj = round(self.__value, ndigits)
        return DotNetNumber(self.get_emulator_obj(), val_obj.dtype, val_obj)

class DotNetInt8(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.int8, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetInt16(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.int16, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetInt32(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.int32, value_obj)

    def CompareTo(self, other):
        return DotNetInt32(self.get_emulator_obj(), self - other)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetInt64(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.int64, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetUInt8(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.uint8, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetUInt16(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.uint16, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetUInt32(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.uint32, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetUInt64(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.uint64, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetSingle(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.float32, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetDouble(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.float64, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetBoolean(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.bool_, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetVoid(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.void, value_obj)

    def ToString(self):
        return net_emu_types.DotNetString(self.get_emulator_obj(), str(self).encode('utf-16le'))

class DotNetChar(DotNetNumber):
    def __init__(self, emulator_obj, value_obj):
        DotNetNumber.__init__(self, emulator_obj, numpy.int16, value_obj)

    def ToString(self):
        b_data = int.to_bytes(self.item(), length=2, byteorder='little', signed=True)
        string = net_emu_types.DotNetString(self.get_emulator_obj(), b_data)
        return string
