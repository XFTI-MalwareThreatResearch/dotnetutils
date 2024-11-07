#cython: language_level=3

from dotnetutils import net_exceptions
from dotnetutils cimport dotnetpefile
import shutil
import binascii
import os


cdef class Stream:
    def __init__(self, raw_data, exe_data, dotnetpe, dummy=False):
        """
        Represents a stream
        :param raw_data: The raw data representing the stream
        :param exe_data: The exe's data
        :param dummy: Is this a dummy object?  Used for patching.
        """
        if not dummy:
            self.offset = raw_data[0]
            self.size = raw_data[1]
            self.name = raw_data[2]
            self.data = bytes(exe_data[self.offset:self.offset + self.size])
        else:
            self.name = None
            self.data = bytes()
            self.size = 0
            self.offset = 0
        self.dotnetpe = dotnetpe

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self):
        return self.dotnetpe

    def __len__(self):
        return len(self.data)

    cpdef bytes get_item(self, unsigned long index):
        """
        Obtain an item from the stream
        :param index: raw index to obtain
        :return: The obtained item
        """
        return None

    cpdef void set_item(self, unsigned long index, bytes value):
        """
        Sets an item in a stream
        :param index: raw index to set
        :param value: value to set
        :return: None
        """
        pass

    cpdef unsigned long del_item(self, unsigned long index):
        """
        Delete item at index
        """
        return -1

    cpdef bytes get_name(self):
        return self.name

    cpdef bytes get_data(self):
        return self.data

    cpdef int get_offset(self):
        return self.offset

    cpdef int get_size(self):
        return self.size

    cpdef Stream make_copy(self):
        """
        Make a dummy copy of the object
        """
        return type(self)(None, self.data, dummy=True)

    def __copy__(self):
        return self.make_copy()

    cpdef Py_ssize_t find_index(self, bytes item):
        """
        Find the index where item is located in the stream
        """
        return 0
    
    cpdef bint has_item(self, bytes item):
        return self.find_index(item) != -1 #THis should work since most heaps start with a few zero bytes.

cdef class StringStream(Stream):

    def __init__(self, raw_data, exe_data, dotnetpe, dummy=False):
        Stream.__init__(self, raw_data, exe_data, dotnetpe, dummy)
        if dummy:
            self.data = bytes([0])

    cpdef bytes get_item(self, unsigned long index):
        """
        Obtains an item at index in the strings stream
        """
        cdef unsigned long start
        cdef bytes result
        start = index
        result = bytes()
        while self.data[start] != 0x0:
            result += bytes([self.data[start]])
            start += 1
        return result

    cpdef Py_ssize_t find_index(self, bytes item):
        """
        Attempts to determine the index of an item within the #Strings stream.
        """
        cdef Py_ssize_t result
        result = self.data.find(item + b'\x00')
        return result

    cpdef unsigned long del_item(self, unsigned long index):
        cdef bytes item
        cdef unsigned long item_len
        item = self.get_item(index)
        item_len = len(item) + 1
        self.data = self.data[:index] + self.data[index + item_len:]
        return item_len

    cpdef list get_items(self):
        """
        Gets all items from the strings stream
        """
        cdef list results
        cdef bytes current
        cdef unsigned long index
        results = list()
        current = b''
        index = 0
        while index < len(self.data):
            if self.data[index] == 0:
                results.append(current)
                current = b''
            else:
                current += bytes([self.data[index]])
            index += 1
        return results

    cpdef void set_item(self, unsigned long index, bytes value):
        """
        NOTE: This function does not do anything
        Figuring out how to specifically set an item within the streams
        gets rediculously complicated so to fix that I would recommend
        just using del_item and append_item.  It results in the same outcome.
        """
        pass

    cpdef unsigned long append_item(self, bytes value):
        """
        Appends an item to the strings stream
        This was a workaround of sorts to get around the complexities
        of set_item - appending doesn't require redoing every stream index
        """
        cdef unsigned long index
        index = len(self.data)
        self.data += value + bytes([0])
        return index


cdef class BlobStream(Stream):

    def __init__(self, raw_data, exe_data, dotnetpe, dummy=False):
        Stream.__init__(self, raw_data, exe_data, dotnetpe, dummy)
        if dummy:
            self.data = bytes([0]) #TODO: is this correct?

    cpdef bytes get_item(self, unsigned long index):
        """
        Obtains an item at index in the Blob stream
        """
        cdef unsigned long size
        cdef unsigned long usable_index
        if index >= len(self.data):
            return None
        size = self.data[index]
        usable_index = index
        if (size & 0x80) == 0:
            usable_index += 1
        elif (size & 0xC0) == 0x80:
            size = ((size & 0x3F) << 8) | self.data[index + 1]
            usable_index += 2
        else:
            size = ((size & 0x1F) << 24) | (self.data[index + 1] << 16) | (self.data[index + 2] << 8) | self.data[
                index + 3]
            usable_index += 4
        return self.data[usable_index:usable_index + size]
        
    cpdef unsigned long del_item(self, unsigned long index):
        cdef unsigned long usable_index
        cdef unsigned long size
        cdef unsigned long old_size
        size = self.data[index]
        usable_index = index
        if (size & 0x80) == 0:
            usable_index += 1
        elif (size & 0xC0) == 0x80:
            size = ((size & 0x3F) << 8) | self.data[index + 1]
            usable_index += 2
        else:
            size = ((size & 0x1F) << 24) | (self.data[index + 1] << 16) | (self.data[index + 2] << 8) | self.data[
                index + 3]
            usable_index += 4
        old_size = len(self.data)
        self.data = self.data[:index] + self.data[usable_index + size:]
        return old_size - len(self.data)
    
    cpdef Py_ssize_t find_index(self, bytes item):
        cdef unsigned long value
        cdef bytes data
        value = len(item)
        data = bytes()
        if value <= 0x7F:
            data += bytes([value])
        elif value <= 0x3FFF:
            data += bytes([((value >> 8) | 0x80) & 0xFF, value & 0xFF])
        elif value <= 0x1FFFFFFF:
            data += bytes([((value >> 24) | 0xC0) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
        else:
            return -1
        
        data += item
        return self.data.find(data)

    cpdef unsigned long append_item(self, bytes raw_value):
        cdef unsigned long index
        cdef unsigned long value
        index = len(self.data)
        value = len(raw_value)
        if value <= 0x7F:
            self.data += bytes([value])
        elif value <= 0x3FFF:
            self.data += bytes([((value >> 8) | 0x80) & 0xFF, value & 0xFF])
        elif value <= 0x1FFFFFFF:
            self.data += bytes([((value >> 24) | 0xC0) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
        else:
            raise net_exceptions.CannotCompressSizeException
        self.data += raw_value
        return index


cdef class GuidStream(Stream):
    cpdef bytes get_item(self, unsigned long index):
        """
        Obtains an item at index in the GUID stream
        """
        return self.data[index:index + 16]

    cpdef unsigned long append_item(self, bytes raw_value):
        if not len(raw_value) == 16:
            raise net_exceptions.InvalidArgumentsException("16 bytes", f"{len(raw_value)} bytes")
        self.data += raw_value
        return 0

    cpdef unsigned long del_item(self, unsigned long index):
        self.data = self.data[:index] + self.data[index + 16:]
        return 16
    
    cpdef Py_ssize_t find_index(self, bytes item):
        cdef Py_ssize_t index
        cdef bytes potential_item
        index = 0
        while index < len(self.data):
            potential_item = self.data[index:index+16]
            if potential_item == item:
                return index
            index += 16
        return -1


cdef class UserStringsStream(Stream):

    cpdef bytes get_item(self, unsigned long index):
        """
        Obtains an item from the user strings stream
        """
        cdef unsigned long size
        cdef unsigned long usable_index
        size = self.data[index]
        usable_index = index
        if (size & 0x80) == 0:
            usable_index += 1
        elif (size & 0xC0) == 0x80:
            size = ((size & 0x3F) << 8) | self.data[index + 1]
            usable_index += 2
        else:
            size = ((size & 0x1F) << 24) | (self.data[index + 1] << 16) | (self.data[index + 2] << 8) | self.data[
                index + 3]
            usable_index += 4
        return self.data[usable_index:usable_index + size - 1]

    cpdef list get_items(self):
        """
        Obtains all items from the user strings stream
        """
        cdef unsigned long index
        cdef list results
        cdef unsigned long size
        cdef unsigned long usable_index
        cdef bytes string
        index = 1
        results = list()
        while index < len(self.data):
            size = self.data[index]
            usable_index = index
            if (size & 0x80) == 0:
                usable_index += 1
            elif (size & 0xC0) == 0x80:
                size = ((size & 0x3F) << 8) | self.data[index + 1]
                usable_index += 2
            else:
                size = ((size & 0x1F) << 24) | (self.data[index + 1] << 16) | (self.data[index + 2] << 8) | self.data[
                    index + 3]
                usable_index += 4

            string = self.data[usable_index: usable_index + size - 1]
            if len(string) != 0:
                results.append(string)

            index = usable_index + size
        return results

    cpdef unsigned long del_item(self, unsigned long index):
        """
        Deletes an item from the User strings stream
        Dont call this method directly, some cleanup is needed to make this work.
        """
        cdef unsigned long size
        cdef unsigned long usable_index
        cdef unsigned long old_size
        size = self.data[index]
        usable_index = index
        if (size & 0x80) == 0:
            usable_index += 1
        elif (size & 0xC0) == 0x80:
            size = ((size & 0x3F) << 8) | self.data[index + 1]
            usable_index += 2
        else:
            size = ((size & 0x1F) << 24) | (self.data[index + 1] << 16) | (self.data[index + 2] << 8) | self.data[
                index + 3]
            usable_index += 4
        old_size = len(self.data)

        self.data = self.data[:index] + self.data[usable_index + size:]
        return old_size - len(self.data)

    cpdef unsigned long append_item_dns(self, object str_item):
        """
        param should be only net_emu_types.DotNetString
        Useful for situations where strings are not exactly readable characters.
        """
        """
        Appends an item to the user strings stream.
        """
        cdef bytes usable
        cdef unsigned long index
        cdef unsigned long value
        cdef int high_bit
        cdef unsigned long x
        cdef int val
        if str_item.get_str_encoding() == 'utf-16le':
            usable = bytes(str_item.get_str_data_as_bytes())
        else:
            usable = bytes(str_item.get_str_data_as_bytes().decode(str_item.get_str_encoding()).encode('utf-16le'))
        if len(self.data) == 0:
            self.data = bytes([0])
        if usable.startswith(b'\xFF\xFE'):
            usable = usable.lstrip(b'\xFF\xFE')  # strip the byte order mark
        index = len(self.data)
        value = len(usable) + 1
        if value <= 0x7F:
            self.data += bytes([value])
        elif value <= 0x3FFF:
            self.data += bytes([((value >> 8) | 0x80) & 0xFF, value & 0xFF])
        elif value <= 0x1FFFFFFF:
            self.data += bytes([((value >> 24) | 0xC0) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
        else:
            raise net_exceptions.CannotCompressSizeException
        self.data += usable
        if not self.data.endswith(b'\x00'):
            self.data += bytes([0])
        high_bit = 0
        for x in range(len(usable)):
            if x % 2 == 0:
                val = usable[x]
                if 0x1 <= val <= 0x8:
                    high_bit = 1
                if 0x0E <= val <= 0x1F:
                    high_bit = 1
                if val == 0x27 or val == 0x2D:
                    high_bit = 1
            else:
                if usable[x] > 0:
                    high_bit = 1
            if high_bit == 1:
                break

        self.data += bytes([high_bit])
        return index


    cpdef unsigned long append_item(self, bytes bstring):
        """
        Appends an item to the user strings stream.
        """
        cdef bytes usable
        cdef unsigned long index
        cdef unsigned long value
        cdef int high_bit
        cdef unsigned long x
        cdef int val
        cdef bytes data_add_buf
        try:
            usable = bstring.decode().encode('utf-16le')
            # TODO: This may be causing issues - maybe just have the user ensure that the strings are UTF-16LE?
        except UnicodeDecodeError:
            usable = bstring
        if len(self.data) == 0:
            self.data = bytes([0])
        if usable.startswith(b'\xFF\xFE'):
            usable = usable.lstrip(b'\xFF\xFE')  # strip the byte order mark
        index = len(self.data)
        value = len(usable) + 1
        data_add_buf = bytes()
        if value <= 0x7F:
            data_add_buf += bytes([value])
        elif value <= 0x3FFF:
            data_add_buf += bytes([((value >> 8) | 0x80) & 0xFF, value & 0xFF])
        elif value <= 0x1FFFFFFF:
            data_add_buf += bytes([((value >> 24) | 0xC0) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
        else:
            raise net_exceptions.CannotCompressSizeException
        data_add_buf += usable
        if not data_add_buf.endswith(b'\x00'):
            data_add_buf += bytes([0])
        high_bit = 0
        for x in range(len(usable)):
            if x % 2 == 0:
                val = usable[x]
                if 0x1 <= val <= 0x8:
                    high_bit = 1
                if 0x0E <= val <= 0x1F:
                    high_bit = 1
                if val == 0x27 or val == 0x2D:
                    high_bit = 1
            else:
                if usable[x] > 0:
                    high_bit = 1
            if high_bit == 1:
                break

        data_add_buf += bytes([high_bit])
        self.data += data_add_buf
        return index
    
    cpdef Py_ssize_t find_index(self, bytes item):
        return -1 #Not actually needed to be implemented as of now. TODO.

    def __len__(self):
        return len(self.data)
