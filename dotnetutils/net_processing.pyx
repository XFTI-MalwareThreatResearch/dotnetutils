#cython: language_level=3
#distutils: language=c++

import warnings
import binascii
from dotnetutils import net_exceptions
from dotnetutils cimport dotnetpefile, net_tokens, net_table_objects, net_structs, net_row_objects
from libcpp.vector cimport vector
from libc.stdint cimport uint64_t
from cpython.ref cimport PyObject, Py_INCREF, Py_XDECREF
from dotnetutils cimport net_cil_disas, net_opcodes

cdef unsigned long read_compressed_int(bytearray data):
    cdef unsigned long result = data[0]
    if (result & 0x80) == 0:
        pass
    elif (result & 0xC0) == 0x80:
        result = ((result & 0x3F) << 8) | data[1]
    else:
        result = ((result & 0x1F) << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
    return result

cdef int read_compressed_int_size(bytearray data):
    cdef int result
    cdef int size = data[0]
    if (size & 0x80) == 0:
        return 1
    elif (size & 0xC0) == 0x80:
        return 2
    else:
        return 4

cdef unsigned long read_compressed_int1(bytes data):
    cdef unsigned long result = data[0]
    if (result & 0x80) == 0:
        pass
    elif (result & 0xC0) == 0x80:
        result = ((result & 0x3F) << 8) | data[1]
    else:
        result = ((result & 0x1F) << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
    return result

cdef int read_compressed_int_size1(bytes data):
    cdef int result
    cdef int size = data[0]
    if (size & 0x80) == 0:
        return 1
    elif (size & 0xC0) == 0x80:
        return 2
    else:
        return 4

cdef class HeapObject:
    """ Heap objects represent various heaps throughout the executable, including #Strings, #GUID, #US, #~.
        General operations for heap objects include replacing items, appending items, deleting items and obtaining items.
    """
    def __init__(self, int offset, int size, bytes name, dotnetpefile.DotNetPeFile dotnetpe):
        self.offset = offset
        self.size = size
        self.name = name
        self.dotnetpe = dotnetpe
        self.tx_data = bytearray()
        self.in_append_tx = False
        if offset == -1 or name is None or size == -1:
            self.offset = 0
            self.name = None
            self.size = size
        self.read()

    cpdef bytes get_raw_data(self):
        return bytes(self.raw_data)

    cdef void update_bitmask(self, int new_size):
        raise net_exceptions.FeatureNotImplementedException()

    cpdef void begin_append_tx(self):
        """ Append by transaction is a way to quickly add a bunch of things to a heap while only having to patch the binary once.
            Start by calling begin_append_tx().  Then use append_tx() to append all the items, then call end_append_tx().
            The stream itself will not be updated until end_append_tx() is called.
            Attempts to call get_item() for an appended index will result in None until end_append_tx() is called.
        """
        if self.in_append_tx:
            raise net_exceptions.OperationNotSupportedException()
        self.in_append_tx = True

    cpdef void end_append_tx(self):
        """ End the append transaction, patch up the binary and any other structures required.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cpdef int append_tx(self, bytes item):
        """ Append an item within a transaction.  begin_append_tx() must be called beforehand.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cdef void update_offset(self, int offset):
        """ Internal use.  Update the held offset of the heap.
        """
        self.offset = offset
    
    cdef void update_size(self, int size):
        """ Internal use.  Update the size of the stream internally.
        """
        self.size = size

    cpdef int get_offset_of_item(self, object item):
        """ Return an integer representing the offset of a item within the heap, -1 if it doesnt exist.
        """
        cdef int offset = <int>self.raw_data.find(<bytes>item)
        return offset

    cpdef bint is_offset_referenced(self, int offset):
        """ return True if an offset within a stream is refernced somewhere in the binary.
        """
        return False

    cdef bytes compress_integer(self, unsigned long number):
        """ Utility function for compressing integers.
        """
        cdef int b0 = 0
        cdef int b1 = 0
        cdef int b2 = 0
        cdef int b3 = 0
        if number <= 0x7F:
            return bytes([number & 0x7F])
        elif number <= 0x3FFF:
            b0 = <int>(0x80 | ((number >> 8) & 0x3F))
            b1 = <int>(number & 0xFF)
            return bytes([b0, b1])
        else:
            # 110vvvvv vvvvvvvv vvvvvvvv vvvvvvvv
            b0 = <int>(0xC0 | ((number >> 24) & 0x1F))
            b1 = <int>((number >> 16) & 0xFF)
            b2 = <int>((number >> 8) & 0xFF)
            b3 = <int>(number & 0xFF)
            return bytes([b0, b1, b2, b3])

    cdef void update(self, int old_value, int new_value, int difference):
        """ Internal method used to update references to a stream when the stream has been modified in a way that requires it.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cpdef bytes to_bytes(self):
        return bytes(self.raw_data)
    
    cdef void read(self):
        """ Responsible for reading and handling the heap data.
        """
        self.raw_data = bytearray((<dotnetpefile.DotNetPeFile>self.dotnetpe).get_exe_data()[self.offset:self.offset+self.size])

    cpdef list get_items(self):
        """ Return a list of all items within the heap.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cpdef bytes get_name(self):
        """ Obtain the name of the stream.
        """
        return self.name

    cpdef int get_offset(self):
        """ Obtain the offset of the heap.
        """
        return self.offset

    cpdef int get_size(self):
        """ Obtain the size of the heap.
        """
        return self.size

    cpdef int replace_item(self, int offset, object item):
        """ Replace heap item at offset with item. 
            Returns the difference between the size of the new heap and the old heap.
        """
        raise net_exceptions.FeatureNotImplementedException()
    
    cpdef int append_item(self, object item):
        """ Append an item onto the end of a heap. Returns the offset of the appended item.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cpdef object get_item(self, int offset):
        """ Obtains an item within a heap at offset.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cdef bytes read_item(self, int offset):
        """ Used to read heap items internally.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cpdef bint has_offset(self, int offset):
        """ Does an offset exist within a heap?
        """
        return 0 < offset < self.get_size()

    cpdef bint has_item(self, object item):
        """ Does a heap have item?
        """
        cdef Py_ssize_t offset = self.raw_data.find(<bytes>item)
        return offset != -1

    cpdef int del_item(self, int offset):
        """ Removes the item at offset from a heap. Returns the difference in size between the new and old heaps.
        """
        raise net_exceptions.FeatureNotImplementedException()

    cpdef int get_next_append_index(self):
        """ Return the next index an item would be appended to for a heap.  This can be useful for append operations when you need to know
            where the next item will be appended beforehand.
        Returns:
            int: The next index where an item would be appended to.
        """
        raise net_exceptions.FeatureNotImplementedException()

    def __len__(self):
        return len(self.raw_data)

cdef class StringHeapObject(HeapObject):
    def __init__(self, int offset, int size, bytes name, dotnetpefile.DotNetPeFile dotnetpe):
        HeapObject.__init__(self, offset, size, name, dotnetpe)
        self.metadata_references = dict()
        self.__build_metadata_references()

    cdef void read(self):
        cdef int index = 0
        self.amt_trailing_zeroes = 0
        self.raw_data = bytearray((<dotnetpefile.DotNetPeFile>self.dotnetpe).get_exe_data()[self.offset:self.offset + self.size])
        index = <int>len(self.raw_data) - 1
        while self.raw_data[index] == 0:
            self.amt_trailing_zeroes += 1
            index -= 1

        self.amt_trailing_zeroes -= 1
        if self.amt_trailing_zeroes < 0:
            self.amt_trailing_zeroes = 0

    cdef void __build_metadata_references(self):
        cdef str table_name = None
        cdef dict table_types = None
        cdef str col_name = None
        cdef net_tokens.BaseToken token = None
        for table_name, table_types in net_table_objects.NET_METADATA_TABLE_HANDLERS.values():
            for col_name, token in table_types.items():
                if token == net_tokens.get_StringsStream():
                    if table_name not in self.metadata_references:
                        self.metadata_references[table_name] = list()
                    self.metadata_references[table_name].append(col_name)

    cpdef void end_append_tx(self):
        cdef int x = 0
        cdef int new_offset = 0
        cdef uint64_t va_addr = 0
        if not self.in_append_tx:
            raise net_exceptions.OperationNotSupportedException()
        self.in_append_tx = False
        if len(self.tx_data) == 0:
            return
        self.update_bitmask(<int>len(self.tx_data) + self.get_size())
        if self.amt_trailing_zeroes > 0:
            self.raw_data = self.raw_data[:-1 * self.amt_trailing_zeroes]
        new_offset = <int>len(self.raw_data)
        self.raw_data.extend(self.tx_data)
        for x in range(self.amt_trailing_zeroes):
            self.raw_data.append(0)
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + new_offset)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, <int>len(self.tx_data), b'#Strings', va_addr - new_offset, None, 0, False)
        self.tx_data = bytearray()

    cdef void update_bitmask(self, int new_size):
        cdef MetadataTableHeapObject heap_obj = <MetadataTableHeapObject>(<dotnetpefile.DotNetPeFile>self.dotnetpe).get_heap('#~')
        cdef int heap_offset_size = heap_obj.get_header().get_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_STRINGS)
        cdef int old_metadata_size = heap_obj.get_size()
        cdef uint64_t va_addr = 0
        cdef int difference = 0
        if heap_offset_size == 2 and new_size > 65535:
            heap_obj.get_header().set_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_STRINGS, 4)
        elif heap_offset_size == 4 and new_size <= 65535:
            heap_obj.get_header().set_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_STRINGS, 2)
        difference = <int>len(heap_obj.to_bytes()) - old_metadata_size
        if difference == 0:
            return
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(heap_obj.get_offset() + old_metadata_size)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#~', va_addr - old_metadata_size, None, 0, False)    

    cpdef int append_tx(self, bytes item):
        cdef int new_offset = 0
        cdef bytearray new_item = bytearray(item)
        if not self.in_append_tx:
            raise net_exceptions.OperationNotSupportedException()
        if len(item) > 0 and item[-1] != 0:
            new_item.append(0)
        new_offset = <int>self.tx_data.find(new_item)
        if new_offset <= 0:
            new_offset = <int>self.raw_data.find(new_item)
            if new_offset <= 0:
                new_offset = self.get_size() + <int>len(self.tx_data) - self.amt_trailing_zeroes
                self.tx_data.extend(new_item)
        else:
            new_offset = self.get_size() + new_offset - self.amt_trailing_zeroes
        return new_offset

    cpdef bint is_offset_referenced(self, int offset):
        cdef str table_name = None
        cdef list col_names = None
        cdef str col_name = None
        cdef net_table_objects.TableObject table_obj = None
        cdef net_row_objects.RowObject row_obj = None
        cdef net_row_objects.ColumnValue col_val = None
        cdef int start_offset = offset
        cdef int end_offset = 0
        if self.in_append_tx:
            raise Exception()
        if offset > 0:
            if self.raw_data[offset-1] != 0:
                while start_offset > 0 and self.raw_data[start_offset] != 0:
                    start_offset -= 1
        
        end_offset = offset
        while end_offset < self.get_size() and self.raw_data[end_offset] != 0:
            end_offset += 1
        #above is for partial reference handling, something specific to the #string heap.
        for table_name, col_names in self.metadata_references.items():
            table_obj = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
            if table_obj is None:
                continue
            for row_obj in table_obj:
                for col_name in col_names:
                    col_val = row_obj.get_column(col_name)
                    if start_offset <= <int>col_val.get_raw_value() <= end_offset:
                        return True
        return False

    cdef void update(self, int old_value, int new_value, int difference):
        cdef int offset = 0
        cdef Py_ssize_t x = 0
        cdef Py_ssize_t y = 0
        cdef Py_ssize_t z = 0
        cdef str table_name = None
        cdef list col_names = None
        cdef str col_name = None
        cdef bytes old_item = None
        cdef net_row_objects.ColumnValue col_val = None
        cdef net_table_objects.TableObject table_object = None
        cdef net_row_objects.RowObject row_object = None
        if difference == 0:
            return
        #Next update the tokens within the metadata tables
        #Strings items can only really be in the metadata heap as far as im aware.
        for table_name, col_names in self.metadata_references.items():
            table_object = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
            if table_object is None:
                continue
            for row_object in table_object:
                for col_name in col_names:
                    col_val = row_object.get_column(col_name)
                    if col_val.get_raw_value() == <unsigned int>old_value and new_value == -1:
                        warnings.warn('Attempting to delete a #Strings object that is still in use')
                    if col_val.get_raw_value() > <unsigned int>old_value:
                        col_val.set_raw_value(col_val.get_raw_value() + difference)
            
    def __len__(self):
        return len(self.raw_data)

    #Something to note: sometimes compilers will pack two strings together - e.x get_Is64BitOperatingSystem and System.
    #These methods dont really handle that and I dont really want to support that.
    cpdef int replace_item(self, int offset, object item):
        cdef bytes b = <bytes> item
        cdef bytes old_item = None
        cdef int difference = 0
        cdef bytes bitem = None
        cdef int off = 0
        cdef uint64_t va_addr
        if len(b) and b[-1] != 0:
            b += b'\x00'
        if not self.has_offset(offset):
            raise net_exceptions.InvalidArgumentsException()
        old_item = self.read_item(offset)
        if old_item is None:
            raise net_exceptions.InvalidArgumentsException()
        difference = <int>(len(b) - len(old_item))
        #first replace in raw_data
        self.update_bitmask(self.get_size() + difference)
        self.raw_data = self.raw_data[:offset] + b + self.raw_data[offset + len(old_item):]
        self.update(offset, offset, difference)
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#Strings', va_addr - offset, None, 0, False)
        return difference

    cpdef int append_item(self, object item):
        cdef bytes b = <bytes> item
        cdef int new_offset = <int>len(self.raw_data)
        cdef int potential = 0
        cdef uint64_t va_addr = 0
        if len(b) > 0 and b[-1] != 0:
            b += b'\x00'
        potential = self.get_offset_of_item(b)
        if potential == -1:
            #we need to make sure were appending at the last item.
            self.update_bitmask(self.get_size() + <int>len(b))
            if self.amt_trailing_zeroes > 0:
                #Take care of any extra 0s on the end.
                self.raw_data = self.raw_data[:-1 * self.amt_trailing_zeroes]
                new_offset = <int>len(self.raw_data)
            self.raw_data += b
            if self.amt_trailing_zeroes > 0:
                self.raw_data += (b'\x00'*self.amt_trailing_zeroes)
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + new_offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, <int>len(b), b'#Strings', va_addr - new_offset, None, 0, False)
            return new_offset
        else:
            return potential

    cpdef int get_next_append_index(self):
        return <int>len(self.raw_data) - self.amt_trailing_zeroes

    cpdef bint has_offset(self, int offset):
        return 0 < offset < self.get_size()

    cdef bytes read_item(self, int offset):
        cdef Py_ssize_t end_index = 0
        cdef int tx_offset = 0
        if not self.has_offset(offset):
            return None
        end_index = self.raw_data.find(b'\x00', offset)
        if end_index == -1:
            return None
        return bytes(self.raw_data[offset:end_index+1])

    cpdef object get_item(self, int offset):
        cdef bytes item = self.read_item(offset)
        if item is None:
            return item
        #we have a case here where two strings are concated together.
        #Just read the string as bytes from the raw data for now.
        return item[:-1] #Read as raw bytes then strip zero terminator

    cpdef list get_items(self):
        cdef list result = list()
        cdef bytes item = None
        cdef int index = 1
        if len(self.raw_data) == 0:
            return result
        while index < self.get_size():
            item = self.read_item(index)
            index += <int>len(item)
            result.append(item[:-1])
        return result

    cpdef int del_item(self, int offset):
        if not self.has_offset(offset):
            raise net_exceptions.InvalidArgumentsException()
        cdef bytes item = self.read_item(offset)
        cdef int difference = -1 * <int>len(item)
        cdef int off = 0
        cdef uint64_t va_addr = 0
        if not self.is_offset_referenced(offset):
            self.update_bitmask(self.get_size() + difference)
            self.raw_data = self.raw_data[:offset] + self.raw_data[offset + len(item):]
            self.update(offset, -1, difference)
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#Strings', va_addr - offset, None, 0, False)
            return difference
        else:
            warnings.warn('Attempting to delete a string item that is currently referenced.  Ignoring.')
            return 0

cdef class BlobHeapObject(HeapObject):
    def __init__(self, int offset, int size, bytes name, dotnetpefile.DotNetPeFile dotnetpe):
        HeapObject.__init__(self, offset, size, name, dotnetpe)
        self.metadata_references = dict()
        self.__build_metadata_references()

    cdef void read(self):
        self.raw_data = bytearray((<dotnetpefile.DotNetPeFile>self.dotnetpe).get_exe_data()[self.offset:self.offset + self.size])

    cdef void update_bitmask(self, int new_size):
        cdef MetadataTableHeapObject heap_obj = <MetadataTableHeapObject>(<dotnetpefile.DotNetPeFile>self.dotnetpe).get_heap('#~')
        cdef int heap_offset_size = heap_obj.get_header().get_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_BLOB)
        cdef int old_metadata_size = heap_obj.get_size()
        cdef uint64_t va_addr = 0
        cdef int difference = 0
        if heap_offset_size == 2 and new_size > 65535:
            heap_obj.get_header().set_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_BLOB, 4)
        elif heap_offset_size == 4 and new_size <= 65535:
            heap_obj.get_header().set_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_BLOB, 2)
        difference = <int>len(heap_obj.to_bytes()) - old_metadata_size
        if difference == 0:
            return
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(heap_obj.get_offset() + old_metadata_size)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#~', va_addr - old_metadata_size, None, 0, False)        


    cdef void __build_metadata_references(self):
        cdef str table_name = None
        cdef dict table_types = None
        cdef str col_name = None
        cdef net_tokens.BaseToken token = None
        for table_name, table_types in net_table_objects.NET_METADATA_TABLE_HANDLERS.values():
            for col_name, token in table_types.items():
                if token == net_tokens.get_BlobStream():
                    if table_name not in self.metadata_references:
                        self.metadata_references[table_name] = list()
                    self.metadata_references[table_name].append(col_name)

    cpdef bint is_offset_referenced(self, int offset):
        cdef str table_name = None
        cdef list col_names = None
        cdef str col_name = None
        cdef net_table_objects.TableObject table_obj = None
        cdef net_row_objects.RowObject row_obj = None
        cdef net_row_objects.ColumnValue col_val = None
        for table_name, col_names in self.metadata_references.items():
            table_obj = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
            if table_obj is None:
                continue
            for row_obj in table_obj:
                for col_name in col_names:
                    col_val = row_obj.get_column(col_name)
                    if <int>col_val.get_raw_value() == offset:
                        return True

        return False

    cdef void update(self, int old_value, int new_value, int difference):
        cdef int offset = 0
        cdef Py_ssize_t x = 0
        cdef Py_ssize_t y = 0
        cdef Py_ssize_t z = 0
        cdef str table_name = None
        cdef list col_names = None
        cdef str col_name = None
        cdef bytes old_item = None
        cdef net_row_objects.ColumnValue col_val = None
        cdef net_table_objects.TableObject table_object = None
        cdef net_row_objects.RowObject row_object = None
        #If new_value is -1, treat it as a removal.
        #First update the listings in the stream itself
        #self.raw_data should already be taken care of by the caller.

        #Next update the tokens within the metadata tables
        for table_name, col_names in self.metadata_references.items():
            table_object = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
            if table_object is None:
                continue
            for row_object in table_object:
                for col_name in col_names:
                    col_val = row_object.get_column(col_name)
                    if col_val.get_raw_value() == <unsigned int>old_value and new_value == -1:
                        warnings.warn('Attempting to delete a blob value that is still in use.')
                    if col_val.get_raw_value() > <unsigned int>old_value:
                        col_val.set_raw_value(col_val.get_raw_value() + difference)
        
    def __len__(self):
        return len(self.raw_data)

    cdef bytes read_item(self, int offset):
        if not self.has_offset(offset):
            return None
        cdef int cpres_size = read_compressed_int(self.raw_data[offset:])
        cdef int cpres_len = read_compressed_int_size(self.raw_data[offset:])
        if not self.has_offset(cpres_size + offset + cpres_len - 1):
            return None
        return bytes(self.raw_data[offset:offset+cpres_len+cpres_size])

    cpdef int replace_item(self, int offset, object item):
        if not self.has_offset(offset):
            return 0
        cdef bytes b = <bytes> item
        cdef bytes compressed_size = self.compress_integer(<unsigned long>len(b))
        cdef bytes orig_item = self.read_item(offset)
        cdef bytes final = compressed_size + b
        cdef bytes bitem = None
        cdef uint64_t va_addr = 0
        cdef int difference = <int>(len(final) - len(orig_item))
        self.update_bitmask(self.get_size() + difference)
        self.raw_data = self.raw_data[:offset] + final + self.raw_data[offset + len(orig_item):]
        self.update(offset, offset, difference)
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe( va_addr, difference, b'#Blob', va_addr - offset, None, 0, False)
        return difference

    cpdef bint has_item(self, object item):
        cdef Py_ssize_t index = self.raw_data.find(self.compress_integer(<unsigned long>len(item)) + item)
        return index != -1

    cpdef int append_item(self, object item):
        cdef int offset = <int>len(self.raw_data)
        cdef bytes final = self.compress_integer(<unsigned long>len(item)) + <bytes>item
        cdef int potential = self.get_offset_of_item(final)
        cdef uint64_t va_addr = 0
        if potential == -1:
            self.update_bitmask(self.get_size() + <int>len(final))
            self.raw_data += final
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, <int>len(final), b'#Blob', va_addr - offset, None, 0, False)
            return offset
        else:
            return potential

    cpdef int get_next_append_index(self):
        return <int>len(self.raw_data)

    cpdef object get_item(self, int offset):
        cdef bytes result = self.read_item(offset)
        if result is not None:
            return result[read_compressed_int_size1(result):]
        return result
    
    cpdef int del_item(self, int offset):
        if not self.has_offset(offset):
            return 0
        cdef bytes item = <bytes>self.read_item(offset)
        cdef int difference = <int>len(item) * -1
        cdef int off = 0
        cdef uint64_t va_addr = 0
        if not self.is_offset_referenced(offset):
            self.update_bitmask(self.get_size() + difference)
            self.raw_data = self.raw_data[:offset] + self.raw_data[offset + len(item):]
            self.update(offset, -1, difference)
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#Blob', va_addr - offset, None, 0, False)
            return difference
        else:
            warnings.warn('Attempting to delete an item that is currently referenced')
            return 0

    cpdef list get_items(self):
        raise Exception() #TODO

cdef class GuidHeapObject(HeapObject):
    def __init__(self, int offset, int size, bytes name, dotnetpefile.DotNetPeFile dotnetpe):
        HeapObject.__init__(self, offset, size, name, dotnetpe)
        self.metadata_references = dict()
        self.__build_metadata_references()

    cdef void __build_metadata_references(self):
        cdef str table_name = None
        cdef dict table_types = None
        cdef str col_name = None
        cdef net_tokens.BaseToken token = None
        for table_name, table_types in net_table_objects.NET_METADATA_TABLE_HANDLERS.values():
            for col_name, token in table_types.items():
                if token == net_tokens.get_GuidStream():
                    if table_name not in self.metadata_references:
                        self.metadata_references[table_name] = list()
                    self.metadata_references[table_name].append(col_name)

    cdef void update_bitmask(self, int new_size):
        cdef MetadataTableHeapObject heap_obj = <MetadataTableHeapObject>(<dotnetpefile.DotNetPeFile>self.dotnetpe).get_heap('#~')
        cdef int heap_offset_size = heap_obj.get_header().get_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_GUID)
        cdef int old_metadata_size = heap_obj.get_size()
        cdef uint64_t va_addr = 0
        cdef int difference = 0
        if heap_offset_size == 2 and new_size > 65535:
            heap_obj.get_header().set_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_GUID, 4)
        elif heap_offset_size == 4 and new_size <= 65535:
            heap_obj.get_header().set_heap_offset_size(net_structs.CorHeapBitmask.BITMASK_GUID, 2)
        difference = <int>len(heap_obj.to_bytes()) - old_metadata_size
        if difference == 0:
            return
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(heap_obj.get_offset() + old_metadata_size)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#~', va_addr - old_metadata_size, None, 0, False)        

    cpdef bint is_offset_referenced(self, int offset):
        cdef str table_name = None
        cdef list col_names = None
        cdef str col_name = None
        cdef net_table_objects.TableObject table_obj = None
        cdef net_row_objects.RowObject row_obj = None
        cdef net_row_objects.ColumnValue col_val = None
        for table_name, col_names in self.metadata_references.items():
            table_obj = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
            if table_obj is None:
                continue
            for row_obj in table_obj:
                for col_name in col_names:
                    col_val = row_obj.get_column(col_name)
                    if <int>col_val.get_raw_value() == offset:
                        return True

        return False

    cdef void update(self, int old_value, int new_value, int difference):
        cdef int offset = 0
        cdef Py_ssize_t x = 0
        cdef Py_ssize_t y = 0
        cdef Py_ssize_t z = 0
        cdef str table_name = None
        cdef list col_names = None
        cdef str col_name = None
        cdef bytes old_item = None
        cdef net_row_objects.ColumnValue col_val = None
        cdef net_table_objects.TableObject table_object = None
        cdef net_row_objects.RowObject row_object = None
        #If new_value is -1, treat it as a removal.
        #First update the listings in the stream itself
        #self.raw_data should already be taken care of by the caller.
        #Next update the tokens within the metadata tables
        for table_name, col_names in self.metadata_references.items():
            table_object = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
            if table_object is None:
                continue
            for row_object in table_object:
                for col_name in col_names:
                    col_val = row_object.get_column(col_name)
                    if col_val.get_raw_value() == <unsigned int>old_value and new_value == -1:
                        warnings.warn('Attempting to delete a guid value that is still in use.')
                    if col_val.get_raw_value() > <unsigned int>old_value:
                        col_val.set_raw_value(col_val.get_raw_value() + difference)

    cdef void read(self):
        self.raw_data = bytearray((<dotnetpefile.DotNetPeFile>self.dotnetpe).get_exe_data()[self.offset:self.offset + self.size])

    cdef bytes read_item(self, int offset):
        if not self.has_offset(offset) or not self.has_offset(offset + 15):
            return None
        return bytes(self.raw_data[offset:offset+16])

    cpdef object get_item(self, int offset):
        return self.read_item(offset)

    cpdef int del_item(self, int offset):
        cdef int difference = -16
        cdef int off = 0
        cdef uint64_t va_addr = 0
        if not self.has_offset(offset):
            raise net_exceptions.InvalidArgumentsException()
        if not self.is_offset_referenced(offset):
            self.update_bitmask(self.get_size() + difference)
            self.raw_data = self.raw_data[:offset] + self.raw_data[offset + 16:]
            self.update(offset, offset, difference)
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#GUID', va_addr - offset, None, 0, False)
            return difference
        else:
            warnings.warn('Attempting to delete a guid item that is currently referenced.')
            return 0

    cpdef int replace_item(self, int offset, object item):
        if len(item) != 16:
            raise net_exceptions.InvalidArgumentsException()
        if not self.has_offset(offset):
            raise net_exceptions.InvalidArgumentsException()
        self.raw_data = self.raw_data[:offset] + item + self.raw_data[offset + 16:]
        return 0

    cpdef int append_item(self, object item):
        if len(item) != 16:
            raise net_exceptions.InvalidArgumentsException()
        cdef int offset = <int>len(self.raw_data)
        cdef int potential = self.get_offset_of_item(item)
        cdef uint64_t va_addr = 0
        if potential == -1:
            self.update_bitmask(self.get_size() + 16)
            self.raw_data += item
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, <int>len(item), b'#GUID', va_addr - offset, None, 0, False)
            return offset
        return potential

    cpdef int get_next_append_index(self):
        return <int>len(self.raw_data)

cdef class UserStringsHeapObject(HeapObject):
    def __init__(self, int offset, int size, bytes name, dotnetpefile.DotNetPeFile dotnetpe):
        HeapObject.__init__(self, offset, size, name, dotnetpe)
        self.warned = False

    cdef void _fill_methods(self):
        cdef net_table_objects.MethodDefTable table = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table('MethodDef')
        cdef net_row_objects.MethodDef mdef = None
        if table is None:
            return
        for mdef in table:
            Py_INCREF(mdef)
            self.methods.push_back(<PyObject*>mdef)

    cpdef void end_append_tx(self):
        cdef int x = 0
        cdef int new_offset = 0
        cdef uint64_t va_addr = 0
        if not self.in_append_tx:
            raise net_exceptions.OperationNotSupportedException()
        self.in_append_tx = False
        if len(self.tx_data) == 0:
            return
        new_offset = <int>len(self.raw_data)
        self.raw_data.extend(self.tx_data)
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + new_offset)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, <int>len(self.tx_data), b'#US', va_addr - new_offset, None, 0, False)
        self.tx_data = bytearray()

    cpdef int append_tx(self, bytes item):
        cdef int new_offset = 0
        cdef bytearray new_item = bytearray(self.sanitize_input(item))
        if not self.in_append_tx:
            raise net_exceptions.OperationNotSupportedException()
        new_offset = <int>self.tx_data.find(new_item)
        if new_offset <= 0:
            new_offset = <int>self.raw_data.find(new_item)
            if new_offset <= 0:
                new_offset = self.get_size() + <int>len(self.tx_data)
                self.tx_data.extend(new_item)
        else:
            new_offset = self.get_size() + new_offset
        return new_offset

    cdef bytes sanitize_input(self, bytes data):
        cdef bytes b = data
        cdef Py_ssize_t i = 0
        cdef int high_bit = 0
        cdef int hi = 0
        cdef int lo = 0
        if len(b) > 1 and b[0] == 0xFF and b[1] == 0xFE: #Strip BOM
            b = b[2:]
        
        for i in range(0, len(b), 2):
            lo = b[i]
            hi = b[i+1]
            if hi != 0:
                high_bit = 1
                break
            if (0x01 <= lo <= 0x08 or
                0x0E <= lo <= 0x1F or
                lo in (0x27, 0x2D, 0x7F)):
                high_bit = 1
                break
        b += bytes([high_bit])
        return self.compress_integer(<unsigned long>len(b)) + b

    def __dealloc__(self):
        for x in range(self.methods.size()):
            Py_XDECREF(self.methods[x])
        self.methods.clear()

    cdef void read(self):
        self.amt_trailing_zeroes = 0 #TODO: well have to see if any binaries actually exploit this or have checks but in general make sure streams arent less because of padding issues.
        self.raw_data = bytearray((<dotnetpefile.DotNetPeFile>self.dotnetpe).get_exe_data()[self.offset:self.offset + self.size])

    cdef void update(self, int old_value, int new_value, int difference):
        cdef net_table_objects.MethodDefTable table_object = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table('MethodDef')
        cdef net_row_objects.MethodDef method = None
        cdef net_cil_disas.MethodDisassembler disasm = None
        cdef Py_ssize_t y = 0
        cdef size_t x = 0
        cdef net_cil_disas.Instruction instr = None
        cdef int argument_token = 0
        cdef bytes new_instr = None
        cdef int off = 0
        cdef bytes item = None
        cdef bytes instr_argument = None

        if not self.warned:
            warnings.warn('Hot patching #US items will only change references in present code.  This may cause issues if code is encrypted.')
            self.warned = True
        for x in range(self.methods.size()):
            method = <net_row_objects.MethodDef>self.methods.at(x)
            if method.has_body():
                disasm = method.disassemble_method()
                if disasm is None:
                    continue
                for y in range(len(disasm)):
                    instr = disasm.get_instr_at_index(<int>y)
                    if instr.get_opcode() == net_opcodes.Opcodes.Ldstr:
                        #This isnt a good idea.  rework instruction arguments a bit to prevent the python calls here.
                        argument_token = int.from_bytes(bytes(instr.get_arguments()), 'little')
                        argument_token = net_tokens.get_Signature().decode_token(argument_token)[1]
                        if argument_token == old_value and new_value == -1:
                            warnings.warn('Attempting to delete a #US token that is still in use.')
                        if argument_token > old_value:
                            argument_token += difference
                            argument_token = net_tokens.get_Signature().encode_token('#US', argument_token)
                            instr_argument = int.to_bytes(argument_token, 4, 'little')
                            instr.setup_arguments_from_int32(argument_token)
                            new_instr = b'\x72' + instr_argument
                            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_instruction(method, new_instr, instr.get_instr_offset(), <unsigned long>len(instr))

    cpdef bint is_offset_referenced(self, int offset):
        cdef int argument = 0
        cdef net_row_objects.MethodDef method_obj = None
        cdef unsigned int index = 0
        cdef Py_ssize_t x = 0
        cdef net_cil_disas.MethodDisassembler disasm_obj = None
        cdef net_cil_disas.Instruction instr = None
        for index in range(self.methods.size()):
            method_obj = <net_row_objects.MethodDef>self.methods.at(index)
            if method_obj.has_body():
                disasm_obj = method_obj.disassemble_method()
                if disasm_obj is None:
                    continue
                for x in range(len(disasm_obj)):
                    instr = disasm_obj.get_instr_at_index(<int>x)
                    if instr.get_opcode() == net_opcodes.Opcodes.Ldstr:
                        #TODO: cleanup how instruction arguments work.
                        argument = int.from_bytes(bytes(instr.get_arguments()), 'little')
                        argument = net_tokens.get_Signature().decode_token(argument)[1]
                        if argument == offset:
                            return True
        return False

    cdef void register_method(self, net_row_objects.MethodDef method):
        #For if method patching is ever allowed.
        Py_INCREF(method)
        self.methods.push_back(<PyObject*>method)

    cdef bytes read_item(self, int offset):
        if not self.has_offset(offset):
            return None
        cdef int cpres_size = read_compressed_int(self.raw_data[offset:])
        cdef int cpres_len = read_compressed_int_size(self.raw_data[offset:])
        if not self.has_offset(offset + cpres_size + cpres_len - 1):
            return None
        return bytes(self.raw_data[offset:offset+cpres_size+cpres_len])

    cpdef object get_item(self, int offset):
        cdef bytes item  = self.read_item(offset)
        if item is None:
            return None
        return item[read_compressed_int_size1(item):][:-1] #strip flag mark.

    cpdef int del_item(self, int offset):
        if not self.has_offset(offset):
            return 0
        cdef bytes old_item = self.read_item(offset)
        cdef int difference = 0
        cdef int off = 0
        cdef uint64_t va_addr = 0
        if old_item is None:
            return 0
        difference = <int>len(old_item) * -1
        if not self.is_offset_referenced(offset):
            self.raw_data = self.raw_data[:offset] + self.raw_data[offset + len(old_item):]
            self.update(offset, -1, difference)
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#US', va_addr - offset, None, 0, False)
            return difference
        else:
            warnings.warn('cant delete item because its referenced')
            return 0

    cpdef int replace_item(self, int offset, object item):
        if not self.has_offset(offset):
            return 0
        cdef bytes old_item = self.read_item(offset)
        cdef bytes b = <bytes>item
        cdef bytes final = None
        cdef int difference = 0
        cdef int off = 0
        cdef bytes bitem = None
        cdef uint64_t va_addr = 0
        if b is None:
            return 0
        final = self.sanitize_input(b)
        difference = <int>(len(final) - len(old_item))
        self.raw_data = self.raw_data[:offset] + final + self.raw_data[offset + len(old_item):]
        self.update(offset, offset, difference)
        va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + offset)
        (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, difference, b'#US', va_addr - offset, None, 0, False)
        return difference

    cpdef int append_item(self, object item):
        cdef bytes b = <bytes>item
        cdef bytes final = None
        cdef int new_offset = <int>len(self.raw_data)
        cdef int potential = 0
        cdef uint64_t va_addr = 0
        final = self.sanitize_input(b)
        potential = self.get_offset_of_item(final)
        if potential == -1:
            if self.amt_trailing_zeroes > 0:
                #Take care of any extra 0s on the end.
                self.raw_data = self.raw_data[:-1 * self.amt_trailing_zeroes]
                new_offset = <int>len(self.raw_data)
            self.raw_data += final
            if self.amt_trailing_zeroes > 0:
                self.raw_data += (b'\x00'*self.amt_trailing_zeroes)
            va_addr = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_pe().get_rva_from_offset(self.get_offset() + new_offset)
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).patch_dpe(va_addr, <int>len(final), b'#US', va_addr - new_offset, None, 0, False)
            return new_offset
        else:
            return potential #Dont append if it already exists.

    cpdef int get_next_append_index(self):
        return <int>len(self.raw_data) - self.amt_trailing_zeroes

    cpdef list get_items(self):
        cdef list result = list()
        cdef bytes item = None
        cdef size_t x = 0
        cdef Py_ssize_t y = 0
        cdef net_row_objects.MethodDef mdef = None
        cdef net_cil_disas.MethodDisassembler disasm = None
        cdef net_cil_disas.Instruction instr = None
        cdef int argument = 0
        for x in range(self.methods.size()):
            mdef = <net_row_objects.MethodDef>self.methods.at(x)
            if mdef.has_body():
                disasm = mdef.disassemble_method()
                if disasm is None:
                    continue
                for y in range(len(disasm)):
                    instr = disasm.get_instr_at_index(<int>y)
                    if instr.get_opcode() == net_opcodes.Opcodes.Ldstr:
                        argument = int.from_bytes(instr.get_arguments(), 'little', signed=False)
                        argument = net_tokens.get_Signature().decode_token(argument)[1]
                        item = self.get_item(argument)
                        if item is not None:
                            result.append(item)
        return result

cdef class MetadataTableHeapObject(HeapObject):
    
    def __init__(self, int offset, int size, bytes name, dotnetpefile.DotNetPeFile dotnetpe):
        HeapObject.__init__(self, offset, size, name, dotnetpe)

    cpdef net_table_objects.MetadataTableHeader get_header(self):
        return self.header

    cdef void read(self):
        cdef unsigned long tables_curr_offset = 0
        cdef int table_id
        cdef int table_amt_rows
        cdef str tbl_name
        cdef dict col_type_handler
        cdef list obj_rows
        cdef bint fill_sizes
        cdef list sizes
        cdef int x
        cdef list raw_row
        cdef unsigned long row_offset
        cdef str field_name
        cdef net_tokens.BaseToken field_type
        cdef int size_of_value
        cdef net_structs.CorHeapBitmask bitmask
        cdef list table_ids
        cdef int identifier
        cdef unsigned long field_value
        cdef unsigned long rid
        cdef int ref_table_id
        cdef net_table_objects.TableObject current_table = None
        cdef bytes file_data = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_exe_data()
        cdef unsigned long table_start_offset = 0
        cdef unsigned long actual_table_size = 0
        cdef unsigned long expected_table_size = 0
        self.header = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_dir().get_metadata_table_header()
        self.items = dict()
        self.end_offset = 0
        tables_curr_offset = self.header.end_offset
        table_start_offset = tables_curr_offset
        self.raw_data = bytearray(file_data[self.offset:self.offset+self.size])
        for table_id, table_amt_rows in self.header.table_amt_rows:
            if table_id not in net_table_objects.NET_METADATA_TABLE_HANDLERS:
                raise net_exceptions.FeatureNotImplementedException('Unknown table {}'.format(table_id))
            tbl_name, col_type_handler = net_table_objects.NET_METADATA_TABLE_HANDLERS[table_id]
            current_table = net_table_objects.NET_METADATA_TABLE_TYPES[tbl_name](self.dotnetpe, tbl_name, table_id)
            fill_sizes = True
            sizes = list()
            for x in range(table_amt_rows):
                raw_row = list()
                row_offset = tables_curr_offset

                for field_name, field_type in col_type_handler.items():
                    if fill_sizes and len(sizes) == len(col_type_handler):
                        fill_sizes = False
                    if field_type is None:
                        raise net_exceptions.InvalidMetadataException
                    if field_type.get_fixed_size() != -1:
                        size_of_value = field_type.get_fixed_size()
                    else:
                        if field_type.is_stream():
                            if field_type.get_token_types()[0] == '#Blob':
                                bitmask = net_structs.CorHeapBitmask.BITMASK_BLOB
                            elif field_type.get_token_types()[0] == '#GUID':
                                bitmask = net_structs.CorHeapBitmask.BITMASK_GUID
                            elif field_type.get_token_types()[0] == '#Strings':
                                bitmask = net_structs.CorHeapBitmask.BITMASK_STRINGS
                            else:
                                raise net_exceptions.FeatureNotImplementedException()
                            size_of_value = self.get_header().get_heap_offset_size(bitmask)
                        else:
                            if len(field_type.get_token_types()) == 1:
                                ref_table_id = net_table_objects.get_table_id_from_name(field_type.get_token_types()[0])
                                size_of_value = net_table_objects.get_single_table_index_size(ref_table_id, self.get_header().table_amt_rows)
                            else:
                                table_ids = list()
                                for table_name in field_type.get_token_types():
                                    if table_name == '':
                                        continue

                                    identifier = net_table_objects.get_table_id_from_name(table_name)
                                    if identifier == -1:
                                        raise net_exceptions.FeatureNotImplementedException()

                                    table_ids.append(identifier)
                                
                                size_of_value = net_table_objects.get_multiple_table_index_size(table_ids,
                                                                              self.get_header().table_amt_rows,
                                                                              field_type.get_bits())
                    
                    field_value = int.from_bytes(file_data[tables_curr_offset:tables_curr_offset + size_of_value], 'little', signed=False)
                    raw_row.append(field_value)
                    
                    tables_curr_offset += size_of_value

                    if fill_sizes:
                        sizes.append(size_of_value)
                raw_row.append(row_offset)
                rid = x + 1
                current_table.add_row(net_row_objects.get_rowobject_for_table(tbl_name)(<dotnetpefile.DotNetPeFile>self.dotnetpe, raw_row, rid, sizes,
                                                                                 col_type_handler, tbl_name))
            self.items[tbl_name] = current_table
        self.end_offset = tables_curr_offset
        self.amt_padding = 0
        expected_table_size = (self.get_size() - (self.header.end_offset - self.header.start_offset))
        actual_table_size = tables_curr_offset - table_start_offset
        if actual_table_size < expected_table_size:
            self.amt_padding = expected_table_size - actual_table_size

    cpdef object get_item(self, int offset):
        raise net_exceptions.FeatureNotImplementedException() #Not allowed use get_table()

    cpdef int del_item(self, int offset):
        raise net_exceptions.FeatureNotImplementedException() #Not allowed

    cpdef int replace_item(self, int offset, object item):
        raise net_exceptions.FeatureNotImplementedException() #Not allowed

    cpdef int append_item(self, object item):
        raise net_exceptions.FeatureNotImplementedException() #Not allowed

    cpdef net_table_objects.TableObject get_table(self, str name):
        if name not in self.items:
            return None
        return self.items[name]

    cdef void process_tables(self):
        cdef net_table_objects.TableObject table = None
        for table in self.items.values():
            table.process()

    cpdef bint has_table(self, str name):
        return name in self.items

    cpdef list present_tables(self):
        return self.items.keys()

    cpdef dict get_tables(self):
        return self.items
    
    cpdef int get_start_offset(self):
        return self.get_offset()

    def __iter__(self):
        return iter(self.items.values())

    cpdef bytes to_bytes(self):
        cdef bytes result
        cdef int table_id
        cdef int amt_rows
        cdef str table_name
        cdef bytes table_bytes
        result = self.get_header().to_bytes()
        for table_id, amt_rows in self.get_header().table_amt_rows:
            table_name, _ = net_table_objects.NET_METADATA_TABLE_HANDLERS[table_id]
            table_bytes = self.get_table(table_name).to_bytes()
            result += table_bytes
        return result + (b'\x00' * self.amt_padding)