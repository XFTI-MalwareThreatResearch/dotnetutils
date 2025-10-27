#cython: language_level=3
#distutils: language=c++


from dotnetutils.net_structs cimport IMAGE_COR20_HEADER, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
from dotnetutils import net_exceptions
from dotnetutils cimport dotnetpefile
from dotnetutils cimport net_table_objects
from dotnetutils cimport net_processing
from libc.stdint cimport uintptr_t, uint64_t
from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, PyBUF_ANY_CONTIGUOUS


cdef class MetaDataHeader:
    """ Represents the header at the beginning of the section where .NET stores metadata.
        TODO: Swap to a data reader for this class.

    Notes:
        start_offset (int): the file offset of the header.
        signature (int): the signature field.
        majorversion (int): the majorversion field.
        minorversion (int): the minorversion field.
        reserved (int): the reserved field.
        versionstr_length (int): the length of the version string in the header.
        versionstr (bytes): the version string from the header
        flags (int): the flags from the header.
        num_streams (int): Amount of streams contained in the directory.
        streamheaders (list[list[int, int, bytes]]): A list of stream headers, containing offset, size and name.
        end_offset (int): The end offset of the header.
        dotnetpe (dotnetpefile.DotNetPeFile): the current dotnetpe.
    """
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, bytes file_data, long offset):
        """ Construct a new MetadataHeader.

        Args:
            dotnetpe (dotnetpefile.DotNetPeFile): the pe file the header is for.
            file_data (bytes): full file data for executable.
            offset (long): The offset of the header.

        Raises:
            ValueError: if offset isnt provided.
        """
        if offset == -1:
            raise ValueError('invalid metadataheader offset')
        self.start_offset = offset
        self.signature = 0x424A534
        self.majorversion = 0x1
        self.minorversion = 0x1
        self.reserved = 0
        self.versionstr_length = 0
        self.versionstr = None
        self.flags = 0
        self.num_streams = 0
        self.streamheaders = list()
        self.end_offset = 0
        self.dotnetpe = dotnetpe
        self.parse_metadata_header(file_data)

    cdef void parse_metadata_header(self, bytes file_data):
        """ Parse the metadata header from file bytes.

        Args:
            file_data (bytes): the file's byte data.
        """
        cdef int current_offset
        cdef int offset
        cdef int size
        cdef bytes name
        cdef int x
        current_offset = self.start_offset
        self.signature = int.from_bytes(file_data[current_offset: current_offset + 4], 'little')
        current_offset += 4
        self.majorversion = int.from_bytes(file_data[current_offset:current_offset + 2], 'little')
        current_offset += 2
        self.minorversion = int.from_bytes(file_data[current_offset:current_offset + 2], 'little')
        current_offset += 2
        self.reserved = int.from_bytes(file_data[current_offset:current_offset + 4], 'little')
        current_offset += 4
        self.versionstr_length = int.from_bytes(file_data[current_offset:current_offset + 4], 'little')
        current_offset += 4
        self.versionstr = file_data[current_offset:current_offset + self.versionstr_length]
        current_offset += self.versionstr_length
        self.flags = int.from_bytes(file_data[current_offset:current_offset + 2], 'little')
        current_offset += 2
        self.num_streams = int.from_bytes(file_data[current_offset:current_offset + 2], 'little')
        current_offset += 2

        for x in range(self.num_streams):
            offset = int.from_bytes(file_data[current_offset:current_offset + 4], 'little')
            current_offset += 4
            size = int.from_bytes(file_data[current_offset:current_offset + 4], 'little')
            current_offset += 4
            name = bytes()
            while file_data[current_offset] != 0:
                name += bytes([file_data[current_offset]])
                current_offset += 1
            current_offset += (4 - (current_offset % 4))
            self.streamheaders.append([self.start_offset + offset, size, name])
        self.end_offset = current_offset

    cpdef bytes to_bytes(self):
        """ Convert the header to its bytes representation.

        Returns:
            bytes: a bytes representation of the header.
        """
        cdef bytes result
        cdef int usable_len
        cdef tuple stream
        cdef int str_len
        cdef int amt_zero
        result = bytes()
        result += int.to_bytes(self.signature, 4, 'little')
        result += int.to_bytes(self.majorversion, 2, 'little')
        result += int.to_bytes(self.minorversion, 2, 'little')
        result += int.to_bytes(self.reserved, 4, 'little')
        if not self.versionstr.endswith(b'\x00'):
            self.versionstr += b'\x00'
        usable_len = <int>(len(self.versionstr) + (4 - (len(self.versionstr) % 4)))
        result += int.to_bytes(usable_len, 4, 'little')
        result += self.versionstr + (b'\x00' * (usable_len - len(self.versionstr)))
        result += int.to_bytes(self.flags, 2, 'little')
        result += int.to_bytes(self.num_streams, 2, 'little')
        for x in range(self.num_streams):
            stream = self.streamheaders[x]
            usable_offset = stream[0] - self.start_offset
            result += int.to_bytes(usable_offset, 4, 'little')
            result += int.to_bytes(stream[1], 4, 'little')
            if not stream[2].endswith(b'\x00'):
                stream[2] = stream[2] + b'\x00'
            str_len = <int>(len(stream[2]) + (4 - (len(stream[2]) % 4)))
            amt_zero = <int>(str_len - len(stream[2]))
            result += stream[2] + (b'\x00' * amt_zero)
        return result

    cdef list get_stream_headers(self):
        """ Obtain the stream headers.
        """
        return self.streamheaders

cdef class MetaDataDirectory:
    """ Represents the metadata directory.

        not really recommended to use as this structure may be changed in the future.

    Notes:
        dotnetpe (dotnetpefile.DotNetPeFile): the dotnetpe the directory is for.
        metadata_header (net_metadata.MetadataHeader): The metadata header object.
        metadata_table_header (net_table_objects.MetadataTableHeader): the #~ stream header.
        heaps (dict[str, net_processing.HeapObject]): A dictionary of heaps from the metadata.
        metadata_heap_size (int): the size of #~
        metadata_file_offset (int): the offset of #~
        metadata_file_size (int): the size of #~
    """
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe):
        self.dotnetpe = dotnetpe
        self.metadata_header = None
        self.metadata_table_header = None
        self.heaps = dict()
        self.metadata_heap_size = 0
        self.metadata_file_offset = 0
        self.metadata_file_size = 0
        self.is_valid_directory = self.process_directory(self.dotnetpe.get_exe_data())

    cpdef IMAGE_COR20_HEADER get_net_header(self):
        """ Obtain the IMAGE_COR20_HEADER for this executable.
        """
        return self.net_header

    cpdef net_processing.HeapObject get_heap(self, str name):
        """ Obtain a heap from the metadata directory.
        """
        return self.heaps[name]

    cpdef dict get_heaps(self):
        """ Obtain the dictionary of heaps.
        """
        return self.heaps

    cpdef int get_metadata_heap_size(self):
        """ Obtain #~ size.
        """
        return self.metadata_heap_size

    cpdef net_table_objects.MetadataTableHeader get_metadata_table_header(self):
        """ Obtain the #~ heap header.
        """
        return self.metadata_table_header

    cdef bint __validate_stream_not_there(self, str name):
        """ Check that a stream hasnt already been added.
        """
        return name not in self.heaps.keys()

    cdef bint process_directory(self, bytes file_data) except *:
        """ Process the information in the metadata directory.
        """
        cdef dotnetpefile.PeFile pe = dotnetpefile.PeFile(file_data)
        cdef IMAGE_DATA_DIRECTORY com_table_directory = pe.get_directory_by_idx(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        cdef uint64_t com_offset = pe.get_physical_by_rva(com_table_directory.VirtualAddress)
        cdef Py_buffer file_data_view
        cdef IMAGE_COR20_HEADER * cor_header = NULL
        cdef IMAGE_DATA_DIRECTORY metadata_dir
        cdef uint64_t metadata_offset
        cdef unsigned int file_offset
        cdef unsigned int size
        cdef bytes name
        PyObject_GetBuffer(file_data, &file_data_view, PyBUF_ANY_CONTIGUOUS)
        cor_header = <IMAGE_COR20_HEADER*>(<uintptr_t>file_data_view.buf + <uintptr_t>com_offset)
        self.net_header = cor_header[0]
        self.net_header_offset = com_offset
        metadata_dir = cor_header.MetaData
        metadata_offset = pe.get_physical_by_rva(metadata_dir.VirtualAddress)
        self.metadata_header = MetaDataHeader(self.dotnetpe, file_data, metadata_offset)
        for file_offset, size, name in self.metadata_header.get_stream_headers():
            #TODO: need to do a better job of supporting streams that arent actually there. (Duplicate streams)
            #Also need to work out issues where reconstruct_executable() is called on binaries with custom heaps / streams
            if name == b'#~' or name == b'#-':
                self.metadata_file_offset = file_offset
                self.metadata_file_size = size
            elif name == b'#Strings':
                if self.__validate_stream_not_there('#Strings'):
                    self.heaps['#Strings'] = net_processing.StringHeapObject(file_offset, size, name, self.dotnetpe)
            elif name == b'#GUID':
                if self.__validate_stream_not_there('#GUID'):
                    self.heaps['#GUID'] = net_processing.GuidHeapObject(file_offset, size, name, self.dotnetpe)
            elif name == b'#US':
                if self.__validate_stream_not_there('#US'):
                    self.heaps['#US'] = net_processing.UserStringsHeapObject(file_offset, size, name, self.dotnetpe)
            elif name == b'#Blob':
                if self.__validate_stream_not_there('#Blob'):
                    self.heaps['#Blob'] = net_processing.BlobHeapObject(file_offset, size, name, self.dotnetpe)
            else:
                # Dont throw exceptions on unknown streams, parse it as a generic stream.
                if self.__validate_stream_not_there(name.decode('ascii')):
                    self.heaps[name.decode('ascii')] = net_processing.HeapObject(file_offset, size, name, self.dotnetpe)
        if not (self.metadata_file_offset != 0 and self.metadata_file_size != 0):
            raise net_exceptions.InvalidMetadataException
        PyBuffer_Release(&file_data_view)
        return True

    cdef void process_metadata_heap(self, bint dont_process):
        """ Process the metadata heaps
        """
        cdef net_processing.MetadataTableHeapObject mheap = None
        cdef net_processing.UserStringsHeapObject usheap = None
        self.metadata_table_header = net_table_objects.MetadataTableHeader(self.dotnetpe, self.metadata_file_offset)
        mheap = net_processing.MetadataTableHeapObject(self.metadata_file_offset, self.metadata_file_size, b'#~', self.dotnetpe)
        self.heaps['#~'] = mheap
        self.metadata_heap_size = self.metadata_file_size
        if not dont_process:
            mheap.process_tables()
            if '#US' in self.heaps:
                usheap = self.heaps['#US']
                usheap._fill_methods() #Fill methods after processing for #US updates.  Patching wont work if processing isnt done.
