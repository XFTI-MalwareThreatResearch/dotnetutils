#cython: language_level=3
import hashlib
from dotnetutils import net_exceptions
from dotnetutils cimport net_structs
from dotnetutils cimport net_utils
from dotnetutils cimport net_cil_disas
from dotnetutils cimport net_tokens
from dotnetutils cimport net_table_objects
from typing import Union
from cysignals.signals cimport sig_check

cdef bytes get_cor_type_name(net_structs.CorElementType element_type):
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
    raise net_exceptions.OperationNotSupportedException()

cdef class RowObject:

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        """
        Initializes a row object by interpreting the raw data.
        """
        self.dotnetpe = dotnetpe
        self.rid = rid
        self.file_offset = raw_data[-1]
        self.values = dict()
        self.table_name = table_name
        self.sizes = sizes
        index = 0
        for col_name, col_type in col_types.items():
            cval = ColumnValue(col_type, sizes[index], raw_data[index], self.dotnetpe, col_name, self)
            if hasattr(self, 'format_{}_column'.format(col_name).lower()):
                cval.set_formatter_method(getattr(self, 'format_{}_column'.format(col_name).lower()), None)
            self.values[col_name.lower()] = cval
            index += 1

    cpdef ColumnValue get_column(self, str col_name) except *:
        if not hasattr(col_name, 'lower'):
            raise net_exceptions.ObjectTypeException
        return <ColumnValue>self.values[col_name.lower()]
    
    cpdef list get_sizes(self):
        """
        Get a list of sizes in bytes of each column.
        """
        return self.sizes

    cpdef dotnetpefile.DotNetPeFile get_dotnetpe(self):
        """
        Get the dotnetpefile.DotNetPeFile that spawned this RowObject
        """
        return self.dotnetpe

    cpdef int get_rid(self) except *:
        """
        Obtain the RID of a RowObject.
        A RID is a 1 based index of the row in a specific metadata table.
        """
        return self.rid

    cpdef str get_table_name(self):
        """
        Obtain the name of the table that a row is associated with.
        """
        return self.table_name

    cpdef int get_token(self) except *:
        """
        Obtain the MDToken value for the column.
        """
        return net_tokens.get_Signature().encode_token(self.get_table_name(), self.get_rid())

    cpdef int get_file_offset(self):
        """
        Obtain the offset of the row in the file.
        """
        return self.file_offset

    def __len__(self):
        result = 0
        for value in self.values.values():
            result += len(value)
        return result

    def __hash__(self):
        return hash(self.get_table_name() + '_' + str(self.get_rid()))

    def __eq__(self, other):
        return isinstance(other, RowObject) and other.get_rid() == self.get_rid() and self.get_table_name() == other.get_table_name()

    def __iter__(self):
        return iter(self.values.values())

    def __getitem__(self, item):
        return self.values[item.lower()]

    def __str__(self):
        if 'name' in self.values:
            try:
                return self['Name'].get_value().decode('ascii')
            except UnicodeDecodeError:
                pass
        return '{}:{}'.format(self.get_table_name(), self.get_rid())

    cpdef bint has_value(self, str val_name):
        """
        Does the row have a value by val_name?
        """
        return val_name.lower() in self.values.keys()

    cpdef int get_offset_to_col(self, str col_name):
        """
        Obtain the offset in bytes to the column matching col_name
        """
        cdef int result
        cdef str key
        cdef ColumnValue value
        result = 0
        for key, value in self.values.items():
            if key == col_name.lower():
                break
            result += len(value)
        return result

    #cpdef int get_col_size(self, str col_name):
    #    """
    #    Get the size of a column's raw value.
    #    """
    #    if not isinstance(col_name, str):
    #       raise net_exceptions.ObjectTypeException
    #    return len(self.get_column(col_name))

    cdef void process(self):
        """
        Process can be used to manipulate the column values
        For instance, param lists for TypeDefs are stored by the starting index
        Requires some logic to actually obtain the full list of params.
        """
        pass

    cdef void post_process(self):
        """
        Post process is called after process().
        """
        pass

    cpdef bytes to_bytes(self):
        """
        Convert a row to bytes.
        """
        cdef bytes result
        cdef ColumnValue item
        result = b''
        for item in self.values.values():
            result += item.to_bytes()

        return result

    cdef void initialize_columns(self):
        """
        Ensures column.original_value is populated by calling get_value() on each column
        right after everything is post-processed.
        """
        cdef ColumnValue column
        for column in self.values.values():
            column.get_value() # make sure original_value is populated.

cdef class ColumnValue:
    """
    A wrapper for column values with different ways to access the data and its properties.
    """

    def __init__(self, col_type, col_size, raw_value, dotnetpe, col_name, row_obj):
        self.col_type = col_type
        self.col_size = col_size
        self.raw_value = raw_value
        self.formatted_value = None
        self.changed_value = None
        self.cached_value = None
        self.dotnetpe = dotnetpe
        self.col_size = self.internal_get_size()
        self.col_name = col_name
        self.row_obj = row_obj
        self.original_value = None
        self.__has_no_value = False
        self.__formatter_method = None
        self.__formatter_param = None

    #Trying to see if these will improve speed in net_deobfuscate.

    cdef bytes get_value_as_bytes(self):
        return <bytes>self.get_value()

    cdef int get_value_as_int(self):
        return <int>self.get_value()

    cdef RowObject get_value_as_rowobject(self):
        return <RowObject>self.get_value()

    cpdef void set_formatter_method(self, formatter_method, formatter_param):
        self.__formatter_method = formatter_method
        self.__formatter_param = formatter_param

    cdef int internal_get_size(self) except *:
        """
        INTERNAL USE ONLY.
        """
        if self.col_type.is_stream():
            if self.col_type == net_tokens.get_BlobStream():
                return self.dotnetpe.get_metadata_dir().get_metadata_table_header().get_heap_offset_size(
                    net_structs.CorHeapBitmask.BITMASK_BLOB)
            elif self.col_type == net_tokens.get_StringsStream():
                return self.dotnetpe.get_metadata_dir().get_metadata_table_header().get_heap_offset_size(
                    net_structs.CorHeapBitmask.BITMASK_STRINGS)
            elif self.col_type == net_tokens.get_GuidStream():
                return self.dotnetpe.get_metadata_dir().get_metadata_table_header().get_heap_offset_size(
                    net_structs.CorHeapBitmask.BITMASK_GUID)
            raise net_exceptions.InvalidArgumentsException()
        else:
            return self.col_size
        
    cpdef object get_original_value(self):
        """
        If possible, obtain the original value that this column had.
        NOTE: Will not work if no_processing is set to True.
        """
        if self.original_value == None:
            self.get_value()
        return self.original_value

    cpdef void change_value(self, object new_value):
        """
        Change a value
        Currently only works with CodedTokens specifically,
        but this function does the legwork to change a value. 
        An example of when this might be useful is deobfuscating method names
        """
        if self.original_value == None:
            self.get_value()
        if new_value is None:
            raise net_exceptions.InvalidArgumentsException
        self.changed_value = new_value
        #instead of going through and making the modifications, make them upon a reconstruct executable call.
        #having get_value return the changed value should be enough - changing the raw value can probably be done on reconstruction
    
    cdef object __retrieve_value(self):
        """
        INTERNAL USE ONLY.
        """
        cdef str table_name
        cdef int table_rid
        cdef net_table_objects.TableObject table_obj
        #TODO: add some sort of detection for calling this function when the tables arent fully initialized.
        try:
            table_name, table_rid = self.col_type.decode_token(self.raw_value)
        except net_exceptions.InvalidTokenException:
            return None
        if table_name is None:
            return table_rid
        elif self.col_type.is_stream():
            if self.dotnetpe.has_heap(table_name):
                return self.dotnetpe.get_heap(table_name).get_item(table_rid)
        elif self.col_type.is_fixed_value():
            return self.raw_value
        else:
            if self.dotnetpe.has_metadata_table(table_name):
                return self.dotnetpe.get_heap('#~')[table_name].get(table_rid)
        if table_name == None:
            return None
        table_obj = self.dotnetpe.get_metadata_table(table_name)
        if table_obj == None:
            self.__has_no_value = True
            return None
        return table_obj.get(table_rid)
    
    cpdef bint has_value(self):
        """
        Does the column actually have a value?
        """
        return not self.__has_no_value

    cpdef object get_value(self) except *:
        """
        Obtain the processed value corresponding to the raw_value
        :return: The processed value corresponding to the column
        """
        #check if value was changed
        try:
            sig_check()
        except KeyboardInterrupt:
            exit(0)
        if self.changed_value != None:
            return self.changed_value
        if self.__has_no_value:
            return None
        if self.cached_value == None:
            try:
                self.cached_value = self.__retrieve_value()
            except:
                self.__has_no_value = True

        if self.original_value == None:
            self.original_value = self.cached_value

        return self.cached_value

    cpdef void set_formatted_value(self, object value):
        """
        Internal Method.
        :param value: The formatted value
        :return: None
        """
        self.formatted_value = value

    cpdef object get_formatted_value(self) except *:
        """
        Obtains the formatted value for a column
        :return: The formatted value
        """
        #formatter method sig: def formatter_method(ColumnValue, DotNetPeFile, RowObject, object)
        if self.formatted_value == None and self.__formatter_method != None:
            self.set_formatted_value(self.__formatter_method(self, self.dotnetpe, self.row_obj, self.__formatter_param))
        return self.formatted_value

    cpdef object get_changed_value(self):
        """
        Get the new value of a ColumnValue (will return none if change_value() was never called.)
        """
        return self.changed_value

    cpdef int get_raw_value(self) except *:
        """
        Obtain the raw, unprocessed value.
        :return: the raw value
        """
        return self.raw_value
    
    cpdef bint was_value_changed(self):
        """
        Was the value changed?
        """
        return self.changed_value != None and self.changed_value != self.original_value
    
    cpdef void set_raw_value(self, int new_value):
        """
        Set the raw value of the column.
        """
        self.raw_value = new_value

    def __len__(self):
        return self.col_size

    cpdef str get_value_table_name(self):
        """
        Get the name of the table the value corresponds to.
        :return:
        """
        cdef str tbl_name
        cdef int tbl_rid
        try:
            tbl_name, tbl_rid = self.col_type.decode_token(self.raw_value)
            return tbl_name
        except net_exceptions.InvalidTokenException:
            return None
        
    cpdef tuple get_value_location(self):
        """
        Get the token meaning for a column value.
        """
        return self.col_type.decode_token(self.raw_value)

    cpdef int get_value_rid(self):
        """
        Get the RID that the value corresponds to.
        :return:
        """
        cdef str tbl_name
        cdef int tbl_rid
        try:
            tbl_name, tbl_rid = self.col_type.decode_token(self.raw_value)
            return tbl_rid
        except net_exceptions.InvalidTokenException:
            return -1
        
    cpdef bytes to_bytes(self):
        try:
            return int.to_bytes(self.get_raw_value(), self.internal_get_size(), 'little', signed=False)
        except Exception as e:
            print('Error converting value {} with size {} in column type {}'.format(hex(self.get_raw_value()), hex(self.internal_get_size()), self.get_value_table_name()))
            raise e

    cpdef net_tokens.BaseToken get_col_type(self):
        """
        Obtain an item that represents the type of value the column holds.
        """
        return self.col_type

    def __eq__(self, other):
        return isinstance(other,
                          ColumnValue) and other.get_raw_value() == self.get_raw_value() and other.col_type == self.col_type

cdef class TypeDefOrRef(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)

    cpdef MethodDef get_cctor_method(self):
        return None

    cpdef TypeDef get_enclosing_type(self):
        return None

    cpdef RowObject get_classlayout_obj(self):
        return None

    cpdef TypeDefOrRef get_superclass(self):
        return None

    cpdef list get_interfaces(self):
        return list()

    cpdef list get_child_classes(self):
        return list()

    cpdef void _add_child_class(self, TypeDefOrRef obj):
        pass

    cpdef list get_member_refs(self):
        return list()

    cpdef list get_generic_params(self):
        return list()

    cpdef bint is_valuetype(self):
        return False

    cdef void process(self):
        pass

    cpdef list get_methods(self):
        return list()

    cdef void post_process(self):
        pass

    cpdef bytes get_full_name(self):
        return bytes()

    cpdef bytes get_class_path(self):
        return bytes()

    cpdef Field get_field(self, bytes name):
        return None

    cpdef list get_methods_by_name(self, bytes name):
        return None

    cpdef TypeDefOrRef get_type(self):
        return None

cdef class TypeDef(TypeDefOrRef):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        TypeDefOrRef.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__enclosing_type = None
        self.__has_enclosing_type = True
        self.__classlayout_obj = None
        self.__superclass = None
        self.__has_superclass = True
        self.__interfaces = list()
        self.__has_interfaces = True
        self.__child_classes = list()
        self._memberrefs = list()
        self._generic_params = list()
        self.__is_valuetype = False
        self.__cctor_method = None
        self.__full_name = None

    cpdef MethodDef get_cctor_method(self):
        """
        Obtain the type's static constructor if exists.
        """
        cdef list results
        if not self.__cctor_method:
            results = self.get_methods_by_name(b'.cctor')
            if len(results) == 1:
                self.__cctor_method = results[0]
        return self.__cctor_method

    cpdef TypeDef get_enclosing_type(self):
        """
        Obtain the type's enclosing type if its a NestedClass.
        """
        cdef net_table_objects.TableObject nested_classes
        cdef RowObject nested
        if not self.__enclosing_type and self.__has_enclosing_type:
            nested_classes = self.get_dotnetpe().get_metadata_table('NestedClass')
            if nested_classes is not None:
                for nested in nested_classes:
                    if nested['NestedClass'].get_raw_value() == self.rid:
                        self.__enclosing_type = self.get_dotnetpe().get_metadata_table('TypeDef').get(
                            nested['EnclosingClass'].get_raw_value())
                        break
            if not self.__enclosing_type:
                self.__has_enclosing_type = False
        return self.__enclosing_type

    cpdef RowObject get_classlayout_obj(self):
        """
        Obtain a classlayout object associated with the type if exists.
        """
        cdef net_table_objects.ClassLayoutTable classlayout_table
        if not self.__classlayout_obj:
            classlayout_table = self.get_dotnetpe().get_metadata_table('ClassLayout')
            if classlayout_table:
                self.__classlayout_obj = classlayout_table.get_layout_by_parent(
                    self.rid)
        return self.__classlayout_obj

    cpdef TypeDefOrRef get_superclass(self):
        cdef bint skip
        cdef TypeDefOrRef extends_obj
        cdef TypeDefOrRef add_to
        """
        Obtain the type's superclass if exists.
        """
        if self['Extends'].get_raw_value() != 0 and self.__has_superclass and not self.__superclass:
            skip = False
            if self['Extends'].get_value_table_name() == 'TypeRef':
                extends_obj = self['Extends'].get_value()
                if not extends_obj or extends_obj['TypeName'].get_value() == b'Object':
                    skip = True
            if not skip:
                self.__superclass = self['Extends'].get_value()
                if isinstance(self.__superclass, TypeDefOrRef):
                    add_to = self.__superclass
                    if hasattr(add_to, '_add_child_class'):
                        add_to._add_child_class(self)
                else:
                    self.__superclass = None
                    self.__has_superclass = False

            if not self.__superclass:
                self.__has_superclass = False
        return self.__superclass

    cpdef list get_interfaces(self):
        """
        Obtain the type's superclass interfaces if exists.
        """
        return self.__interfaces

    cpdef list get_child_classes(self):
        """
        Obtains children classes of the type if exists.
        """
        return self.__child_classes

    cpdef void _add_child_class(self, TypeDefOrRef obj):
        self.__child_classes.append(obj)

    cpdef list get_member_refs(self):
        """
        Obtains any memberrefs associated with the type.
        """
        return self._memberrefs

    cpdef list get_generic_params(self):
        """
        Obtains generic parameters for the type.
        """
        return self._generic_params

    cpdef bint is_valuetype(self):
        """
        Determines whether or not the class is a System.ValueType.
        """
        cdef bytes extends_name
        if not self.__superclass and self.__has_superclass:
            self.get_superclass()  # make sure the superclass field is populated.
        if self.__superclass and not self.__is_valuetype:
            extends_name = self.__superclass.get_full_name()
            self.__is_valuetype = extends_name == b'System.ValueType'
        return self.__is_valuetype

    cdef void process(self):
        cdef int field_start_index
        cdef list fieldlist
        cdef net_table_objects.MetadataHeap metadata_heap
        cdef int field_end_index
        cdef int x
        cdef Field field_obj
        cdef list methodlist
        cdef int method_start_index
        cdef int method_table_len
        cdef int method_index_end
        cdef net_table_objects.MethodDefTable method_table
        cdef MethodDef method
        field_start_index = self['FieldList'].get_raw_value()
        fieldlist = list()
        metadata_heap = self.get_dotnetpe().get_heap('#~')
        if metadata_heap.has_table('Field') and self['FieldList'].get_raw_value() != 0:
            field_end_index = len(metadata_heap.obtain_table('Field')) + 1
            if metadata_heap.obtain_table('TypeDef').has_index(self.rid + 1):
                field_end_index = metadata_heap.obtain_table('TypeDef').get(self.rid + 1)['fieldlist'].get_raw_value()
            if not metadata_heap.obtain_table('Field').has_index(field_end_index):
                field_end_index = len(metadata_heap.obtain_table('Field')) + 1
            for x in range(field_start_index, field_end_index):
                field_obj = metadata_heap.obtain_table('Field').get(x)
                if field_obj:
                    field_obj._set_parent_type(self)
                    fieldlist.append(field_obj)
            self['FieldList'].set_formatted_value(fieldlist)
        if metadata_heap.has_table('MethodDef') and self['MethodList'].get_raw_value() != 0:
            methodlist = list()
            method_start_index = self['MethodList'].get_raw_value()
            method_table_len = len(metadata_heap.obtain_table('MethodDef')) + 1
            method_index_end = method_table_len
            method_table = metadata_heap.obtain_table('MethodDef')
            if  metadata_heap.obtain_table('TypeDef').has_index(self.rid + 1):
                method_index_end = metadata_heap.obtain_table('TypeDef').get(self.rid + 1)[
                    'methodlist'].get_raw_value()
            if not metadata_heap.obtain_table('MethodDef').has_index(method_index_end):
                method_index_end = len(metadata_heap.obtain_table('MethodDef')) + 1
            for x in range(method_start_index, method_index_end):
                method = method_table.get(x)
                method._set_parent_type(self)
                methodlist.append(method)
            self['MethodList'].set_formatted_value(methodlist)

    cpdef list get_methods(self):
        """
        Obtain a list of MethodDef objects associated with the TypeDef.
        """
        return self['MethodList'].get_formatted_value()

    cdef void post_process(self):
        cdef net_table_objects.MetadataHeap metadata_heap
        cdef RowObject item
        cdef RowObject interface_obj
        
        if self.__has_interfaces:
            metadata_heap = self.get_dotnetpe().get_heap('#~')
            if metadata_heap.has_table('InterfaceImpl'):
                for item in metadata_heap.obtain_table('InterfaceImpl'):
                    if item['Class'].get_raw_value() == self.rid:
                        interface_obj = item['Interface'].get_value()
                        if interface_obj:
                            interface_obj._add_child_class(self)

                            self.__interfaces.append(interface_obj)
            if len(self.__interfaces) == 0:
                self.__has_interfaces = False

    cpdef bytes get_full_name(self):
        """
        Obtain the full name of the class, including the namespace
        """
        cdef TypeDef ptr
        cdef bytes result
        cdef TypeDef old_ptr
        if not self.__full_name: # ensure enclosing_type is populated.
            ptr = self.get_enclosing_type()
            if ptr is None:
                if self['TypeNamespace'].get_value() == b'':
                    return self['TypeName'].get_value()
                return self['TypeNamespace'].get_value() + b'.' + self['TypeName'].get_value()
            result = self['TypeName'].get_value()
            old_ptr = None
            while ptr is not None:
                result = ptr['TypeName'].get_value() + b'.' + result
                old_ptr = ptr
                ptr = ptr.get_enclosing_type()
            if old_ptr['TypeNamespace'].get_value() != b'':
                result = old_ptr['TypeNamespace'].get_value() + b'.' + result
            self.__full_name = result

        return self.__full_name

    cpdef bytes get_class_path(self):
        """
        Obtain the full name of the class, without the namespace.
        """
        return b'.'.join(self.get_full_name().split(b'.')[1:])

    cpdef Field get_field(self, bytes name):
        """
        Obtain a field object matching 'name' from the type
        """
        cdef Field field
        for field in self['FieldList'].get_formatted_value():
            if field['Name'].get_value() == name:
                return field
        return None

    cpdef list get_methods_by_name(self, bytes name):
        """
        Obtain a method matching 'name' from the type
        """
        cdef list result
        cdef MethodDef method
        if name == self['TypeName'].get_value():
            return self.get_methods_by_name(b'.ctor')
        result = list()
        for method in self['MethodList'].get_formatted_value():
            if method['Name'].get_value() == name:
                result.append(method)
        return result

    def __str__(self):
        self.get_superclass()  # ensure superclass is populated.
        extends_name = None
        if self.__superclass:
            extends_name = self.__superclass.get_full_name()
        return 'class_name: {}, extends: {}, RID: {} {}'.format(self.get_full_name(), extends_name, self.get_rid(),
                                                                hex(self.get_token()))

cdef class Field(RowObject):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__rva_object = None
        self.__parent_type = None
        self.__class_size = 0
        self.__sig_obj = None
        self.__field_type = None
        self.__xrefs = list()

    cpdef list get_xrefs(self):
        """
        Obtain a list of tuples (method_rid, instr_index) representing references of a Field.
        Field references occur when stsfld, ldsfld, stfld, ldfld are called on a Field.
        """
        return self.__xrefs

    cpdef void _add_xref(self, int rid, int instr_index):
        self.__xrefs.append((rid, instr_index))

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        self.__parent_type = parent_type

    cpdef TypeDefOrRef get_parent_type(self):
        """
        Obtain the field's parent type.
        """
        return self.__parent_type

    cdef void process(self):
        cdef net_table_objects.FieldRVATable fieldrva_table
        fieldrva_table = self.get_dotnetpe().get_metadata_table('FieldRVA')
        if fieldrva_table:
            self.__rva_object = fieldrva_table.get_by_field_rid(self.get_rid())

    cpdef net_utils.FieldSig get_field_signature(self):
        """
        Obtains the signature object associated with the field.
        """
        if not self.__sig_obj:
            self.__initialize_sig()
        return self.__sig_obj

    cdef void __initialize_sig(self):
        cdef bytes sig
        cdef net_utils.SignatureReader sig_reader
        cdef net_utils.TypeSig type_obj
        cdef TypeDefOrRef typedef_obj
        sig = self['Signature'].get_value()
        if sig:
            sig_reader = net_utils.SignatureReader(self.get_dotnetpe(), sig)
            self.__sig_obj = sig_reader.read_signature()
            if isinstance(self.__sig_obj, net_utils.FieldSig):
                type_obj = self.__sig_obj.get_type_sig()
                if isinstance(type_obj, net_utils.TypeDefOrRefSig) and type_obj.get_type() != None:
                    typedef_obj = type_obj.get_type()
                    self.__field_type = typedef_obj
                    if isinstance(typedef_obj, TypeDef) and typedef_obj.get_classlayout_obj():
                        self.__class_size = typedef_obj.get_classlayout_obj()['ClassSize'].get_value()
                elif isinstance(type_obj, net_utils.CorLibTypeSig):
                    if type_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I8:
                        self.__class_size = 8
                    elif type_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_R4:
                        self.__class_size = 4

    cpdef bint is_static(self):
        """
        Checks if the field is static or not.
        """
        return self['Flags'].get_value() & net_structs.CorFieldAttr.fdStatic != 0

    cpdef bytes get_data(self):
        """
        If the field has initial constant data, attempt to obtain it.
        """
        cdef int rva
        cdef int offset
        if not self.__rva_object:
            return None

        if not self.__sig_obj or self.__class_size == 0:
            self.__initialize_sig()

        if self.__class_size == 0:
            return None

        rva = self.__rva_object['RVA'].get_value()
        if rva == 0:
            return None

        offset = self.get_dotnetpe().get_pe().get_offset_from_rva(rva)
        if self.__class_size:
            return self.get_dotnetpe().get_exe_data()[offset:offset + self.__class_size]
        return None

    def __str__(self):
        return 'Field:{}'.format(self.get_rid())


cdef class TypeRef(TypeDefOrRef):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        TypeDefOrRef.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__methods = list()
        self.__child_classes = list()
        self.__interfaces = list()  # same as below.
        self.__superclass = None  # I dont think its possible for a TypeRef to have a superclass
        self.__cctor_method = None
        self.__full_name = None
        self._memberrefs = list()

    cpdef list get_member_refs(self):
        """
        Obtains any memberrefs associated with the TypeRef.
        """
        return self._memberrefs

    cpdef TypeDefOrRef get_superclass(self):
        """
        Gets the superclass of the type.
        """
        return self.__superclass

    cpdef list get_interfaces(self):
        """
        Obtains any interfaces inherited by the type.
        """
        return self.__interfaces

    cpdef void _add_child_class(self, TypeDefOrRef obj):
        self.__child_classes.append(obj)

    cpdef list get_child_classes(self):
        """
        Obtains any child classes for the type.
        """
        return self.__child_classes

    cdef void process(self):
        cdef MemberRef member_ref
        cdef str class_table
        for member_ref in self.get_dotnetpe().get_metadata_table('MemberRef'):
            class_table = member_ref['Class'].get_value_table_name()
            if class_table == 'TypeRef':
                if member_ref['Class'].get_value_rid() == self.get_rid():
                    self.__methods.append(member_ref)
                    member_ref._set_parent_type(self)

    cpdef list get_methods(self):
        """
        Obtains any methods associated with the type.
        """
        return self.__methods

    cpdef list get_methods_by_name(self, bytes method_name):
        cdef list result
        cdef RowObject method
        result = list()
        for method in self.__methods:
            if method['Name'].get_value() == method_name:
                result.append(method)
        return result

    cpdef MethodDef get_cctor_method(self):
        """
        Obtains the type's static constructor if exists.
        """
        cdef list results
        if not self.__cctor_method:
            results = self.get_methods_by_name(b'.cctor')
            if len(results) == 1:
                self.__cctor_method = results[0]
        return self.__cctor_method

    cpdef bytes get_full_name(self):
        """
        Obtains the full name of the type.
        """
        cdef bytes type_namespace
        cdef bytes type_name
        if not self.__full_name:
            type_namespace = self['TypeNamespace'].get_value()
            type_name = self['TypeName'].get_value()
            if type_name:
                if type_namespace:
                    self.__full_name = type_namespace + b'.' + type_name
                else:
                    self.__full_name = type_name
            else:
                return None
        return self.__full_name

    def __str__(self):
        return self.get_full_name().decode('ascii')

cdef class MethodDefOrRef(RowObject):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)

    cpdef net_cil_disas.MethodDisassembler disassemble_method(self, bint no_save=False, bint original=False):
        return None

    cpdef bytes get_original_method_data(self):
        return bytes()

    cpdef list get_xrefs(self):
        return list()

    cpdef void _add_xref(self, int rid, int instr_index):
        pass

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        pass

    cpdef bint is_abstract(self):
        return False

    cdef void process(self):
        pass

    cdef void post_process(self):
        pass

    cpdef list get_param_types(self):
        return list()

    cpdef bytes get_full_name(self):
        return bytes()
    
    cpdef bint is_virtual(self):
        return False

    cpdef bint is_hidebysig(self):
        return False

    cpdef bint is_static_method(self):
        return False

    cpdef net_utils.MethodBaseSig get_method_signature(self):
        return None

    cpdef bint is_entrypoint(self):
        return False

    cpdef bint is_static_constructor(self):
        return False

    cpdef bint is_constructor(self):
        return False

    cpdef bytes get_method_data(self):
        return bytes()

    cpdef bint has_body(self):
        return False

    cpdef TypeDefOrRef get_parent_type(self):
        return None

    cpdef bint has_return_value(self):
        return False

    cpdef bint method_has_this(self):
        return False

    cpdef int get_amt_params(self):
        return 0

cdef class MethodDef(MethodDefOrRef):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        MethodDefOrRef.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__parent_type = None
        self._generic_params = list()
        self.__has_return_value = False
        self.__method_has_this = False
        self.__sig_obj = None
        self.__disasm_obj = None
        self.__full_name = None
        self.__current_method_hash = None
        self.__has_invalid_signature = False
        self.__xrefs = list()

    cpdef net_cil_disas.MethodDisassembler disassemble_method(self, bint no_save=False, bint original=False):
        """
        Obtains a MethodDisassembler object for the method.
        This method now accounts for changes in memory of the method code using
        a MD5 hash.

        no_save: If true, dont save the disassembler object.
        original: Get a disasm object based on the original exe's data before any manipulation.
        """
        cdef bytes hashval
        if original:
            return net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self, force_data=self.get_original_method_data())
            
        if self.has_body():
            if no_save:
                return net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self)
            else:
                if not self.__disasm_obj:
                    self.__disasm_obj = net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self)
                    md5 = hashlib.md5()
                    md5.update(self.get_method_data())
                    self.__current_method_hash = md5.digest()
                else:
                    #Check to make sure the method hasnt been modified.
                    md5 = hashlib.md5()
                    md5.update(self.get_method_data())
                    hashval = md5.digest()
                    if hashval != self.__current_method_hash:
                        self.__disasm_obj = net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self)
                        self.__current_method_hash = hashval
                return self.__disasm_obj
        return None

    cpdef bytes get_original_method_data(self):
        """
        Obtain the methods data based on the original copy of the exe.
        """
        cdef unsigned long file_offset
        cdef unsigned long method_size
        if self['RVA'].get_value() == 0:
            return None
        file_offset = self.get_dotnetpe().get_pe().get_offset_from_rva(self['RVA'].get_value())
        method_size = net_cil_disas.get_total_method_size(self.get_dotnetpe().get_original_exe_data()[file_offset:])
        return self.get_dotnetpe().get_original_exe_data()[file_offset: file_offset + method_size]

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        self.__parent_type = parent_type

    cpdef void _add_xref(self, int rid, int instr_index):
        self.__xrefs.append((rid, instr_index))

    cpdef list get_xrefs(self):
        """
        Obtains a list of tuples (method_rid, instr_index) representing xrefs of a method.
        A method xref is when call or callvirt is used on a methoddef object.
        """
        return self.__xrefs

    cpdef bint is_abstract(self):
        """
        Returns true if the method is abstract, false otherwise.
        """
        return self['Flags'].get_raw_value() & net_structs.CorMethodAttr.mdAbstract != 0

    cdef void process(self):
        cdef net_table_objects.MetadataHeap metadata_heap
        cdef int params_list_end
        cdef int params_list_len
        cdef int params_list_start
        cdef list paramlist

        # process paramslist
        metadata_heap = self.get_dotnetpe().get_heap('#~')
        if metadata_heap.has_table('Param'):
            params_list_len = len(metadata_heap.obtain_table('Param'))
            params_list_end = params_list_len + 1

            if metadata_heap.obtain_table('MethodDef').has_index(self.get_rid() + 1):
                params_list_end = metadata_heap.obtain_table('MethodDef').get(self.get_rid() + 1).values[
                    'paramlist'].get_raw_value()
            if not metadata_heap.obtain_table('Param').has_index(params_list_end):
                params_list_end = params_list_len + 1
            params_list_start = self.values['paramlist'].get_raw_value()
            paramlist = list()
            #for x in range(params_list_start, params_list_end):
            #    paramlist.append(metadata_heap.obtain_table('Param').get(x))
            paramlist.extend(metadata_heap.obtain_table('Param')[params_list_start:params_list_end])
            self['ParamList'].set_formatted_value(paramlist)

    cpdef list get_param_types(self):
        """
        Obtain the TypeSigs for each parameter in the function.
        """
        return self.get_method_signature().get_parameters()

    cpdef bytes get_full_name(self):
        """
        Obtain the full name of a method.
        """
        if not self.__full_name:
            if self.__parent_type is None:
                self.__full_name = self['Name'].get_value()
            else:
                self.__full_name = self.__parent_type.get_full_name() + b'.' + self['Name'].get_value()
        return self.__full_name
    
    cpdef bint is_virtual(self):
        """
        Returns True if a method is virtual, false otherwise.
        """
        return self['Flags'].get_raw_value() & net_structs.CorMethodAttr.mdVirtual != 0

    cpdef bint is_hidebysig(self):
        """
        Returns True if a method is HideBySig, false otherwise.
        """
        return self['Flags'].get_raw_value() & net_structs.CorMethodAttr.mdHideBySig != 0

    cpdef bint is_static_method(self):
        """
        Is the method static?
        """
        return self['Flags'].get_raw_value() & net_structs.CorMethodAttr.mdStatic != 0

    cpdef net_utils.MethodBaseSig get_method_signature(self):
        """
        Obtains the method's signature object.
        """
        cdef bytes signature_data
        cdef net_utils.SignatureReader sig_reader
        if self.__sig_obj == None and not self.__has_invalid_signature:
            signature_data = self['Signature'].get_value()
            try:
                sig_reader = net_utils.SignatureReader(self.get_dotnetpe(), signature_data, self)
                self.__sig_obj = sig_reader.read_signature()
                if not isinstance(self.__sig_obj, net_utils.MethodSig):
                    raise net_exceptions.InvalidSignatureException('Sig mismatch')
                self.__has_return_value = not isinstance(
                    self.__sig_obj.get_return_type(), net_utils.CorLibTypeSig) or self.__sig_obj.get_return_type() != net_utils.get_CorSig_Void()
                self.__method_has_this = self.__sig_obj.get_calling_conv() & net_structs.CorCallingConvention.HasThis != 0
            except net_exceptions.InvalidSignatureException:
                self.__has_invalid_signature = True
        return self.__sig_obj

    cpdef bint is_entrypoint(self):
        cdef MethodDef ep
        """
        Is the function an entrypoint?
        """
        if self.get_dotnetpe().get_metadata_dir().net_header.Flags & net_structs.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
            return False
        ep = self.get_dotnetpe().get_entry_point()
        return ep == self

    cpdef bint is_static_constructor(self):
        """
        Checks if the method is a static constructor.
        """
        return self['Name'].get_value() == b'.cctor'

    cpdef bint is_constructor(self):
        """
        Checks if the method is an instance constructor.
        """
        return self['Name'].get_value() == b'.ctor'

    def __str__(self):
        return 'MethodDef:{}='.format(self.get_rid()) + self.get_full_name().__str__()

    cpdef bytes get_method_data(self):
        """
        Obtain the method body's data.
        """
        cdef int file_offset
        cdef int method_size
        if self['RVA'].get_value() == 0:
            return None
        file_offset = self.get_dotnetpe().get_pe().get_offset_from_rva(self['RVA'].get_value())
        method_size = net_cil_disas.get_total_method_size(self.get_dotnetpe().get_exe_data()[file_offset:])
        return self.get_dotnetpe().get_exe_data()[file_offset: file_offset + method_size]

    cpdef bint has_body(self):
        """
        Does the method object contain an actual method body?
        """
        return self['RVA'].get_value() != 0

    cpdef TypeDefOrRef get_parent_type(self):
        """
        Obtain the parent TypeDef TypeSpec TypeRef of a MethodDef.
        """
        return self.__parent_type

    cpdef bint has_return_value(self):
        """
        Does the method return a value?
        """
        self.get_method_signature()
        return self.__has_return_value

    cpdef bint method_has_this(self):
        """
        Does the method have a this parameter?
        """
        self.get_method_signature() # Make sure signature is populated
        return self.__method_has_this

    cpdef int get_amt_params(self):
        """
        Obtain the amount of parameters that the function takes.
        """
        return len(self['ParamList'].get_formatted_value())


cdef class MemberRef(MethodDefOrRef):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__parent_type = None
        self.__sig_obj = None
        self.__method_has_this = False
        self.__method_has_return = False
        self.__full_name = None
        self.__is_field = False
        self.__is_method = False
        self.__method_has_return_called = False
        self.__method_has_this_called = False
        self.__xrefs = list()

    cpdef list get_xrefs(self):
        """
        Obtain a list of xrefs for a MemberRef (a list of tuples with values (method_rid, instr_index))
        """
        return self.__xrefs

    cpdef void _add_xref(self, int rid, int instr_index):
        self.__xrefs.append((rid, instr_index))

    cpdef TypeDefOrRef get_parent_type(self):
        """
        Obtain the memberref's parent.
        """
        return self.__parent_type

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        self.__parent_type = parent_type

    cdef void post_process(self):
        cdef RowObject class_obj
        cdef RowObject sig_type
        class_obj = self['Class'].get_value()
        if class_obj:
            if class_obj.get_table_name() == 'TypeRef':
                self._set_parent_type(class_obj)
            elif class_obj.get_table_name() == 'ModuleRef':
                self._set_parent_type(class_obj)
            elif class_obj.get_table_name() == 'MethodDef':
                self._set_parent_type(class_obj)
            elif class_obj.get_table_name() == 'TypeDef':
                self._set_parent_type(class_obj)
                self.__parent_type._memberrefs.append(self)
            elif class_obj.get_table_name() == 'TypeSpec':
                sig_type = class_obj.get_type()
                self._set_parent_type(class_obj)
                if sig_type != None:
                    sig_type._memberrefs.append(self)

    cpdef MethodDef get_method_impl(self):
        """
        Attempt to obtain the definition of a method (useful for handling virtual methods and such.)
        #TODO: handle methodimpl table methods
        """
        cdef RowObject parent_type
        cdef RowObject sig_type
        cdef MethodDef method
        if self.is_field():
            return None
        parent_type = self.get_parent_type()
        if parent_type:
            if isinstance(parent_type, TypeSpec):
                sig_type = parent_type.get_type()
                if sig_type and isinstance(sig_type, TypeDef):
                    for method in sig_type['MethodList'].get_formatted_value():
                        if method['Name'].get_original_value() == self['Name'].get_original_value():
                            if method.get_method_signature() == self.get_method_signature():
                                return method
        return None


    cpdef bint is_field(self):
        """
        Returns True if the memberref object represents a field.
        """
        return isinstance(self.get_method_signature(), net_utils.FieldSig)
    
    cpdef bint is_method(self):
        """
        Returns True if the memberref object represents a method.
        """
        return isinstance(self.get_method_signature(), net_utils.MethodSig)

    cpdef bint is_static_method(self):
        return not self.method_has_this()

    cpdef bint is_hidebysig(self):
        return True #For internal use with DotNetEmulator only.  I dont think MemberRefs actually have  the hiding property.

    cpdef bytes get_full_name(self):
        """
        Obtain the full name of the method.
        """
        cdef bytes parent_name
        if not self.__full_name:
            if self.__parent_type:
                parent_name = self.__parent_type.get_full_name()
                if parent_name is not None:
                    self.__full_name = parent_name + b'.' + self['Name'].get_value()
                else:
                    self.__full_name = self['Name'].get_value()
            else:
                self.__full_name = self['Name'].get_value()
        return self.__full_name

    cpdef bint has_return_value(self):
        """
        Does the method have a return value?
        """
        return self.get_method_signature().get_return_type() != net_utils.get_CorSig_Void()

    cpdef list get_param_types(self):
        """
        Obtain the TypeSigs for each parameter in the function.
        """
        return self.get_method_signature().get_parameters()

    cpdef bint method_has_this(self):
        """
        Does the method have a this parameter?
        """
        return self.get_method_signature().get_calling_conv() & net_structs.CorCallingConvention.HasThis != 0

    cpdef int get_amt_params(self):
        """
        Obtain the amount of parameters that the function takes.
        """
        return len(self.get_param_types())

    cpdef net_utils.MethodBaseSig get_method_signature(self):
        """
        Obtain the signature object associated with the method.
        """
        if self.__sig_obj == None:
            try:
                self.__sig_obj = net_utils.SignatureReader(self.get_dotnetpe(), self['Signature'].get_value()).read_signature()
            except:
                return None
        return self.__sig_obj

    def __str__(self):
        return 'MemberRef:{}={}'.format(self.get_rid(), self.get_full_name().__str__())


cdef class GenericParam(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)

    cdef void process(self):
        cdef RowObject owner_obj
        owner_obj = self['Owner'].get_value()
        if owner_obj:
            if isinstance(owner_obj, TypeDef):
                owner_obj._generic_params.append(self)
            elif isinstance(owner_obj, MethodDef):
                owner_obj._generic_params.append(self)
            else:
                raise net_exceptions.InvalidArgumentsException()

cdef class MethodSpec(MethodDefOrRef):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        MethodDefOrRef.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__parsed_sig = None
        self.__xrefs = list()

    cpdef list get_xrefs(self):
        """
        Obtain a list of xrefs (tuples with (method_rid, instr_index)) for the MethodSpec
        """
        return self.__xrefs

    cpdef void _add_xref(self, int rid, int instr_index):
        self.__xrefs.append((rid, instr_index))

    cpdef MethodDefOrRef get_method(self):
        """
        Get the base method for the MethodSpec
        """
        return self['Method'].get_value()
    
    cpdef bytes get_full_name(self):
        """
        Obtain the full name of the method.
        """
        return self.get_method().get_full_name()
    
    def __eq__(self, other): #TODO: should this return true if get_method() == other?
        if isinstance(other, MethodSpec):
            return other.get_rid() == self.get_rid()
        else:
            return self.get_method() == other

    cpdef net_utils.MethodSig get_sig_obj(self):
        """
        Obtain the Type's signature object.
        """
        cdef bytes signature
        cdef net_utils.SignatureReader sig_reader
        if not self.__parsed_sig:
            signature = self['Signature'].get_value()
            sig_reader = net_utils.SignatureReader(self.get_dotnetpe(), signature)
            try:
                self.__parsed_sig = sig_reader.handle_method_sig()
            except net_exceptions.InvalidSignatureException:
                pass
        return self.__parsed_sig


cdef class TypeSpec(TypeDefOrRef):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        TypeDefOrRef.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__parsed_sig = None
        self.__has_invalid_signature = False

    cpdef void _add_child_class(self, TypeDefOrRef to_add):
        self.get_type()._add_child_class(to_add)

    cpdef TypeDefOrRef get_type(self):
        """
        Attempts to obtain a TypeDef or TypeRef object behind the TypeSpec signature.
        """
        cdef net_utils.TypeSig sig_obj
        cdef net_structs.CorElementType element_type
        cdef bytes element_type_name
        sig_obj = self.get_sig_obj()
        if isinstance(sig_obj, net_utils.GenericInstSig):
            return sig_obj.get_generic_type().get_type()
        elif isinstance(sig_obj, net_utils.CorLibTypeSig):
            element_type = sig_obj.get_element_type()
            element_type_name = get_cor_type_name(element_type)
            return self.get_dotnetpe().get_typeref_by_full_name(element_type_name)
        if hasattr(sig_obj, 'get_type'):
            return sig_obj.get_type()
        #TODO: There is a possibility this will require updating as semantics of other signatures are revealed.
        return None
    
    cpdef bytes get_full_name(self):
        """
        Attempts to obtain the full name of a typespec.
        """
        cdef TypeDefOrRef type_obj
        type_obj = self.get_type()
        if type_obj is None:
            #first check and see if we have a corlibtypesig, maybe we can still get the name off that. 
            if isinstance(self.get_sig_obj(), net_utils.CorLibTypeSig):
                try:
                    return get_cor_type_name(self.get_sig_obj().get_element_type())
                except:
                    pass
            return None
        return type_obj.get_full_name()
    
    cpdef list get_methods(self):
        """
        Attempts to obtain all methods associated with a typespec.
        """
        return self.get_type().get_methods()

    cpdef list get_member_refs(self):
        """
        Attempts to obtain all memberrefs associated with a TypeSpec
        """
        return self.get_type().get_member_refs()

    cpdef TypeDefOrRef get_superclass(self):
        """
        Attempts to obtain the superclass of a TypeSpec if it exists.
        """
        return self.get_type().get_superclass()

    def __eq__(self, other):
        if isinstance(other, TypeSpec):
            return other.get_rid() == self.get_rid()
        else:
            return self.get_type() == other

    cpdef net_utils.TypeSig get_sig_obj(self):
        """
        Obtain the Type's signature object.
        """
        cdef net_utils.SignatureReader sig_reader
        cdef bytes signature
        if not self.__parsed_sig and not self.__has_invalid_signature:
            signature = self['Signature'].get_value()
            try:
                sig_reader = net_utils.SignatureReader(self.get_dotnetpe(), signature)
                self.__parsed_sig = sig_reader.handle_type_sig()
            except net_exceptions.InvalidSignatureException:
                self.__has_invalid_signature = True
                return None
        return self.__parsed_sig
    
cdef class StandAloneSig(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__parsed_sig = None
        self.__has_invalid_signature

    cpdef net_utils.TypeSig get_sig_obj(self):
        """
        Obtain the Signature object.
        """
        cdef net_utils.SignatureReader sig_reader
        cdef bytes signature
        if not self.__parsed_sig and not self.__has_invalid_signature:
            signature = self['Signature'].get_value()
            try:
                sig_reader = net_utils.SignatureReader(self.get_dotnetpe(), signature)
                self.__parsed_sig = sig_reader.handle_type_sig()
            except net_exceptions.InvalidSignatureException:
                self.__has_invalid_signature = True
        return self.__parsed_sig

cdef class MethodImpl(RowObject):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__class = None
        self.__declaration = None
        self.__body = None

    cpdef RowObject get_class(self):
        """
        Obtain the Class column of a MethodImpl
        """
        if not self.__class:
            self.__class = self['Class'].get_value()
        return self.__class
    
    cpdef RowObject get_declaration(self):
        """
        Obtain the MethodDeclaration column of MethodImpl
        """
        if not self.__declaration:
            self.__declaration = self['MethodDeclaration'].get_value()

        return self.__declaration
    
    cpdef MethodDef get_body(self):
        """
        Obtain the MethodBody column of a MethodImpl
        """
        if not self.__body:
            self.__body = self['MethodBody'].get_value()
        return self.__body
    
cdef class MethodSemantic(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
    
    cpdef MethodDef get_method(self):
        """
        Obtains the Method object associated with the semantic.
        """
        return self['Method'].get_value()
    
    cpdef RowObject get_assocciation(self):
        """
        Obtain the event or property the semantic is associated with.
        """
        return self['Association'].get_value()
    
    cpdef bint is_setter(self):
        """
        Is the method marked as a property setter method?
        """
        return self['Semantics'].get_raw_value() & net_structs.CorMethodSemanticsAttr.msSetter != 0
    
    cpdef bint is_getter(self):
        """
        Is the method marked as a property getter method?
        """
        return self['Semantics'].get_raw_value() & net_structs.CorMethodSemanticsAttr.msGetter != 0

    cpdef bint is_other(self):
        """
        Is the method marked as an other method for a property or event?
        """
        return self['Semantics'].get_raw_value() & net_structs.CorMethodSemanticsAttr.msOther != 0
    
    cpdef bint is_add_on(self):
        """
        Is the method marked as a addon method for an event?
        """
        return self['Semantics'].get_raw_value() & net_structs.CorMethodSemanticsAttr.msAddOn != 0
    
    cpdef bint is_remove_on(self):
        """
        Is the method marked as a RemoveOn method for an event?
        """
        return self['Semantics'].get_raw_value() & net_structs.CorMethodSemanticsAttr.msRemoveOn != 0
    
    cpdef bint is_fire(self):
        """
        is the method marked as a Fire method for an event?
        """
        return self['Semantics'].get_raw_value() & net_structs.CorMethodSemanticsAttr.msFire != 0
    
    
cdef class PropertyMap(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        
    cdef void process(self):
        cdef int property_list_end
        cdef int property_list_len
        cdef int property_list_start
        cdef list propertylist
        cdef int x
        property_list_len = len(self.get_dotnetpe().get_metadata_table('Property'))
        property_list_end = property_list_len
        if self.get_rid() + 1 < len(self.get_dotnetpe().get_metadata_table('PropertyMap')):
            property_list_end = self.get_dotnetpe().get_metadata_table('PropertyMap').get(self.get_rid() + 1)['PropertyList'].get_raw_value()
        if property_list_end > property_list_len:
            property_list_end = property_list_len
        property_list_start = self['PropertyList'].get_raw_value()
        propertylist = list()
        for x in range(property_list_start, property_list_end):
            propertylist.append(self.get_dotnetpe().get_metadata_table('Property').get(x))
        self['PropertyList'].set_formatted_value(propertylist)

    cpdef RowObject get_parent(self):
        """
        Get the parent type for a property.
        """
        return self['Parent'].get_value()
    
    cpdef list get_properties(self):
        """
        Get all of the properties associated with a parent.
        """
        return self['PropertyList'].get_formatted_value()

cdef dict NET_METADATA_ROW_TYPES = {
    'Module': RowObject,
    'TypeRef': TypeRef,
    'TypeDef': TypeDef,
    'FieldPtr': RowObject,
    'Field': Field,
    'MethodPtr': RowObject,
    'MethodDef': MethodDef,
    'ParamPtr': RowObject,
    'Param': RowObject,
    'InterfaceImpl': RowObject,
    'MemberRef': MemberRef,
    'Constant': RowObject,
    'CustomAttribute': RowObject,
    'FieldMarshal': RowObject,
    'DeclSecurity': RowObject,
    'ClassLayout': RowObject,
    'FieldLayout': RowObject,
    'StandAloneSig': StandAloneSig,
    'EventMap': RowObject,
    'EventPtr': RowObject,
    'Event': RowObject,
    'PropertyMap': PropertyMap,
    'PropertyPtr': RowObject,
    'Property': RowObject,
    'MethodSemantics': MethodSemantic,
    'MethodImpl': MethodImpl,
    'ModuleRef': RowObject,
    'TypeSpec': TypeSpec,
    'ImplMap': RowObject,
    'FieldRVA': RowObject,
    'EncLog': RowObject,
    'EncMap': RowObject,
    'Assembly': RowObject,
    'AssemblyProcessor': RowObject,
    'AssemblyOS': RowObject,
    'AssemblyRef': RowObject,
    'AssemblyRefProcessor': RowObject,
    'AssemblyRefOS': RowObject,
    'File': RowObject,
    'ExportedType': RowObject,
    'ManifestResource': RowObject,
    'NestedClass': RowObject,
    'GenericParam': GenericParam,
    'MethodSpec': MethodSpec,
    'GenericParamConstraint': RowObject
}

cdef get_rowobject_for_table(str table_id):
    return NET_METADATA_ROW_TYPES[table_id]