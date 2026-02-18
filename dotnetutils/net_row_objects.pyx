#cython: language_level=3
#distutils: language=c++


import os
import hashlib
from dotnetutils import net_exceptions, net_graphing
from dotnetutils cimport net_structs
from dotnetutils cimport net_sigs
from dotnetutils cimport net_utils
from dotnetutils cimport net_cil_disas
from dotnetutils cimport net_tokens
from dotnetutils cimport net_table_objects
from dotnetutils cimport net_processing, net_opcodes

cdef class RowObject:

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        """ Initializes a row object by interpreting the raw data.
        """
        self.dotnetpe = dotnetpe
        self.rid = rid
        if len(raw_data) == 0: #For DynamicMethodObjects
            self.file_offset = 0
        else:
            self.file_offset = raw_data[-1]
        self.values = dict()
        self.table_name = table_name
        self.sizes = sizes
        index = 0
        for col_name, col_type in col_types.items():
            cval = ColumnValue(col_type, sizes[index], raw_data[index], (<dotnetpefile.DotNetPeFile>self.dotnetpe), col_name, self)
            if hasattr(self, 'format_{}_column'.format(col_name).lower()):
                cval.set_formatter_method(getattr(self, 'format_{}_column'.format(col_name).lower()), None)
            self.values[col_name.lower()] = cval
            index += 1

    cpdef ColumnValue get_column(self, str col_name):
        return <ColumnValue>self.values[col_name.lower()]
    
    cpdef list get_sizes(self):
        """ Get a list of sizes in bytes of each column.
        """
        return self.sizes

    cpdef base.DotNetUtilsBaseType get_dotnetpe(self):
        """ Get the dotnetpefile.DotNetPeFile that spawned this RowObject
        """
        return (<dotnetpefile.DotNetPeFile>self.dotnetpe)

    cpdef int get_rid(self):
        """ Obtain the RID of a RowObject. A RID is a 1 based index of the row in a specific metadata table.
        """
        return self.rid

    cpdef str get_table_name(self):
        """ Obtain the name of the table that a row is associated with.
        """
        return self.table_name

    cpdef int get_token(self) except *:
        """ Obtain the MDToken value for the column.
        """
        return net_tokens.get_Signature().encode_token(self.get_table_name(), self.get_rid())

    cpdef int get_file_offset(self):
        """ Obtain the offset of the row in the file.
        """
        return self.file_offset

    def __len__(self):
        cdef Py_ssize_t result = 0
        cdef ColumnValue value = None
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
        return self.get_column(item)

    def __str__(self):
        if 'name' in self.values:
            try:
                return self.get_column('Name').get_value().decode('ascii')
            except UnicodeDecodeError:
                pass
        return '{}:{}'.format(self.get_table_name(), self.get_rid())

    cpdef bint has_value(self, str val_name):
        """ Does the row have a value by val_name?
        """
        return val_name.lower() in self.values.keys()

    cpdef int get_offset_to_col(self, str col_name):
        """ Obtain the offset in bytes to the column matching col_name
        """
        cdef int result = 0
        cdef str key
        cdef ColumnValue value
        for key, value in self.values.items():
            if key == col_name.lower():
                break
            result += <int>len(value)
        return result

    cdef void process(self):
        """ Process can be used to manipulate the column values
            For instance, param lists for TypeDefs are stored by the starting index
            Requires some logic to actually obtain the full list of params.
        """
        pass

    cdef void post_process(self):
        """ Post process is called after process().
        """
        pass

    cpdef bytes to_bytes(self):
        """ Convert a row to bytes.
        """
        cdef bytes result
        cdef ColumnValue item
        result = b''
        for item in self.values.values():
            result += item.to_bytes()

        return result

    cdef void initialize_columns(self):
        """ Ensures column.original_value is populated by calling get_value() on each column
            right after everything is post-processed.
        """
        cdef ColumnValue column
        for column in self.values.values():
            column.get_value() # make sure original_value is populated.

cdef class ColumnValue:
    """
    A wrapper for column values with different ways to access the data and its properties.
    """

    def __init__(self, net_tokens.BaseToken col_type, unsigned int col_size, unsigned int raw_value, dotnetpefile.DotNetPeFile dotnetpe, str col_name, net_row_objects.RowObject row_obj):
        self.col_type = col_type
        self.col_size = col_size
        self.raw_value = raw_value
        self.formatted_value = None
        self.has_changed_value = False
        self.cached_value = None
        self.dotnetpe = dotnetpe
        self.col_size = self.internal_get_size()
        self.col_name = col_name
        self.row_obj = row_obj
        self.original_value = None
        self.__has_no_value = False
        self.__formatter_method = None
        self.__formatter_param = None

    cdef bytes get_value_as_bytes(self):
        """ Obtain the value associated with a column, casted to bytes.

        Returns:
            bytes: The value, as bytes.
        """
        return <bytes>self.get_value()

    cdef int get_value_as_int(self):
        """ Obtain the value associated with a column, casted to int.

        Returns:
            int: The value, as int.
        """
        return <int>self.get_value()

    cdef RowObject get_value_as_rowobject(self):
        """ Obtain the value associated with a column, casted to RowObject

        Returns:
            net_row_objects.RowObject: The value, as RowObject.
        """
        return <RowObject>self.get_value()

    cpdef void set_formatter_method(self, formatter_method, formatter_param):
        """ Unused and likely to be removed.
        """
        self.__formatter_method = formatter_method
        self.__formatter_param = formatter_param

    cdef int internal_get_size(self) except *:
        """ For internal use mostly, but obtains the expected size of a column's value.
        """
        if self.col_type.is_stream():
            if self.col_type == net_tokens.get_BlobStream():
                return (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_dir().get_metadata_table_header().get_heap_offset_size(
                    net_structs.CorHeapBitmask.BITMASK_BLOB)
            elif self.col_type == net_tokens.get_StringsStream():
                return (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_dir().get_metadata_table_header().get_heap_offset_size(
                    net_structs.CorHeapBitmask.BITMASK_STRINGS)
            elif self.col_type == net_tokens.get_GuidStream():
                return (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_dir().get_metadata_table_header().get_heap_offset_size(
                    net_structs.CorHeapBitmask.BITMASK_GUID)
            raise net_exceptions.InvalidArgumentsException()
        else:
            return self.col_size
        
    cpdef object get_original_value(self):
        """ If possible, obtain the original value that this column had.
            NOTE: Will not work if no_processing is set to True.
        
        Returns:
            object: The original value.  Usually either bytes, RowObject or int.
        """
        if self.original_value == None:
            self.get_value()
        return self.original_value

    cpdef void change_value(self, object new_value) except *:
        """ Change a value
            Currently only works with CodedTokens specifically,
            but this function does the legwork to change a value. 
            An example of when this might be useful is deobfuscating method names

        Args:
            new_value (object): The new value.  Must match the expected type for the column.
        Raises:
            net_exceptions.InvalidArgumentsException: Invalid new_value or internal error.
            net_exceptions.FeatureNotImplementedException: Attempted to change a column that currently isnt supported by this method.
        """
        cdef str table_name = None
        cdef int table_rid = 0
        cdef int orig_value = self.raw_value
        cdef net_processing.HeapObject stream = None
        if self.original_value == None:
            self.get_value()
        if new_value is None:
            raise net_exceptions.InvalidArgumentsException()
        if self.col_type.is_stream():
            table_name = self.col_type.get_token_types()[0]
            stream = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_heap(table_name)
            if stream is None:
                raise net_exceptions.InvalidArgumentsException()
            self.raw_value = stream.get_next_append_index()
            stream.append_item(new_value)
            self.cached_value = None
            self.__has_no_value = False #Reset everything for next grab.
            if orig_value != 0 and stream.has_offset(orig_value): #Stream.del_item() already handles references checks.  It will warn for now but thats fine.
                #If the stream doesnt have the offset, its probably an invalid row.  Allow the change but dont delete original.
                stream.del_item(orig_value)
        elif self.col_type.is_fixed_value():
            self.raw_value = new_value
            (<dotnetpefile.DotNetPeFile>self.dotnetpe).update_streams() # Ensure the raw change is updated in.
        else:
            #I dont think it would be safe to edit metadata columns that reference other metadata columns.
            #Nor can I really think of a good reason to do it right now.  May be something to implement later.
            raise net_exceptions.FeatureNotImplementedException()
    
    cdef object __retrieve_value(self):
        """ INTERNAL USE ONLY. Internal method for retrieving a column's value
        
        Returns:
            object: None on failure, either RowObject, int, bytes otherwise.
        """
        cdef str table_name
        cdef int table_rid
        cdef net_table_objects.TableObject table_obj
        cdef net_processing.HeapObject heap_obj
        cdef object result
        #TODO: add some sort of detection for calling this function when the tables arent fully initialized.
        try:
            table_name, table_rid = self.col_type.decode_token(self.raw_value)
        except net_exceptions.InvalidTokenException:
            return None
        if table_name is None:
            return table_rid
        elif self.col_type.is_stream():
            if (<dotnetpefile.DotNetPeFile>self.dotnetpe).has_heap(table_name):
                heap_obj = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_heap(table_name)
                result = heap_obj.get_item(table_rid)
                return result
        elif self.col_type.is_fixed_value():
            return self.raw_value
        else:
            if (<dotnetpefile.DotNetPeFile>self.dotnetpe).has_metadata_table(table_name):
                return (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_heap('#~').get_table(table_name).get(table_rid)
        if table_name is None:
            return None
        table_obj = (<dotnetpefile.DotNetPeFile>self.dotnetpe).get_metadata_table(table_name)
        if table_obj is None:
            self.__has_no_value = True
            return None
        return table_obj.get(table_rid)
    
    cpdef bint has_value(self):
        """ Does the column actually have a value?
        """
        return not self.__has_no_value

    cpdef object get_value(self):
        """ Obtain the processed value corresponding to the raw_value
        
        Returns:
            object: The processed value corresponding to the column
        """
        #check if value was changed
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
        """ Internal Method.Used by certain rowobjects to set formatted value (e.x FieldList, MethodList etc)
        
        Args:
            value (object): The formatted value
        """
        self.formatted_value = value

    cpdef object get_formatted_value(self):
        """ Obtains the formatted value for a column

        Returns:
            object: The formatted value, usually a list.
        """
        #formatter method sig: def formatter_method(ColumnValue, DotNetPeFile, RowObject, object)
        if self.formatted_value == None and self.__formatter_method != None:
            self.set_formatted_value(self.__formatter_method(self, (<dotnetpefile.DotNetPeFile>self.dotnetpe), self.row_obj, self.__formatter_param))
        return self.formatted_value

    cpdef object get_changed_value(self):
        """ Get the new value of a ColumnValue (will return none if change_value() was never called.)
            Currently this is the same as get_value().
        """
        return self.get_value()

    cpdef unsigned int get_raw_value(self) except *:
        """ Obtain the raw, unprocessed value.
        
        Returns:
            unsigned int: the raw integer value
        """
        return self.raw_value
    
    cpdef bint was_value_changed(self):
        """ Was the value changed?

        Returns:
            bool: True if the value has changed, False otherwise.
        """
        if self.original_value is None:
            return False
        return self.original_value != self.cached_value
    
    cpdef void set_raw_value(self, unsigned int new_value):
        """ Set the raw value of the column.  Useful for some patching operations.
        """
        self.has_changed_value = True
        self.raw_value = new_value
        self.cached_value = None
        self.__has_no_value = False

    def __len__(self):
        return self.col_size

    cpdef str get_value_table_name(self):
        """ Get the name of the table the value corresponds to.
        """
        cdef str tbl_name
        cdef unsigned int tbl_rid
        try:
            tbl_name, tbl_rid = self.col_type.decode_token(self.raw_value)
            return tbl_name
        except net_exceptions.InvalidTokenException:
            return None
        
    cpdef tuple get_value_location(self):
        """ Get the token meaning for a column value (str, int) (table / heap name, index)
        """
        return self.col_type.decode_token(self.raw_value)

    cpdef int get_value_rid(self):
        """ Get the RID that the value corresponds to.
        
        Returns:
            int: -1 if error, the table rid of the value otherwise.
        """
        cdef str tbl_name
        cdef int tbl_rid
        try:
            tbl_name, tbl_rid = self.col_type.decode_token(self.raw_value)
            return tbl_rid
        except net_exceptions.InvalidTokenException:
            return -1
        
    cpdef bytes to_bytes(self):
        """ Obtain a bytes representation of the column.
        """
        try:
            return int.to_bytes(self.get_raw_value(), self.internal_get_size(), 'little', signed=False)
        except Exception as e:
            raise e

    cpdef net_tokens.BaseToken get_col_type(self):
        """ Obtain an item that represents the type of value the column holds.
        """
        return self.col_type

    def __eq__(self, other):
        return isinstance(other,
                          ColumnValue) and other.get_raw_value() == self.get_raw_value() and other.col_type == self.col_type

cdef class TypeDefOrRef(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)

    cdef void _add_method(self, MethodDefOrRef method_obj):
        pass #This should never be called.

    cpdef MethodDef get_static_constructor(self):
        return None

    cpdef list get_constructors(self):
        return list()

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

    cpdef bint is_enum(self):
        return False

    cdef void process(self):
        pass

    cpdef list get_methods(self):
        return list()

    cdef void post_process(self):
        pass

    cpdef bytes get_full_name(self):
        return bytes()

    cpdef Field get_field(self, bytes name):
        return None

    cpdef list get_methods_by_name(self, bytes name):
        return None

    cpdef TypeDefOrRef get_type(self):
        return self

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

    cpdef MethodDef get_static_constructor(self):
        """ Obtain the type's static constructor if exists.

        Returns:
            net_row_objects.MethodDef: The static constructor, or None if it doesnt exist.  Not all types have one, but there can only be one.
        """
        cdef list results
        if not self.__cctor_method:
            results = self.get_methods_by_name(b'.cctor')
            if len(results) == 1:
                self.__cctor_method = results[0]
        return self.__cctor_method

    cpdef list get_constructors(self):
        """ Obtain a list of methods with the special name '.ctor'

        Returns:
            list[net_row_objects.MethodDef]: A list of constructors.
        """
        return self.get_methods_by_name(b'.ctor')

    cpdef TypeDef get_enclosing_type(self):
        """ Obtain the type's enclosing type if its a NestedClass.

        Returns:
            net_row_objects.TypeDef: None if the class isnt nested, the enclosing type otherwise.
        """
        cdef net_table_objects.TableObject nested_classes
        cdef RowObject nested
        if not self.__enclosing_type and self.__has_enclosing_type:
            nested_classes = self.get_dotnetpe().get_metadata_table('NestedClass')
            if nested_classes is not None:
                for nested in nested_classes:
                    if <int>nested.get_column('NestedClass').get_raw_value() == self.rid:
                        self.__enclosing_type = self.get_dotnetpe().get_metadata_table('TypeDef').get(
                            nested.get_column('EnclosingClass').get_raw_value())
                        break
            if not self.__enclosing_type:
                self.__has_enclosing_type = False
        return self.__enclosing_type

    cpdef RowObject get_classlayout_obj(self):
        """ Obtain a classlayout object associated with the type if exists.

        Returns:
            net_row_objects.RowObject: The ClassLayout object, if it exists.
        """
        cdef net_table_objects.ClassLayoutTable classlayout_table
        if not self.__classlayout_obj:
            classlayout_table = self.get_dotnetpe().get_metadata_table('ClassLayout')
            if classlayout_table:
                self.__classlayout_obj = classlayout_table.get_layout_by_parent(
                    self.rid)
        return self.__classlayout_obj

    cpdef TypeDefOrRef get_superclass(self):
        """ Obtain the Type's superclass.

        Returns:
            net_row_objects.TypeDef: None if the method extends System.Object only or doesnt have a superclass, the superclass otherwise.
        """
        cdef bint skip
        cdef TypeDefOrRef extends_obj
        cdef TypeDefOrRef add_to
        if self.get_column('Extends').get_raw_value() != 0 and self.__has_superclass and not self.__superclass:
            skip = False
            if self.get_column('Extends').get_value_table_name() == 'TypeRef':
                extends_obj = self.get_column('Extends').get_value()
                if not extends_obj or extends_obj.get_column('TypeName').get_value() == b'Object': #TODO: should object be considered a valid superclass?
                    skip = True
            if not skip:
                self.__superclass = self.get_column('Extends').get_value()
                if isinstance(self.__superclass, TypeDefOrRef):
                    add_to = self.__superclass
                    add_to._add_child_class(self)
                else:
                    self.__superclass = None
                    self.__has_superclass = False

            if not self.__superclass:
                self.__has_superclass = False
        return self.__superclass

    cpdef list get_interfaces(self):
        """ Obtain a list of interfaces associated with the type.

        Returns:
            list[net_row_objects.TypeDefOrRef]: A list of interfaces associated with the type.
        """
        return self.__interfaces

    cpdef list get_child_classes(self):
        """ Obtains a list of classes that extend this type.

        Returns:
            list[net_row_objects.TypeDefOrRef]: A list of classes that extend this type.
        """
        return self.__child_classes

    cpdef void _add_child_class(self, TypeDefOrRef obj):
        """ Internal method for adding child classes to a type during processing.
        """
        if obj not in self.__child_classes:
            self.__child_classes.append(obj)

    cpdef list get_member_refs(self):
        """ Obtains any memberrefs associated with the type.  This is usually used alongside generic methods and such.

        Returns:
            list[net_row_objects.MemberRef]: A list of memberrefs associated with this type.
        """
        return self._memberrefs

    cpdef list get_generic_params(self):
        """ Obtains a list of GenericParams associated with the type.

        Returns:
            list[net_row_objects.GenericParam]: A list of generic params associated with this type.
        """
        return self._generic_params

    cpdef bint is_valuetype(self):
        """ Determines whether or not the class is a System.ValueType.

        Returns:
            bool: True if its a valuetype, False otherwise.
        """
        if not self.__has_superclass:
            return False
        cdef TypeDefOrRef ptr = self.get_superclass()
        while ptr is not None:
            if isinstance(ptr, TypeDef):
                ptr = ptr.get_superclass()
            elif isinstance(ptr, TypeRef):
                return ptr.is_valuetype()
            elif isinstance(ptr, TypeSpec):
                ptr = ptr.get_type()
        return False

    cpdef bint is_enum(self):
        """ Determines whether or not this class extends System.Enum

        Returns:
            bool: True if enum, False otherwise.
        """
        if not self.__has_superclass:
            return False
        cdef TypeDefOrRef ptr = self.get_superclass()
        while ptr is not None:
            if isinstance(ptr, TypeDef):
                ptr = ptr.get_superclass()
            elif isinstance(ptr, TypeRef):
                return ptr.is_enum()
            elif isinstance(ptr, TypeSpec):
                ptr = ptr.get_type()
        return False

    cdef void process(self):
        cdef int field_start_index
        cdef list fieldlist
        cdef int field_end_index
        cdef int x
        cdef Field field_obj
        cdef list methodlist
        cdef int method_start_index
        cdef int method_table_len
        cdef int method_index_end
        cdef net_table_objects.MethodDefTable method_table = self.get_dotnetpe().get_metadata_table('MethodDef')
        cdef net_table_objects.TableObject methodptr_table = self.get_dotnetpe().get_metadata_table('MethodPtr')
        cdef net_table_objects.TableObject fieldptr_table = self.get_dotnetpe().get_metadata_table('FieldPtr')
        cdef net_table_objects.TypeDefTable typedef_table = self.get_dotnetpe().get_metadata_table('TypeDef')
        cdef net_table_objects.TableObject field_table = self.get_dotnetpe().get_metadata_table('Field')
        cdef MethodDef method
        field_start_index = self.get_column('FieldList').get_raw_value()
        fieldlist = list()
        if field_table is not None and self.get_column('FieldList').get_raw_value() != 0:
            if fieldptr_table is None:
                field_end_index = <int>len(field_table) + 1
                if typedef_table.has_index(self.rid + 1):
                    field_end_index = typedef_table.get(self.rid + 1).get_column('FieldList').get_raw_value()
                if not field_table.has_index(field_end_index):
                    field_end_index = <int>len(field_table) + 1
            else:
                field_end_index = <int>len(fieldptr_table) + 1
                if typedef_table.has_index(self.rid + 1):
                    field_end_index = typedef_table.get(self.rid + 1).get_column('FieldList').get_raw_value()
                if not fieldptr_table.has_index(field_end_index):
                    field_end_index = <int>len(fieldptr_table) + 1
            for x in range(field_start_index, field_end_index):
                if fieldptr_table is None:
                    field_obj = field_table.get(x)
                else:
                    field_obj = fieldptr_table.get(x).get_column('Field').get_value()
                if field_obj:
                    field_obj._set_parent_type(self)
                    fieldlist.append(field_obj)
            self.get_column('FieldList').set_formatted_value(fieldlist)
        if method_table is not None and self.get_column('MethodList').get_raw_value() != 0:
            methodlist = list()
            method_start_index = self.get_column('MethodList').get_raw_value()
            if methodptr_table is None:
                method_table_len = <int>len(method_table) + 1
                method_index_end = method_table_len

                if typedef_table.has_index(self.rid + 1):
                    method_index_end = typedef_table.get(self.rid + 1).get_column('MethodList').get_raw_value()
                if not method_table.has_index(method_index_end):
                    method_index_end =<int> len(method_table) + 1
            else:
                method_table_len = <int>len(methodptr_table) + 1
                method_index_end = method_table_len
                if typedef_table.has_index(self.rid + 1):
                    method_index_end = typedef_table.get(self.rid + 1).get_column('MethodList').get_raw_value()
                if not methodptr_table.has_index(method_index_end):
                    method_index_end = method_table_len
            for x in range(method_start_index, method_index_end):
                if methodptr_table is None:
                    method = method_table.get(x)
                else:
                    method = methodptr_table.get(x).get_column('Method').get_value()
                method._set_parent_type(self)
                methodlist.append(method)
            self.get_column('MethodList').set_formatted_value(methodlist)

    cpdef list get_methods(self):
        """ Obtain a list of MethodDef objects associated with the TypeDef.

        Returns:
            list[net_row_objects.MethodDef]: A list of methods associated with the type.
        """
        return self.get_column('MethodList').get_formatted_value()

    cdef void post_process(self):
        cdef net_processing.MetadataTableHeapObject metadata_heap
        cdef RowObject item
        cdef RowObject interface_obj
        
        if self.__has_interfaces:
            metadata_heap = self.get_dotnetpe().get_heap('#~')
            if metadata_heap.has_table('InterfaceImpl'):
                for item in metadata_heap.get_table('InterfaceImpl'):
                    if <int>item.get_column('Class').get_raw_value() == self.rid:
                        interface_obj = item.get_column('Interface').get_value()
                        if interface_obj:
                            interface_obj._add_child_class(self)

                            self.__interfaces.append(interface_obj)
            if len(self.__interfaces) == 0:
                self.__has_interfaces = False
        self.get_superclass()

    cpdef bytes get_full_name(self):
        """ Obtain the full name of the class, including the namespace

        Returns:
            bytes: The full name of the type, including namespace.  E.x System.Object
        """
        cdef TypeDef ptr
        cdef bytes result
        cdef TypeDef old_ptr
        cdef bytes type_namespace = None
        if not self.__full_name: # ensure enclosing_type is populated.
            ptr = self.get_enclosing_type()
            if ptr is None:
                type_namespace = self.get_column('TypeNamespace').get_value()
                if type_namespace is None or type_namespace == b'':
                    return self.get_column('TypeName').get_value()
                return type_namespace + b'.' + self.get_column('TypeName').get_value()
            result = self.get_column('TypeName').get_value()
            old_ptr = None
            while ptr is not None:
                result = ptr.get_column('TypeName').get_value() + b'.' + result
                old_ptr = ptr
                ptr = ptr.get_enclosing_type()
            type_namespace = old_ptr.get_column('TypeNamespace').get_value()
            if type_namespace is not None and type_namespace != b'':
                result = type_namespace + b'.' + result
            self.__full_name = result

        return self.__full_name

    cpdef Field get_field(self, bytes name):
        """ Obtain a field object matching 'name' from the type

        Returns:
            net_row_objects.Field: A field from the type that matches name.
        """
        cdef Field field
        for field in self.get_column('FieldList').get_formatted_value():
            if field.get_column('Name').get_value() == name:
                return field
        return None

    cpdef list get_methods_by_name(self, bytes name):
        """ Obtain a method matching 'name' from the type

        Returns:
            list[net_row_objects.MethodDef]: A list of MethodDef objects from the type associated with name.
        """
        cdef list result
        cdef MethodDef method
        if name == self.get_column('TypeName').get_value():
            return self.get_methods_by_name(b'.ctor')
        result = list()
        for method in self.get_column('MethodList').get_formatted_value():
            if method.get_column('Name').get_value() == name:
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
        """ Obtain a list of tuples (method_rid, instr_offset) representing references of a Field.
            Field references occur when stsfld, ldsfld, stfld, ldfld are called on a Field.

        Returns:
            list[tuple[int, int]]: A list of xrefs for the field.
        """
        return self.__xrefs

    cpdef void _add_xref(self, int rid, int instr_offset):
        """ Internal method to register xrefs.
        """
        self.__xrefs.append((rid, instr_offset))

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        """ Internal method to register parent types.
        """
        self.__parent_type = parent_type

    cpdef TypeDefOrRef get_parent_type(self):
        """ Obtain the field's parent type.

        Returns:
            net_row_objects.TypeDefOrRef: parent type of the field, or None if not found.
        """
        return self.__parent_type

    cdef void process(self):
        cdef net_table_objects.FieldRVATable fieldrva_table
        fieldrva_table = self.get_dotnetpe().get_metadata_table('FieldRVA')
        if fieldrva_table:
            self.__rva_object = fieldrva_table.get_by_field_rid(self.get_rid())

    cpdef net_sigs.FieldSig get_field_signature(self):
        """ Obtains the signature object associated with the field.

        Returns:
            net_sigs.FieldSig: A field signature object with the signature of the field.
        """
        if not self.__sig_obj:
            self.__initialize_sig()
        return self.__sig_obj

    cdef void __initialize_sig(self):
        """ Internal method for initializing the fields signature
        """
        cdef bytes sig
        cdef net_sigs.SignatureReader sig_reader
        cdef net_sigs.TypeSig type_obj
        cdef TypeDefOrRef typedef_obj
        sig = self.get_column('Signature').get_value()
        if sig:
            sig_reader = net_sigs.SignatureReader(self.get_dotnetpe(), sig)
            self.__sig_obj = sig_reader.read_signature()
            if isinstance(self.__sig_obj, net_sigs.FieldSig):
                type_obj = self.__sig_obj.get_type_sig()
                if isinstance(type_obj, net_sigs.TypeDefOrRefSig) and type_obj.get_type() != None:
                    typedef_obj = type_obj.get_type()
                    self.__field_type = typedef_obj
                    if isinstance(typedef_obj, TypeDef) and typedef_obj.get_classlayout_obj():
                        self.__class_size = typedef_obj.get_classlayout_obj().get_column('ClassSize').get_value()
                elif isinstance(type_obj, net_sigs.CorLibTypeSig):
                    if type_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_I8:
                        self.__class_size = 8
                    elif type_obj.get_element_type() == net_structs.CorElementType.ELEMENT_TYPE_R4:
                        self.__class_size = 4

    cpdef bint is_static(self):
        """ Checks if the field is static or not.

        Returns:
            bool: True if fdStatic is set, False otherwise.
        """
        return self.get_column('Flags').get_value() & net_structs.CorFieldAttr.fdStatic != 0

    cpdef bytes get_data(self):
        """ If the field has initial constant data, attempt to obtain it.
        
        Returns:
            bytes: The initial constant data for a field, or None if not found.
                Useful for obtaining the initial data that a field is eventually set to by the CLR.
        """
        cdef int rva
        cdef uint64_t offset
        if not self.__rva_object:
            return None

        if not self.__sig_obj or self.__class_size == 0:
            self.__initialize_sig()

        if self.__class_size == 0:
            return None

        rva = self.__rva_object.get_column('RVA').get_value()
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
        self.__enum_value = 0

    cpdef bint is_enum(self):
        """ Checks if the type's name matches System.Enum and thus is an Enum.
            So the problem here is now we can only determine if its a valuetype.  We need other assemblies to go further.
            so for now, assume valuetypes are enums for the purpose of this function in order to get the emulator to work. 
            TODO: make some sort of fix here, maybe have the emulator use a version of the function that can look into mscorlib types

        Returns:
            bool: True if the type is enum, False otherwise.
        """
        if self.__enum_value == 1:
            return True
        if self.__enum_value == 2:
            return False
        #So the problem here is now we can only determine if its a valuetype.  We need other assemblies to go further.
        #so for now, assume valuetypes are enums for the purpose of this function in order to get the emulator to work.
        if self.get_full_name() == b'System.Enum':
            self.__enum_value = 1
            return True
        self.__enum_value = 2
        return False

    cpdef bint is_valuetype(self):
        """ Checks if the type's name matches System.ValueType and thus is a ValueType

        Returns:
            bool: True if the type is valuetype, False otherwise.
        """
        return self.get_full_name() == b'System.ValueType'

    cpdef list get_member_refs(self):
        """ Obtains any memberrefs associated with the TypeRef.

        Returns:
            list[net_row_objects.MemberRef]: A list of MemberRefs associated with the TypeRef.  Usually imported methods like FromBase64String() etc.
        """
        return self._memberrefs

    cpdef TypeDefOrRef get_superclass(self):
        """ Gets the superclass of the type.

        Returns:
            net_row_objects.TypeDefOrRef: The superclass for the type.  Usually going to be None since thats not within this binary's metadata.
        """
        return self.__superclass

    cpdef list get_interfaces(self):
        """ Obtains any interfaces inherited by the type.

        Returns:
            list[net_row_objects.TypeDefOrRef]: A list of interfaces associated with the type.
        """
        return self.__interfaces

    cpdef void _add_child_class(self, TypeDefOrRef obj):
        """ Internal method to add a child class.
        """
        if obj not in self.__child_classes:
            self.__child_classes.append(obj)

    cpdef list get_child_classes(self):
        """ Obtains any child classes for the type.

        Returns:
            list[net_row_objects.TypeDefOrRef]: a list of child classes for the type (within this binary's metadata)
        """
        return self.__child_classes
    
    cdef void _add_method(self, MethodDefOrRef method_obj):
        """ Internal method to add a method to the type, might be removed.
        """
        if method_obj in self.__methods:
            return
        self.__methods.append(method_obj)

    cpdef list get_methods(self):
        """ Obtains any methods associated with the type.

        Returns:
            list[net_row_objects.MethodDef]: Likely to return a blank list.
        """
        return self.__methods

    cpdef list get_methods_by_name(self, bytes method_name):
        """ Obtain a list of MemberRefs associated with the type that match method_name.

        Returns:
            list[net_row_objects.MemberRef]: A list of member refs associated with the type that match the name.
        """
        cdef list result
        cdef MemberRef method
        result = list()
        for method in self.get_member_refs():
            if method.get_column('Name').get_value() == method_name:
                result.append(method)
        return result

    cpdef MethodDef get_static_constructor(self):
        """ Obtains the type's static constructor if exists.
            I dont think this is a thing for TypeRefs

        Returns:
            net_row_objects.MethodDef: Likely None.
        """
        cdef list results
        if not self.__cctor_method:
            results = self.get_methods_by_name(b'.cctor')
            if len(results) == 1:
                self.__cctor_method = results[0]
        return self.__cctor_method

    cpdef list get_constructors(self):
        """ Obtain a list of constructors associated with the TypeRef.

        Returns:
            list[net_row_objects.MemberRef]: A list of constructors associated with the type.
        """
        return self.get_methods_by_name(b'.ctor')

    cpdef bytes get_full_name(self):
        """ Obtains the full name of the type.

        Returns:
            bytes: the full name of the type, e.x System.Object
        """
        cdef bytes type_namespace
        cdef bytes type_name
        if not self.__full_name:
            type_namespace = self.get_column('TypeNamespace').get_value()
            type_name = self.get_column('TypeName').get_value()
            if type_name:
                if type_namespace:
                    self.__full_name = type_namespace + b'.' + type_name
                else:
                    self.__full_name = type_name
            else:
                return None
        return self.__full_name

    def __str__(self):
        return self.get_full_name().decode('utf-8')

cdef class MethodDefOrRef(RowObject):

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)

    cpdef void set_method_data(self, bytes new_data):
        pass

    cpdef bytes get_name(self):
        return b''

    cpdef net_cil_disas.MethodDisassembler disassemble_method(self, bint no_save=False, bint original=False):
        return None

    cpdef bytes get_original_method_data(self):
        return bytes()

    cpdef list get_xrefs(self):
        return list()

    cpdef void _add_xref(self, int rid, int instr_offset):
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

    cpdef bint is_newslot(self):
        return False

    cpdef bint is_final(self):
        return False

    cpdef bint is_static_method(self):
        return False

    cpdef net_sigs.CallingConventionSig get_method_signature(self):
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
        self.__graph = None
        self.__was_something_changed = False

    cpdef bint replace_instruction(self, unsigned int offset, net_cil_disas.Instruction instr):
        """ Replaces an instruction within a method with another instruction.
            begin_recompile() must be called before calling this method.

            Do not use this method.  It is a work in progress and does not currently work.
            Use DotNetPeFile.patch_instruction().

        Args:
            offset (unsigned int): The offset within the ORIGINAL method to replace.
            instr (net_cil_disas.Instruction): The instruction to replace it with.
        Returns:
            bint: True if successful, False otherwise.
        """
        return self.remove_instruction(offset) and self.add_instruction(offset, instr)

    cpdef bint add_instruction(self, unsigned int offset, net_cil_disas.Instruction instr):
        """ adds an instruction to a method's code.
            begin_recompile() must be called before calling this method.

            Do not use this method.  It is a work in progress and does not currently work.
            Use DotNetPeFile.patch_instruction().

        Args:
            offset (unsigned int): The offset within the ORIGINAL method to add.
            instr (net_cil_disas.Instruction): The instruction to add.
        Returns:
            bint: True if successful, False otherwise.
        """
        cdef object block = None
        cdef net_cil_disas.Instruction insn = None
        cdef net_cil_disas.Instruction target_instr = None
        cdef object next_block = None
        cdef unsigned int target = 0
        if self.__graph is None:
            return False

        block = self.__graph.get_block_by_offset(offset)
        if block is None:
            return False
        for insn in block.get_instrs():
            if insn.get_instr_offset() == offset:
                target_instr = insn
                break
        if target_instr is None:
            return False
        if instr.is_branch() or instr.is_absolute_jmp():
            next_block = block.split_block(offset)
            self.__graph.register_block(offset, next_block)

            if instr.get_opcode() == net_opcodes.Opcodes.Switch:
                instr.setup_instr_offset(offset, target_instr.get_instr_index())
                for target in instr.get_arguments():
                    block.add_next(self.__graph.get_block_by_offset(target))
            else:
                if instr.is_branch():
                    target = offset + <int>len(instr) + instr.get_argument()
                    block.add_next(self.__graph.get_block_by_offset(target))    
                else:
                    block.remove_next(next_block)
                    target = offset + <int>len(instr) + instr.get_argument()
                    block.add_next(self.__graph.get_block_by_offset(target))
        instr.setup_instr_offset(offset, target_instr.get_instr_index())
        block.insert_instr(target_instr.get_instr_index(), instr)
        self.__was_something_changed = True
        return True

    cpdef bint remove_instruction(self, unsigned int offset):
        """ Removes an instruction from a method's code.
            begin_recompile() must be called before calling this method.

            Do not use this method.  It is a work in progress and does not currently work.
            Use DotNetPeFile.patch_instruction().

        Args:
            offset (unsigned int): The offset within the ORIGINAL method to remove.
        Returns:
            bint: True if successful, False otherwise.
        """
        cdef object block = None
        cdef net_cil_disas.Instruction instr = None
        cdef net_cil_disas.Instruction target_instr = None
        cdef object next_block = None
        cdef unsigned int index = 0
        cdef unsigned int target = 0
        if self.__graph is None:
            return False

        block = self.__graph.get_block_by_offset(offset)
        if block is None:
            return False
        for instr in block.get_instrs():
            if instr.get_instr_offset() == offset:
                target_instr = instr
                break
        if target_instr is None:
            return False
        if target_instr.is_branch() or target_instr.is_absolute_jmp():
            if target_instr.get_opcode() == net_opcodes.Opcodes.Switch:
                for target in target_instr.get_arguments():
                    block.remove_next(self.__graph.get_block_by_offset(target))
            else:
                if target_instr.is_branch():
                    target = target_instr.get_instr_offset() + <int>len(instr)
                    block.remove_next(self.__graph.get_block_by_offset(target))
                    target = target_instr.get_argument() + <int>len(target_instr) + offset
                    block.remove_next(self.__graph.get_block_by_offset(target))
                else:
                    target = target_instr.get_instr_offset() + <int>len(instr) + target_instr.get_argument()
                    block.remove_next(self.__graph.get_block_by_offset(target))
        index = target_instr.get_instr_index()
        block.remove_instrs(index, index + 1) #TODO This wont work - need to fix these methods.
        self.__was_something_changed = True
        return True

    cpdef bint finish_recompile(self):
        """ Finish recompiling a method and patch it into the exe file.

            Do not use this method.  It is a work in progress and does not currently work.
            Use DotNetPeFile.patch_instruction().

        Returns:
            bint: True if successful, False otherwise.
        """
        if self.__graph is None:
            return False

        if not self.__was_something_changed:
            self.__graph = None
            return True #if nothings been edited, dont do anything.
        cdef list instrs = None
        cdef list exc_blocks = None
        cdef int localvartok = self.disassemble_method().get_local_var_sig_token()
        cdef object fanalyzer = net_graphing.GraphAnalyzer(self, self.__graph)
        cdef object recompiler = None
        cdef bytes data = None
        fanalyzer.repair_blocks()
        instrs = self.__graph.emit_instructions_as_list()
        exc_blocks = self.__graph.get_exception_blocks()
        recompiler = net_graphing.MethodRecompiler(instrs, exc_blocks, localvartok)
        data = recompiler.compile_method()
        self.__was_something_changed = False
        self.__graph = None
        if data is None:
            return False
        self.set_method_data(data)
        return True

    cpdef object get_recompile_graph(self):
        """ Obtain the function graph associated with the recompile.

            Do not use this method.  It is a work in progress and does not currently work.
            Use DotNetPeFile.patch_instruction().

        Returns:
            net_graphing.FunctionGraph: The function graph associated with the current recompile.
        """
        return self.__graph

    cpdef bint begin_recompile(self):
        """ Called before calling add_instruction(), replace_instruction() and remove_instruction()

            finish_recompile() must be called once all method changes are complete.

            Do not use this method.  It is a work in progress and does not currently work.
            Use DotNetPeFile.patch_instruction().
        Returns:
            bint: True if successful, False otherwise.
        """
        if not self.has_body():
            return False
        self.__graph = net_graphing.FunctionGraph(self)
        return True

    cpdef void set_method_data(self, bytes data):
        """ Replaces the data of a method with different content.

        Args:
            data (bytes): The new method data to patch in.
        """
        if self.get_column('RVA').get_value_as_int() == 0:
            raise net_exceptions.InvalidArgumentsException()
            #TODO: add the ability to add addiitonal methods when they dont already exist.
        cdef bytes old_data = self.get_method_data()
        cdef int orig_method_size = <int>len(old_data)
        cdef int new_method_size = <int>len(data)
        cdef int difference = 0
        cdef dotnetpefile.PeFile pe = self.get_dotnetpe().get_pe()
        cdef uint64_t rva = <uint64_t>self.get_column('RVA').get_value_as_int()
        cdef uint64_t file_offset = pe.get_offset_from_rva(rva)
        cdef bytes final_data = None
        cdef int amt_padding = 0
        difference = new_method_size - orig_method_size
        while (orig_method_size % 4) != ((new_method_size + amt_padding) % 4):
            amt_padding += 1
        #This approach might leave an extra byte or two in the binary when patching methods but it also saves a ton of time when patching methods.
        #TODO Figure out a better way to handle alignment than checking after each patch.
        final_data = data + (b'\x00' * amt_padding)
        self.get_dotnetpe().patch_dpe(rva, difference + amt_padding, None, rva, final_data, file_offset + orig_method_size, False)

    cpdef bytes get_name(self):
        """ Equivalent to RowObject.get_column('Name').get_value_as_bytes().
            Mostly used for dotnetemulator purposes but can be used to replace the above.

        Returns:
            bytes: The value of the Name column for the object.
        """
        return self.get_column('Name').get_value_as_bytes()

    cpdef net_cil_disas.MethodDisassembler disassemble_method(self, bint no_save=False, bint original=False):
        """
            Obtains a MethodDisassembler object for the method.
            This method now accounts for changes in memory of the method code using
            a MD5 hash.

        Args:
            no_save (bool): If Enabled, the disassembler object will not be stored in the MethodDef for later use.
            original (bool): If enabled, the disassembler object will return for the original method's data before any manipulation.
                Best to avoid this one, going to remove it probably.

        Returns:
            net_cil_disas.MethodDisassembler: A disassembler object that can parse the method.
        """
        cdef bytes hashval
        cdef object md5 
        if original:
            return net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self, force_data=self.get_original_method_data())
            
        if self.has_body():
            if no_save:
                return net_cil_disas.MethodDisassembler(self.get_dotnetpe(), self)
            else:
                try:
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
                except Exception as e:
                    return None #Allows for encrypted methods and such.
        return None

    cpdef bytes get_original_method_data(self):
        """ Obtain the methods data based on the original copy of the exe.
        
        Returns:
            bytes: the original method's data before any manipulation
        """
        cdef uint64_t file_offset
        cdef unsigned long method_size
        if self.get_column('RVA').get_original_value() == 0:
            return None
        file_offset = self.get_dotnetpe().get_pe().get_offset_from_rva(self.get_column('RVA').get_original_value())
        method_size = net_cil_disas.get_total_method_size(self.get_dotnetpe().get_original_exe_data()[file_offset:])
        return self.get_dotnetpe().get_original_exe_data()[file_offset: file_offset + method_size]

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        """ Internal method to register parent type.
        """
        self.__parent_type = parent_type

    cpdef void _add_xref(self, int rid, int instr_offset):
        """ Internal method to register an xref during processing.
        """
        self.__xrefs.append((rid, instr_offset))

    cpdef list get_xrefs(self):
        """ Obtains a list of tuples (method_rid, instr_offset) representing xrefs of a method.
            A method xref is when call or callvirt is used on a methoddef object.

        Returns:
            list[tuple[int, int]]: A list of xrefs
        """
        return self.__xrefs

    cpdef bint is_abstract(self):
        """ Returns true if the method is abstract, false otherwise.

        Returns:
            bool: True if the method is abstract, false otherwise.
        """
        return self.get_column('Flags').get_raw_value() & net_structs.CorMethodAttr.mdAbstract != 0

    cdef void process(self):
        cdef net_processing.MetadataTableHeapObject metadata_heap
        cdef int params_list_end
        cdef int params_list_len
        cdef int params_list_start
        cdef list paramlist
        cdef net_table_objects.TableObject param_table = self.get_dotnetpe().get_metadata_table('Param')
        cdef net_table_objects.TableObject paramptr_table = self.get_dotnetpe().get_metadata_table('ParamPtr')
        cdef net_table_objects.TableObject methoddef_table = self.get_dotnetpe().get_metadata_table('MethodDef')


        # process paramslist
        if param_table is not None and self.get_column('ParamList').get_raw_value() != 0:
            if paramptr_table is None:
                params_list_len = <int>len(param_table)
                params_list_end = params_list_len + 1

                if methoddef_table.has_index(self.get_rid() + 1):
                    params_list_end = methoddef_table.get(self.get_rid() + 1).get_column('ParamList').get_raw_value()
                if not param_table.has_index(params_list_end):
                    params_list_end = params_list_len + 1
            else:
                params_list_len = <int>len(paramptr_table)
                params_list_end = params_list_len + 1
                if methoddef_table.has_index(self.get_rid() + 1):
                    params_list_end = methoddef_table.get(self.get_rid() + 1).get_column('ParamList').get_raw_value()
                if not paramptr_table.has_index(params_list_end):
                    params_list_end = params_list_len + 1
            params_list_start = self.get_column('ParamList').get_raw_value()
            paramlist = list()
            for x in range(params_list_start, params_list_end):
                if paramptr_table is None:
                    paramlist.append(param_table.get(x))
                else:
                    paramlist.append(paramptr_table.get(x).get_column('Param').get_value())
            self.get_column('ParamList').set_formatted_value(paramlist)

    cpdef list get_param_types(self):
        """ Obtain the TypeSigs for each parameter in the function.

        Returns:
            list[net_sigs.TypeSig]: A list of typesigs representing the method parameters.
        """
        return self.get_method_signature().get_parameters()

    cpdef bytes get_full_name(self):
        """ Obtain the full name of a method.

        Returns:
            bytes: A utf-8 encoded string, example Console.WriteLine or System.Object..ctor
        """
        if not self.__full_name:
            if self.__parent_type is None:
                self.__full_name = self.get_column('Name').get_value()
            else:
                self.__full_name = self.__parent_type.get_full_name() + b'.' + self.get_column('Name').get_value()
        return self.__full_name
    
    cpdef bint is_final(self):
        """  Returns True if a method is final, false otherwise.

        Returns:
            bool: True if the method is final, false otherwise.
        """
        return self.get_column('Flags').get_raw_value() & net_structs.CorMethodAttr.mdFinal != 0

    cpdef bint is_newslot(self):
        """  Returns True if a method is newslot, false otherwise.

        Returns:
            bool: True if the method is newslot, false otherwise.
        """
        return self.get_column('Flags').get_raw_value() & net_structs.CorMethodAttr.mdNewSlot != 0

    cpdef bint is_virtual(self):
        """  Returns True if a method is virtual, false otherwise.

        Returns:
            bool: True if the method is virtual, false otherwise.
        """
        return self.get_column('Flags').get_raw_value() & net_structs.CorMethodAttr.mdVirtual != 0

    cpdef bint is_hidebysig(self):
        """  Returns True if a method is hidebysig, false otherwise.

        Returns:
            bool: True if the method is hidebysig, false otherwise.
        """
        return self.get_column('Flags').get_raw_value() & net_structs.CorMethodAttr.mdHideBySig != 0

    cpdef bint is_static_method(self):
        """  Returns True if a method is static, false otherwise.

        Returns:
            bool: True if the method is static, false otherwise.
        """
        return self.get_column('Flags').get_raw_value() & net_structs.CorMethodAttr.mdStatic != 0

    cpdef net_sigs.CallingConventionSig get_method_signature(self):
        """  Obtains the method's signature object.

        Returns:
            net_sigs.MethodSig: The method's signature.
        """
        cdef bytes signature_data
        cdef net_sigs.SignatureReader sig_reader
        if self.__sig_obj is None and not self.__has_invalid_signature:
            signature_data = self.get_column('Signature').get_value()
            try:
                sig_reader = net_sigs.SignatureReader(self.get_dotnetpe(), signature_data, self)
                self.__sig_obj = sig_reader.read_signature()
                if not isinstance(self.__sig_obj, net_sigs.MethodSig):
                    raise net_exceptions.InvalidSignatureException('Sig mismatch')
                self.__has_return_value = not isinstance(
                    self.__sig_obj.get_return_type(), net_sigs.CorLibTypeSig) or self.__sig_obj.get_return_type() != net_sigs.get_CorSig_Void()
                if isinstance(self.__sig_obj.get_return_type(), net_sigs.ModifierSig):
                    if self.__sig_obj.get_return_type().get_next() == net_sigs.get_CorSig_Void():
                        self.__has_return_value = False
                self.__method_has_this = self.__sig_obj.get_calling_conv() & net_structs.CorCallingConvention.HasThis != 0
            except net_exceptions.InvalidSignatureException as e:
                self.__has_invalid_signature = True
        return self.__sig_obj

    cpdef bint is_entrypoint(self):
        """  Returns True if a method is an entrypoint, false otherwise.

        Returns:
            bool: True if the method is an entrypoint, false otherwise.
        """
        cdef MethodDef ep
        if self.get_dotnetpe().get_metadata_dir().net_header.Flags & net_structs.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0:
            return False
        ep = self.get_dotnetpe().get_entry_point()
        return ep == self

    cpdef bint is_static_constructor(self):
        """  Returns True if a method is a cctor method, false otherwise.

        Returns:
            bool: True if the method is cctor method, false otherwise.
        """
        return self.get_column('Name').get_value() == b'.cctor'

    cpdef bint is_constructor(self):
        """  Returns True if a method is a ctor method, false otherwise.

        Returns:
            bool: True if the method is ctor method, false otherwise.
        """
        return self.get_column('Name').get_value() == b'.ctor'

    def __str__(self):
        return 'MethodDef:{}='.format(self.get_rid()) + self.get_full_name().__str__()

    cpdef bytes get_method_data(self):
        """  Obtains the byte data, including headers, for the method.

        Returns:
            bytes: The bytes representing the method, including headers and trailers.
        """
        cdef uint64_t file_offset
        cdef int method_size
        if self.get_column('RVA').get_value() == 0:
            return None
        file_offset = self.get_dotnetpe().get_pe().get_offset_from_rva(self.get_column('RVA').get_value())
        method_size = net_cil_disas.get_total_method_size(self.get_dotnetpe().get_exe_data()[file_offset:])
        return self.get_dotnetpe().get_exe_data()[file_offset: file_offset + method_size]

    cpdef bint has_body(self):
        """  Returns True if a method has a body, false otherwise.

        Returns:
            bool: True if the method has a body, false otherwise.
        """
        return self.get_column('RVA').get_value() != 0

    cpdef TypeDefOrRef get_parent_type(self):
        """  Obtain the method's parent type.

        Returns:
            net_row_objects.TypeDefOrRef: The parent type for the method.  Shouldnt ever be None.
        """
        return self.__parent_type

    cpdef bint has_return_value(self):
        """  Returns True if a method has a return value, false otherwise.

        Returns:
            bool: True if the method has a return value, false otherwise.
        """
        self.get_method_signature()
        return self.__has_return_value

    cpdef bint method_has_this(self):
        """  Returns True if a method has this as a param, false otherwise.

        Returns:
            bool: True if the method has this as a param, false otherwise.
        """
        self.get_method_signature() # Make sure signature is populated
        return self.__method_has_this

    cpdef int get_amt_params(self):
        """  Obtains the amount of parameters a method has, based on its signature.

        Returns:
            int: The amount of parameters a method has, based on its signature.
        """
        return <int>len(self.get_method_signature().get_parameters())


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

    cpdef bytes get_name(self):
        return self.get_column('Name').get_value_as_bytes()

    cpdef list get_xrefs(self):
        """ Obtain a list of xrefs for a MemberRef (a list of tuples with values (method_rid, instr_offset))

        Returns:
            list[tuple[int, int]]: The xrefs for the memberref.
        """
        return self.__xrefs

    cpdef void _add_xref(self, int rid, int instr_offset):
        """ Internal method to register xrefs
        """
        self.__xrefs.append((rid, instr_offset))

    cpdef TypeDefOrRef get_parent_type(self):
        """ Obtain the memberref's parent.

        Returns:
            net_row_objects.TypeDefOrRef: The parent Type for the member.
        """
        return self.__parent_type

    cpdef void _set_parent_type(self, TypeDefOrRef parent_type):
        """ Internal method to set parent type.
        """
        self.__parent_type = parent_type

    cdef void post_process(self):
        cdef TypeDefOrRef class_obj
        cdef RowObject sig_type
        class_obj = self.get_column('Class').get_value()
        if class_obj:
            if class_obj.get_table_name() == 'TypeRef':
                self._set_parent_type(class_obj)
                class_obj._memberrefs.append(self)
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
        """ Attempt to obtain the definition of a method (useful for handling virtual methods and such.)

            Without method specs this method doesnt really have access to complete generic contexts so it could be wrong.

        Returns:
            net_row_objects.MethodDef: The resulting method implementation.
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
                    for method in sig_type.get_column('MethodList').get_formatted_value():
                        if method.get_column('Name').get_original_value() == self.get_column('Name').get_original_value():
                            if net_sigs.method_sig_compare(self.get_method_signature(), method.get_method_signature(), None, parent_type.get_sig_obj()):
                                return method
        return None


    cpdef bint is_field(self):
        """  Returns True if a member refers to a field, false otherwise.

        Returns:
            bool: True if the member refers to a field, false otherwise.
        """
        return isinstance(self.get_method_signature(), net_sigs.FieldSig)
    
    cpdef bint is_method(self):
        """  Returns True if member refers to a method, false otherwise.

        Returns:
            bool: True if the member refers to a method, false otherwise.
        """
        return isinstance(self.get_method_signature(), net_sigs.MethodSig)

    cpdef bint is_static_method(self):
        """  Returns True if a method is static, false otherwise

        Returns:
            bool: True if the method is static, false otherwise.
        """
        return not self.method_has_this()

    cpdef bint is_hidebysig(self):
        """  Returns True if a method is hidebysig, false otherwise.

            This is mostly for internal purposes since memberrefs cant really actually be HideBysig.

        Returns:
            bool: True if the method is hidebysig, false otherwise.
        """
        return True

    cpdef bytes get_full_name(self):
        """  Obtain the full name of the memberref.

        Returns:
            bytes: The full name of the MemberRef - e.x System.Type.GetType
        """
        cdef bytes parent_name
        if not self.__full_name:
            if self.__parent_type:
                parent_name = self.__parent_type.get_full_name()
                if parent_name is not None:
                    self.__full_name = parent_name + b'.' + self.get_column('Name').get_value()
                else:
                    self.__full_name = self.get_column('Name').get_value()
            else:
                self.__full_name = self.get_column('Name').get_value()
        return self.__full_name

    cpdef bint has_return_value(self):
        """  Returns True if a method has a return value, false otherwise.

        Returns:
            bool: True if the method has a return value, false otherwise.
        """
        if self.is_field():
            return False
        cdef net_sigs.TypeSig ret_type = self.get_method_signature().get_return_type()
        if isinstance(ret_type, net_sigs.ModifierSig):
            if ret_type.get_next() == net_sigs.get_CorSig_Void():
                return False
        return self.get_method_signature().get_return_type() != net_sigs.get_CorSig_Void()

    cpdef list get_param_types(self):
        """  Obtain a list of parameter type sigs from the method signature

        Returns:
            list[net_sigs.TypeSig]: A list of typesigs representing the parameter or empty list for fields.
        """
        if self.is_field():
            return list()
        return self.get_method_signature().get_parameters()

    cpdef bint method_has_this(self):
        """  Returns True if a method has this, false otherwise.

        Returns:
            bool: True if the method has this, false otherwise.
        """
        return self.get_method_signature().get_calling_conv() & net_structs.CorCallingConvention.HasThis != 0

    cpdef int get_amt_params(self):
        """  Obtains the amount of parameters based on method signature.

        Returns:
            int: the amount of parameters based on the signature.
        """
        return <int>len(self.get_param_types())

    cpdef net_sigs.CallingConventionSig get_method_signature(self):
        """  Obtains a signature object associated with the MemberRef.  In certain cases (usually field generics), this can be FieldSig instead of MethodSig.

        Returns:
            net_sigs.CallingConventionSig: The signature object for the member.
        """
        if self.__sig_obj == None:
            try:
                self.__sig_obj = net_sigs.SignatureReader(self.get_dotnetpe(), self.get_column('Signature').get_value_as_bytes()).read_signature()
            except Exception as e:
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
        owner_obj = self.get_column('Owner').get_value()
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

    cpdef list get_param_types(self):
        return self.get_method().get_param_types()

    cpdef bytes get_name(self):
        return self.get_method().get_name()

    cpdef bint has_return_value(self):
        return self.get_method().has_return_value()

    cpdef list get_xrefs(self):
        """ Obtain a list of xrefs (tuples with (method_rid, instr_offset)) for the MethodSpec

        Returns:
            list[tuple[int, int]]: A list of xrefs for the methodspec object
        """
        return self.__xrefs

    cpdef void _add_xref(self, int rid, int instr_offset):
        """ Internal method to add xrefs
        """
        self.__xrefs.append((rid, instr_offset))

    cpdef MethodDefOrRef get_method(self):
        """ Obtain the methodspecs base method.

        Returns:
            net_row_objects.MethodDefOrRef: the base method for the spec.
        """
        return self.get_column('Method').get_value()
    
    cpdef bytes get_full_name(self):
        """  Obtain the full name of the method.

        Returns:
            bytes: The full name of the method - e.x System.Type.GetType
        """
        return self.get_method().get_full_name()
    
    def __eq__(self, other):
        if not isinstance(other, MethodSpec):
            return False
        return other.get_rid() == self.get_rid()

    cpdef net_sigs.CallingConventionSig get_sig_obj(self):
        """  Obtains a signature object associated with the MethodSpec.  This will probably be a GenericInstMethodsig

        Returns:
            net_sigs.CallingConventionSig: The signature object for the methodspec.
        """
        cdef bytes signature
        cdef net_sigs.SignatureReader sig_reader
        if not self.__parsed_sig:
            signature = self.get_column('Signature').get_value()
            sig_reader = net_sigs.SignatureReader(self.get_dotnetpe(), signature)
            try:
                self.__parsed_sig = sig_reader.read_calling_convention_sig()
            except net_exceptions.InvalidSignatureException as e:
                raise e
        return self.__parsed_sig

    def __hash__(self):
        return hash(self.get_table_name() + '_' + str(self.get_rid()))


cdef class TypeSpec(TypeDefOrRef):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        TypeDefOrRef.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__has_type = False
        self.__parsed_sig = None
        self.__has_invalid_signature = False

    cdef void post_process(self):
        self.__has_type = self.get_type() is not None

    cpdef void _add_child_class(self, TypeDefOrRef to_add):
        """ Internal method to add child classes.  Specs themselves dont really have child classes right now, so this just adds to the generic type.
        """
        if not self.__has_type:
            return
        self.get_type()._add_child_class(to_add)

    cpdef TypeDefOrRef get_type(self):
        """  Obtains the generic type associated with a typespec. 

        Returns:
            net_row_objects.TypeDefOrRef: A object representing the specs generic type.
        """
        cdef net_sigs.TypeSig sig_obj
        cdef net_structs.CorElementType element_type
        cdef bytes element_type_name
        sig_obj = self.get_sig_obj()
        if isinstance(sig_obj, net_sigs.GenericInstSig):
            return sig_obj.get_generic_type().get_type()
        elif isinstance(sig_obj, net_sigs.CorLibTypeSig):
            element_type = sig_obj.get_element_type()
            element_type_name = net_utils.get_cor_type_name(element_type)
            return self.get_dotnetpe().get_typeref_by_full_name(element_type_name)
        if hasattr(sig_obj, 'get_type'):
            return sig_obj.get_type()
        #TODO: There is a possibility this will require updating as semantics of other signatures are revealed.
        return None
    
    cpdef bytes get_full_name(self):
        """  Obtain the full name of the type.

        Returns:
            bytes: The full name of the type - e.x System.Type
        """
        cdef TypeDefOrRef type_obj
        type_obj = self.get_type()
        if type_obj is None:
            #first check and see if we have a corlibtypesig, maybe we can still get the name off that. 
            if isinstance(self.get_sig_obj(), net_sigs.CorLibTypeSig):
                try:
                    return net_utils.get_cor_type_name(self.get_sig_obj().get_element_type())
                except:
                    pass
            return None
        return type_obj.get_full_name()
    
    cpdef list get_methods(self):
        """  Obtain a list of methods associated with a typespecs generic type.

        Returns:
            list[net_row_objects.MethodDef]: A list of methods associated with a typespecs generic type
        """
        if not self.__has_type:
            return None
        return self.get_type().get_methods()

    cdef void _add_method(self, MethodDefOrRef method_obj):
        """ Internal method for adding associations between types and their methods.
        """
        if not self.__has_type:
            return
        self.get_type()._add_method(method_obj)

    cpdef list get_member_refs(self):
        """  Obtains a list of memberrefs associated with a typespecs generic type

        Returns:
            list[net_row_objects.MemberRef]: a list of memberrefs associated with a typespecs type.
        """
        if not self.__has_type:
            return list()
        return self.get_type().get_member_refs()

    cpdef TypeDefOrRef get_superclass(self):
        """  Obtains a superclass for the types generic type.

        Returns:
            net_row_objects.TypeDefOrRef: the superclass for the typespecs generic type.
        """
        if not self.__has_type:
            return None
        return self.get_type().get_superclass()

    def __eq__(self, other):
        if isinstance(other, TypeSpec):
            return other.get_rid() == self.get_rid()
        else:
            return False

    cpdef net_sigs.TypeSig get_sig_obj(self):
        """  Obtains a signature object associated with the TypeSpec.  This will probably be a GenericInstSig

        Returns:
            net_sigs.TypeSig: The signature object for the typespec.
        """
        cdef net_sigs.SignatureReader sig_reader
        cdef bytes signature
        if not self.__parsed_sig and not self.__has_invalid_signature:
            signature = self.get_column('Signature').get_value()
            try:
                sig_reader = net_sigs.SignatureReader(self.get_dotnetpe(), signature)
                self.__parsed_sig = sig_reader.handle_type_sig(False)
            except net_exceptions.InvalidSignatureException as e:
                self.__has_invalid_signature = True
                return None
        return self.__parsed_sig

    def __hash__(self):
        return hash(self.get_table_name() + '_' + str(self.get_rid()))
    
cdef class StandAloneSig(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
        self.__parsed_sig = None
        self.__has_invalid_signature

    cpdef net_sigs.CallingConventionSig get_sig_obj(self):
        """  Obtains a signature object associated with the StandAloneSig.

        Returns:
            net_sigs.CallingConventionSig: The signature object for the StandAloneSig.
        """
        cdef net_sigs.SignatureReader sig_reader
        cdef bytes signature
        if not self.__parsed_sig and not self.__has_invalid_signature:
            signature = self.get_column('Signature').get_value()
            try:
                sig_reader = net_sigs.SignatureReader(self.get_dotnetpe(), signature)
                self.__parsed_sig = sig_reader.read_calling_convention_sig()
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

    cpdef TypeDef get_class(self):
        """ Obtain the Class column of a MethodImpl.

        Returns:
            net_row_objects.TypeDef: The class value for the MethodImpl.
        """
        if not self.__class:
            self.__class = self.get_column('Class').get_value()
        return self.__class
    
    cpdef MethodDefOrRef get_declaration(self):
        """ Obtain the MethodDeclaration column of a MethodImpl.

        Returns:
            net_row_objects.MethodDefOrRef: The MethodDeclaration value for the MethodImpl.
        """
        if not self.__declaration:
            self.__declaration = self.get_column('MethodDeclaration').get_value()

        return self.__declaration
    
    cpdef MethodDefOrRef get_body(self):
        """ Obtain the MethodBody column of a MethodImpl.

        Returns:
            net_row_objects.MethodDefOrRef: The MethodBody value for the MethodImpl.
        """
        if not self.__body:
            self.__body = self.get_column('MethodBody').get_value()
        return self.__body
    
cdef class MethodSemantic(RowObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, list raw_data, int rid, list sizes, dict col_types, str table_name):
        RowObject.__init__(self, dotnetpe, raw_data, rid,
                           sizes, col_types, table_name)
    
    cpdef MethodDef get_method(self):
        """ Obtain the Method column of a MethodSemantic.

        Returns:
            net_row_objects.MethodDef: The class value for the MethodSemantic.
        """
        return self.get_column('Method').get_value()
    
    cpdef RowObject get_assocciation(self):
        """ Obtain the Association column of a MethodSemantic, usually Event or Property table.

        Returns:
            net_row_objects.RowObject: The Association value for the MethodSemantic.
        """
        return self.get_column('Association').get_value()
    
    cpdef bint is_setter(self):
        """ Is the method marked as a property setter method?

        Returns:
            bool: True if the method is a property setter, false otherwise.
        """
        return self.get_column('Semantics').get_raw_value() & net_structs.CorMethodSemanticsAttr.msSetter != 0
    
    cpdef bint is_getter(self):
        """ Is the method marked as a property getter method?

        Returns:
            bool: True if the method is a property getter, false otherwise.
        """
        return self.get_column('Semantics').get_raw_value() & net_structs.CorMethodSemanticsAttr.msGetter != 0

    cpdef bint is_other(self):
        """ Is the method marked as a property or event other method?

        Returns:
            bool: True if the method is a property or event other method, false otherwise.
        """
        return self.get_column('Semantics').get_raw_value() & net_structs.CorMethodSemanticsAttr.msOther != 0
    
    cpdef bint is_add_on(self):
        """ Is the method marked as a event add method?

        Returns:
            bool: True if the method is a event add, false otherwise.
        """
        return self.get_column('Semantics').get_raw_value() & net_structs.CorMethodSemanticsAttr.msAddOn != 0
    
    cpdef bint is_remove_on(self):
        """ Is the method marked as a event remove method?

        Returns:
            bool: True if the method is a event remove method, false otherwise.
        """
        return self.get_column('Semantics').get_raw_value() & net_structs.CorMethodSemanticsAttr.msRemoveOn != 0
    
    cpdef bint is_fire(self):
        """ Is the method marked as a event fire method?

        Returns:
            bool: True if the method is a event fire, false otherwise.
        """
        return self.get_column('Semantics').get_raw_value() & net_structs.CorMethodSemanticsAttr.msFire != 0
    
    
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
        cdef net_table_objects.TableObject property_table = self.get_dotnetpe().get_metadata_table('Property')
        cdef net_table_objects.PropertyMapTable propertymap_table = self.get_dotnetpe().get_metadata_table('PropertyMap')
        cdef net_table_objects.TableObject propertyptr_table = self.get_dotnetpe().get_metadata_table('PropertyPtr')
        if propertyptr_table is None:
            property_list_len = <int>len(property_table)
            property_list_end = property_list_len
            if propertymap_table.has_index(self.get_rid() + 1):
                property_list_end = propertymap_table.get(self.get_rid() + 1).get_column('PropertyList').get_raw_value()
            if property_list_end > property_list_len:
                property_list_end = property_list_len
        else:
            property_list_len = <int>len(propertyptr_table) + 1
            property_list_end = property_list_len
            if propertymap_table.has_index(self.get_rid() + 1):
                property_list_end = propertymap_table.get(self.get_rid() + 1).get_column('PropertyList').get_raw_value()
            if not property_table.has_index(property_list_end):
                property_list_end = property_list_len
        
        property_list_start = self.get_column('PropertyList').get_raw_value()
        propertylist = list()
        for x in range(property_list_start, property_list_end):
            if propertyptr_table is None:
                propertylist.append(property_table.get(x))
            else:
                propertylist.append(propertyptr_table.get(x).get_column('Property').get_value())
        self.get_column('PropertyList').set_formatted_value(propertylist)

    cpdef TypeDef get_parent(self):
        """ Obtain the parent type for the property mapping

        Returns:
            net_row_objects.TypeDef: The parent type for the property mapping.
        """
        return self.get_column('Parent').get_value()
    
    cpdef list get_properties(self):
        """ Obtain a list of all properties in the mapping.

        Returns:
            list[net_row_objects.RowObject]: A list of all properties associated with the mapping.
        """
        return self.get_column('PropertyList').get_formatted_value()

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