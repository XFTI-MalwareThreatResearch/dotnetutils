#cython: language_level=3
from dotnetutils cimport net_tokens
from dotnetutils cimport dotnetpefile, net_structs, net_row_objects, net_cil_disas
from dotnetutils import net_exceptions

from logging import getLogger

logger = getLogger(__name__)


cdef get_single_table_index_size(int table_id, list row_amt_list):
    row_amt = 0
    for tbl_id, count in row_amt_list:
        if tbl_id == table_id:
            row_amt = count
            break
    if row_amt == 0:
        return 2
    if row_amt > 0xFFFF:
        return 4
    return 2


cdef get_multiple_table_index_size(list potential_table_ids, list row_amt_list, int bits_used):
    max_value = 0xFFFF >> bits_used
    for ident in potential_table_ids:
        row_amt = 0
        for tbl_id, count in row_amt_list:
            if tbl_id == ident:
                row_amt = count
                break
        if row_amt != 0:
            if row_amt >= max_value:
                return 4
    return 2

cdef module_col_types = {
    'Generation': net_tokens.get_TwoByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'Mvid': net_tokens.get_GuidStream(),
    'EncId': net_tokens.get_GuidStream(),
    'EncBaseId': net_tokens.get_GuidStream()
}

cdef typeref_col_types = {
    'ResolutionScope': net_tokens.get_ResolutionScope(),
    'Typename': net_tokens.get_StringsStream(),
    'TypeNamespace': net_tokens.get_StringsStream()
}

cdef typedef_col_types = {
    'Flags': net_tokens.get_FourByteValue(),
    'TypeName': net_tokens.get_StringsStream(),
    'TypeNamespace': net_tokens.get_StringsStream(),
    'Extends': net_tokens.get_TypeDefOrRef(),
    'FieldList': net_tokens.SingleTableCodedToken('Field'),
    'MethodList': net_tokens.SingleTableCodedToken('MethodDef')
}

cdef fieldptr_col_types = {
    'Field': net_tokens.SingleTableCodedToken('Field')
}

cdef field_col_types = {
    'Flags': net_tokens.get_TwoByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'Signature': net_tokens.get_BlobStream()
}

cdef methodptr_col_types = {
    'Method': net_tokens.SingleTableCodedToken('MethodDef')
}

cdef methoddef_col_types = {
    'RVA': net_tokens.get_FourByteValue(),
    'ImplFlags': net_tokens.get_TwoByteValue(),
    'Flags': net_tokens.get_TwoByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'Signature': net_tokens.get_BlobStream(),
    'ParamList': net_tokens.SingleTableCodedToken('Param')
}

cdef paramptr_col_types = {
    'Param': net_tokens.SingleTableCodedToken('Param')
}

cdef param_col_types = {
    'Flags': net_tokens.get_TwoByteValue(),
    'Sequence': net_tokens.get_TwoByteValue(),
    'Name': net_tokens.get_StringsStream()
}

cdef interfaceimpl_col_types = {
    'Class': net_tokens.SingleTableCodedToken('TypeDef'),
    'Interface': net_tokens.get_TypeDefOrRef()
}

cdef memberref_col_types = {
    'Class': net_tokens.get_MemberRefParent(),
    'Name': net_tokens.get_StringsStream(),
    'Signature': net_tokens.get_BlobStream()
}

cdef constant_col_types = {
    'Type': net_tokens.get_OneByteValue(),
    'Padding': net_tokens.get_OneByteValue(),
    'Parent': net_tokens.get_HasConstant(),
    'Value': net_tokens.get_BlobStream()
}

cdef customattribute_col_types = {
    'Parent': net_tokens.get_HasCustomAttribute(),
    'Type': net_tokens.get_CustomAttributeType(),
    'Value': net_tokens.get_BlobStream()
}

cdef fieldmarshal_col_types = {
    'Parent': net_tokens.get_HasFieldMarshal(),
    'NativeType': net_tokens.get_BlobStream()
}

cdef declsecurity_col_types = {
    'Action': net_tokens.get_TwoByteValue(),
    'Parent': net_tokens.get_HasDeclSecurity(),
    'PermissionSet': net_tokens.get_BlobStream()
}

cdef classlayout_col_types = {
    'PackingSize': net_tokens.get_TwoByteValue(),
    'ClassSize': net_tokens.get_FourByteValue(),
    'Parent': net_tokens.SingleTableCodedToken('TypeDef')
}

cdef fieldlayout_col_types = {
    'Offset': net_tokens.get_FourByteValue(),
    'Field': net_tokens.SingleTableCodedToken('Field')
}

cdef standalonesig_col_types = {
    'Signature': net_tokens.get_BlobStream()
}

cdef eventmap_col_types = {
    'Parent': net_tokens.SingleTableCodedToken('TypeDef'),
    'EventList': net_tokens.SingleTableCodedToken('Event')
}

cdef eventptr_col_types = {
    'Event': net_tokens.SingleTableCodedToken('Event')
}

cdef event_col_types = {
    'EventFlags': net_tokens.get_TwoByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'EventType': net_tokens.get_TypeDefOrRef()
}

cdef propertymap_col_types = {
    'Parent': net_tokens.SingleTableCodedToken('TypeDef'),
    'PropertyList': net_tokens.SingleTableCodedToken('Property')
}

cdef propertyptr_col_types = {
    'Property': net_tokens.SingleTableCodedToken('Property')
}

cdef property_col_types = {
    'Flags': net_tokens.get_TwoByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'Type': net_tokens.get_BlobStream()
}

cdef methodsemantics_col_types = {
    'Semantics': net_tokens.get_TwoByteValue(),
    'Method': net_tokens.SingleTableCodedToken('MethodDef'),
    'Association': net_tokens.get_HasSemantic()
}

cdef methodimpl_col_types = {
    'Class': net_tokens.SingleTableCodedToken('TypeDef'),
    'MethodBody': net_tokens.get_MethodDefOrRef(),
    'MethodDeclaration': net_tokens.get_MethodDefOrRef()
}

cdef moduleref_col_types = {
    'Name': net_tokens.get_StringsStream()
}

cdef typespec_col_types = {
    'Signature': net_tokens.get_BlobStream()
}

cdef implmap_col_types = {
    'MappingFlags': net_tokens.get_TwoByteValue(),
    'MemberForwarded': net_tokens.get_MemberForwarded(),
    'ImportName': net_tokens.get_StringsStream(),
    'ImportScope': net_tokens.SingleTableCodedToken('ModuleRef')
}

cdef fieldrva_col_types = {
    'RVA': net_tokens.get_FourByteValue(),
    'Field': net_tokens.SingleTableCodedToken('Field')
}

cdef enclog_col_types = {
    'Token': net_tokens.get_FourByteValue(),
    'FuncCode': net_tokens.get_FourByteValue()
}

cdef encmap_col_types = {
    'Token': net_tokens.get_FourByteValue()
}

cdef assembly_col_types = {
    'HashAlgId': net_tokens.get_FourByteValue(),
    'MajorVersion': net_tokens.get_TwoByteValue(),
    'MinorVersion': net_tokens.get_TwoByteValue(),
    'BuildNumber': net_tokens.get_TwoByteValue(),
    'RevisionNumber': net_tokens.get_TwoByteValue(),
    'Flags': net_tokens.get_FourByteValue(),
    'PublicKey': net_tokens.get_BlobStream(),
    'Name': net_tokens.get_StringsStream(),
    'Culture': net_tokens.get_StringsStream()
}

cdef assemblyprocessor_col_types = {
    'Processor': net_tokens.get_FourByteValue()
}

cdef assemblyos_col_types = {
    'OSPlatformId': net_tokens.get_FourByteValue(),
    'OSMajorVersion': net_tokens.get_FourByteValue(),
    'OSMinorVersion': net_tokens.get_FourByteValue()
}

cdef assemblyref_col_types = {
    'MajorVersion': net_tokens.get_TwoByteValue(),
    'MinorVersion': net_tokens.get_TwoByteValue(),
    'BuildNumber': net_tokens.get_TwoByteValue(),
    'RevisionNumber': net_tokens.get_TwoByteValue(),
    'Flags': net_tokens.get_FourByteValue(),
    'PublicKeyOrToken': net_tokens.get_BlobStream(),
    'Name': net_tokens.get_StringsStream(),
    'Culture': net_tokens.get_StringsStream(),
    'HashValue': net_tokens.get_BlobStream()
}

cdef assemblyrefprocessor_col_types = {
    'Processor': net_tokens.get_FourByteValue(),
    'AssemblyRef': net_tokens.SingleTableCodedToken('AssemblyRef')
}

cdef assemblyrefos_col_types = {
    'OSPlatformId': net_tokens.get_FourByteValue(),
    'OSMajorVersion': net_tokens.get_FourByteValue(),
    'OSMinorVersion': net_tokens.get_FourByteValue(),
    'AssemblyRef': net_tokens.SingleTableCodedToken('AssemblyRef')
}

cdef file_col_types = {
    'Flags': net_tokens.get_FourByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'HashValue': net_tokens.get_BlobStream()
}

cdef exportedtype_col_types = {
    'Flags': net_tokens.get_FourByteValue(),
    'TypeDefId': net_tokens.get_FourByteValue(),
    'TypeName': net_tokens.get_StringsStream(),
    'TypeNameSpace': net_tokens.get_StringsStream(),
    'Implementation': net_tokens.get_Implementation()
}

cdef manifestresource_col_types = {
    'Offset': net_tokens.get_FourByteValue(),
    'Flags': net_tokens.get_FourByteValue(),
    'Name': net_tokens.get_StringsStream(),
    'Implementation': net_tokens.get_Implementation()
}

cdef nestedclass_col_types = {
    'NestedClass': net_tokens.SingleTableCodedToken('TypeDef'),
    'EnclosingClass': net_tokens.SingleTableCodedToken('TypeDef')
}

cdef genericparam_col_types = {
    'Number': net_tokens.get_TwoByteValue(),
    'Flags': net_tokens.get_TwoByteValue(),
    'Owner': net_tokens.get_TypeOrMethodDef(),
    'Name': net_tokens.get_StringsStream()
}

cdef methodspec_col_types = {
    'Method': net_tokens.get_MethodDefOrRef(),
    'Signature': net_tokens.get_BlobStream()
}

cdef genericparamconstraint_col_types = {
    'Owner': net_tokens.SingleTableCodedToken('GenericParam'),
    'Constraint': net_tokens.get_TypeDefOrRef()
}

cdef NET_METADATA_TABLE_HANDLERS = {
    0: ('Module', module_col_types),
    1: ('TypeRef', typeref_col_types),
    2: ('TypeDef', typedef_col_types),
    3: ('FieldPtr', fieldptr_col_types),
    4: ('Field', field_col_types),
    5: ('MethodPtr', methodptr_col_types),
    6: ('MethodDef', methoddef_col_types),
    7: ('ParamPtr', paramptr_col_types),
    8: ('Param', param_col_types),
    9: ('InterfaceImpl', interfaceimpl_col_types),
    10: ('MemberRef', memberref_col_types),
    11: ('Constant', constant_col_types),
    12: ('CustomAttribute', customattribute_col_types),
    13: ('FieldMarshal', fieldmarshal_col_types),
    14: ('DeclSecurity', declsecurity_col_types),
    15: ('ClassLayout', classlayout_col_types),
    16: ('FieldLayout', fieldlayout_col_types),
    17: ('StandAloneSig', standalonesig_col_types),
    18: ('EventMap', eventmap_col_types),
    19: ('EventPtr', eventptr_col_types),
    20: ('Event', event_col_types),
    21: ('PropertyMap', propertymap_col_types),
    22: ('PropertyPtr', propertyptr_col_types),
    23: ('Property', property_col_types),
    24: ('MethodSemantics', methodsemantics_col_types),
    25: ('MethodImpl', methodimpl_col_types),
    26: ('ModuleRef', moduleref_col_types),
    27: ('TypeSpec', typespec_col_types),
    28: ('ImplMap', implmap_col_types),
    29: ('FieldRVA', fieldrva_col_types),
    30: ('EncLog', enclog_col_types),
    31: ('EncMap', encmap_col_types),
    32: ('Assembly', assembly_col_types),
    33: ('AssemblyProcessor', assemblyprocessor_col_types),
    34: ('AssemblyOS', assemblyos_col_types),
    35: ('AssemblyRef', assemblyref_col_types),
    36: ('AssemblyRefProcessor', assemblyrefprocessor_col_types),
    37: ('AssemblyRefOS', assemblyrefos_col_types),
    38: ('File', file_col_types),
    39: ('ExportedType', exportedtype_col_types),
    40: ('ManifestResource', manifestresource_col_types),
    41: ('NestedClass', nestedclass_col_types),
    42: ('GenericParam', genericparam_col_types),
    43: ('MethodSpec', methodspec_col_types),
    44: ('GenericParamConstraint', genericparamconstraint_col_types)
}


cdef class TableObject:

    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        self.rows = rows
        self.name = name
        self.tid = tid
        self.dotnetpe = dotnetpe

    cpdef net_row_objects.RowObject get(self, int index):
        """
        Obtain an item by RID in this table.
        RIDs are basically indexes but 1 based.
        """
        if (index - 1) < len(self.rows):
            return self.rows[index - 1]
        else:
            return None  # again prevent errors from corrupted tables.

    cpdef bint has_index(self, int index):
        """
        Check if the table has RID index
        """
        cdef int actual_index
        actual_index = index - 1
        if actual_index < 0:
            return False
        if actual_index < len(self.rows):
            return True
        return False

    def __len__(self):
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)
    
    def __getitem__(self, items):
        if isinstance(items, slice):
            start = items.start - 1
            end = items.stop - 1
            return self.rows[start:end]
        elif isinstance(items, int):
            return self.rows[items - 1]
        else:
            raise net_exceptions.InvalidArgumentsException()
        
    cdef void process(self):
        cdef net_row_objects.RowObject item
        for item in self.rows:
            item.process()
        for item in self.rows:
            item.post_process()
        self.post_process()

    cdef void post_process(self):
        """
        Used in case any post processing on a table needs to be done.
        """
        pass

    cpdef bytes to_bytes(self):
        cdef net_row_objects.RowObject item
        cdef bytes result
        result = b''
        for item in self.rows:
            result += item.to_bytes()
        return result


cdef class TypeDefTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef net_row_objects.TypeDef get_type_by_full_name(self, bytes full_name):
        """
        Obtain a TypeDef by its full name.
        """
        cdef net_row_objects.TypeDef item
        for item in self.rows:
            if full_name == item.get_full_name():
                return item
        return None

    cpdef list get_types_by_name(self, bytes name):
        """
        Obtain a list of TypeDefs with name 'name'
        """
        cdef list results
        cdef net_row_objects.TypeDef item
        results = list()
        for item in self.rows:
            if name == item['TypeName'].get_value():
                results.append(item)
        return results


cdef class ClassLayoutTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef net_row_objects.RowObject get_layout_by_parent(self, int parent):
        """
        Obtain a classlayout object that has Parent 'parent'
        """
        cdef net_row_objects.RowObject item
        for item in self.rows:
            if parent == item['Parent'].get_raw_value():
                return item
        return None


cdef class MethodDefTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef list get_methods_by_name(self, bytes name):
        """
        Obtain a list of MethodDef objects with name 'name'
        """
        cdef list result
        cdef net_row_objects.MethodDef item
        result = list()
        for item in self.rows:
            if item['Name'].get_value() == name:
                result.append(item)
        return result

    cdef void post_process(self):
        #setup all method and field references here.
        cdef net_row_objects.MethodDef method_obj
        cdef net_cil_disas.MethodDisassembler disasm_obj
        cdef net_cil_disas.Instruction instr
        cdef int x
        cdef str instr_name
        cdef net_row_objects.RowObject instr_arg
        for method_obj in self:
            if method_obj.has_body():
                try:
                    disasm_obj = method_obj.disassemble_method(original=True, no_save=True) # Dont save these disasm objects, probably not worth the memory.
                except Exception as e:
                    logger.warn('Error processing method {}.  Its possible the method is encrypted.'.format(hex(method_obj.get_token())))
                    disasm_obj = None
                if disasm_obj != None:
                    for x in range(len(disasm_obj)):
                        instr = disasm_obj[x]
                        instr_name = instr.get_name()
                        if instr_name == 'call' or instr_name == 'callvirt':
                            #handle method references here.
                            instr_arg = instr.get_argument()
                            if instr_arg != None:
                                instr_arg._add_xref(method_obj.get_rid(), x)
                        elif instr_name == 'stsfld' or instr_name == 'ldsfld' or instr_name == 'ldfld' or instr_name == 'stfld':
                            instr_arg = instr.get_argument()
                            if instr_arg != None:
                                instr_arg._add_xref(method_obj.get_rid(), x)


cdef class FieldRVATable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef net_row_objects.RowObject get_by_field_rid(self, int field_rid):
        """
        Obtain a FieldRVA object that matches field 'field_rid'
        """
        cdef net_row_objects.RowObject item
        for item in self.rows:
            if item['Field'].get_raw_value() == field_rid:
                return item
        return None


cdef class TypeRefTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef net_row_objects.TypeRef get_type_by_full_name(self, bytes name):
        """
        Obtain a TypeRef by its full name.
        """
        cdef net_row_objects.TypeRef item
        for item in self.rows:
            if item.get_full_name() == name:
                return item
        return None

cdef class MethodImplTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)
        self.__method_dict = dict()

    cdef void post_process(self):
        cdef net_row_objects.MethodImpl item
        cdef net_row_objects.TypeDef class_obj
        for item in self:
            class_obj = item.get_class()
            if class_obj not in self.__method_dict:
                self.__method_dict[class_obj] = dict()
            self.__method_dict[class_obj][item.get_declaration()] = item.get_body()

    cpdef bint is_method_in_table(self, net_row_objects.RowObject method_obj):
        """
        Check if a Method exists somewhere within the MethodImpl table.
        """
        for item in self:
            if item.get_body() == method_obj:
                return True
            if item.get_declaration() == method_obj:
                return True
        return False
    
    cpdef net_row_objects.MethodDef get_method_definition(self, net_row_objects.RowObject method_obj, net_row_objects.TypeDef class_obj):
        """
        Obtain the definition of a method 'method_obj' if it exists in the table.
        """
        cdef dict class_dict
        if class_obj not in self.__method_dict:
            return None

        class_dict = self.__method_dict[class_obj]
        if method_obj not in class_dict:
            return None
        return class_dict[method_obj]

    
cdef class MethodSemanticsTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef list get_semantics_for_item(self, net_row_objects.RowObject item):
        """
        Obtain the semantics for a property or event 'item'.
        """
        cdef list result
        cdef net_row_objects.MethodSemantic elem
        result = list()
        for elem in self:
            if elem['Association'].get_value() == item:
                result.append(elem)

        return result
    
    cpdef bint is_method_in_table(self, net_row_objects.RowObject method):
        """
        Check if a method exists within the MethodSemantics table.
        """
        cdef net_row_objects.MethodSemantic elem
        for elem in self:
            if elem['Method'].get_value() == method:
                return True
        return False
    
cdef class PropertyMapTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef list get_properties_for_parent(self, net_row_objects.RowObject parent):
        """
        Obtain a list of properties associated with parent
        """
        cdef net_row_objects.PropertyMap item
        for item in self:
            if item.get_parent() == parent:
                return item.get_properties()
            
        return list()
    
    cpdef net_row_objects.RowObject get_parent_for_property(self, net_row_objects.RowObject prop):
        """
        Obtain a parent from a property.
        """
        cdef net_row_objects.PropertyMap item
        for item in self:
            if prop in item.get_properties():
                return item.get_parent()
            
        return None

cdef class MemberRefTable(TableObject):
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, str name, list rows, int tid):
        TableObject.__init__(self, dotnetpe, name, rows, tid)

    cpdef net_row_objects.MemberRef get_ref_by_name(self, bytes name):
        """
        Obtain a MemberRef by its name.
        """
        cdef net_row_objects.MemberRef item
        for item in self:
            if item['Name'].get_value() == name:
                return item
        return None

NET_METADATA_TABLE_TYPES = {
    'Module': TableObject,
    'TypeRef': TypeRefTable,
    'TypeDef': TypeDefTable,
    'FieldPtr': TableObject,
    'Field': TableObject,
    'MethodPtr': TableObject,
    'MethodDef': MethodDefTable,
    'ParamPtr': TableObject,
    'Param': TableObject,
    'InterfaceImpl': TableObject,
    'MemberRef': MemberRefTable,
    'Constant': TableObject,
    'CustomAttribute': TableObject,
    'FieldMarshal': TableObject,
    'DeclSecurity': TableObject,
    'ClassLayout': ClassLayoutTable,
    'FieldLayout': TableObject,
    'StandAloneSig': TableObject,
    'EventMap': TableObject,
    'EventPtr': TableObject,
    'Event': TableObject,
    'PropertyMap': PropertyMapTable,
    'PropertyPtr': TableObject,
    'Property': TableObject,
    'MethodSemantics': MethodSemanticsTable,
    'MethodImpl': MethodImplTable,
    'ModuleRef': TableObject,
    'TypeSpec': TableObject,
    'ImplMap': TableObject,
    'FieldRVA': FieldRVATable,
    'EncLog': TableObject,
    'EncMap': TableObject,
    'Assembly': TableObject,
    'AssemblyProcessor': TableObject,
    'AssemblyOS': TableObject,
    'AssemblyRef': TableObject,
    'AssemblyRefProcessor': TableObject,
    'AssemblyRefOS': TableObject,
    'File': TableObject,
    'ExportedType': TableObject,
    'ManifestResource': TableObject,
    'NestedClass': TableObject,
    'GenericParam': TableObject,
    'MethodSpec': TableObject,
    'GenericParamConstraint': TableObject
}


def get_table_name_from_id(identifier):
    return NET_METADATA_TABLE_HANDLERS[identifier][0]


def get_table_id_from_name(name):
    for table_id in NET_METADATA_TABLE_HANDLERS:
        if NET_METADATA_TABLE_HANDLERS[table_id][0] == name:
            return table_id
    return -1


cdef class MetadataTableHeader:
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, bytes file_data, int offset):
        self.start_offset = offset
        self.reserved = 0
        self.majorversion = 0
        self.minorversion = 0
        self.heapoffsetsizes_orig = 0
        self.heapoffsetsizes_curr = 0
        self.reserved2 = 1
        self.valid = 0
        self.__sorted = 0
        self.table_amt_rows = list()  # we need to preserve order here.
        self.end_offset = 0
        self.dotnetpe = dotnetpe
        self.parse_table_header(file_data)

    cdef void parse_table_header(self, bytes file_data):
        cdef int current_offset
        cdef int num_tables_found
        current_offset = self.start_offset
        self.reserved = int.from_bytes(file_data[current_offset:current_offset + 4], 'little')
        current_offset += 4
        self.majorversion = file_data[current_offset]
        current_offset += 1
        self.minorversion = file_data[current_offset]
        current_offset += 1
        self.heapoffsetsizes_orig = file_data[current_offset]
        self.heapoffsetsizes_curr = self.heapoffsetsizes_orig
        current_offset += 1
        self.reserved2 = file_data[current_offset]
        current_offset += 1
        self.valid = int.from_bytes(file_data[current_offset: current_offset + 8], 'little')
        current_offset += 8
        self.__sorted = int.from_bytes(file_data[current_offset:current_offset + 8], 'little')
        current_offset += 8
        num_tables_found = 0
        for key in NET_METADATA_TABLE_HANDLERS:
            if ((self.valid >> key) & 1) != 0:
                rows_offset = current_offset + (4 * num_tables_found)
                num_tables_found += 1
                self.table_amt_rows.append((key, int.from_bytes(file_data[rows_offset:rows_offset + 4], 'little')))
        self.end_offset = current_offset + (4 * num_tables_found)
        if self.heapoffsetsizes_orig & 0x40 != 0:
            self.end_offset += 4 #if this is the case, there is 4 bytes of extra data to handle.  Doesnt seem to have any meaning.

    cpdef bytes to_bytes(self):
        # So assuming we are only currently supporting adding to the Strings stream, we can use all the old row counts.
        cdef bytes result
        result = b''
        result += int.to_bytes(self.reserved, 4, 'little')
        result += bytes([self.majorversion, self.minorversion, self.heapoffsetsizes_curr, self.reserved2])
        result += int.to_bytes(self.valid, 8, 'little')
        result += int.to_bytes(self.__sorted, 8, 'little')
        for table_id, num_rows in self.table_amt_rows:
            result += int.to_bytes(num_rows, 4, 'little')
        return result

    cpdef void set_heap_offset_size(self, net_structs.CorHeapBitmask bitmask, int new_size):
        if new_size != 2 and new_size != 4:
            raise net_exceptions.InvalidArgumentsException()

        if self.get_heap_offset_size(bitmask) == new_size:
            return

        if new_size == 2:
            self.heapoffsetsizes_curr = self.heapoffsetsizes_curr ^ bitmask
        else:
            self.heapoffsetsizes_curr = self.heapoffsetsizes_curr | bitmask

    cpdef str get_heap_name_from_bitmask(self, net_structs.CorHeapBitmask bitmask):
        if bitmask == net_structs.CorHeapBitmask.BITMASK_STRINGS:
            return '#Strings'
        elif bitmask == net_structs.CorHeapBitmask.BITMASK_BLOB:
            return '#Blob'
        elif bitmask == net_structs.CorHeapBitmask.BITMASK_GUID:
            return '#GUID'
        return None

    cpdef int get_heap_offset_size(self, net_structs.CorHeapBitmask bitmask):
        if (self.heapoffsetsizes_curr & bitmask) != 0:
            return 4
        return 2


cdef class MetadataHeap:
    def __init__(self, dotnetpefile.DotNetPeFile dotnetpe, int offset, MetadataTableHeader table_header):
        self.table_header = table_header
        self.table_objects = dict()
        self.dotnetpe = dotnetpe
        self.start_offset = offset
        self.end_offset = 0

    cpdef int get_start_offset(self):
        return self.start_offset

    cdef MetadataTableHeader get_table_header(self):
        return self.table_header

    cdef void parse_tables(self, bytes file_data):
        cdef unsigned long tables_curr_offset
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
        tables_curr_offset = self.table_header.end_offset
        for table_id, table_amt_rows in self.table_header.table_amt_rows:
            if table_id not in NET_METADATA_TABLE_HANDLERS:
                raise net_exceptions.FeatureNotImplementedException()
            tbl_name, col_type_handler = NET_METADATA_TABLE_HANDLERS[table_id]
            obj_rows = list()
            fill_sizes = True
            sizes = list()  # we only need to fill sizes once since its the same for every row.
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
                            size_of_value = self.table_header.get_heap_offset_size(bitmask)
                        else:
                            if len(field_type.get_token_types()) == 1:
                                size_of_value = get_single_table_index_size(table_id, self.table_header.table_amt_rows)
                            else:
                                table_ids = list()
                                for table_name in field_type.get_token_types():
                                    if table_name == '':
                                        continue

                                    identifier = get_table_id_from_name(table_name)
                                    if identifier == -1:
                                        raise net_exceptions.FeatureNotImplementedException()

                                    table_ids.append(identifier)
                                
                                size_of_value = get_multiple_table_index_size(table_ids,
                                                                              self.table_header.table_amt_rows,
                                                                              field_type.get_bits())
                    
                    field_value = int.from_bytes(file_data[tables_curr_offset:tables_curr_offset + size_of_value], 'little', signed=False)
                    raw_row.append(field_value)
                    
                    tables_curr_offset += size_of_value

                    if fill_sizes:
                        sizes.append(size_of_value)
                raw_row.append(row_offset)
                rid = x + 1
                obj_rows.append(net_row_objects.get_rowobject_for_table(tbl_name)(self.dotnetpe, raw_row, rid, sizes,
                                                                                 col_type_handler, tbl_name))
            self.table_objects[tbl_name] = NET_METADATA_TABLE_TYPES[tbl_name](self.dotnetpe, tbl_name, obj_rows, table_id)
        self.end_offset = tables_curr_offset

    cdef void process_tables(self):
        cdef TableObject table_obj
        for table_obj in self.table_objects.values():
            table_obj.process()

    cpdef bint has_table(self, str table_name):
        return table_name in self.table_objects.keys()

    cpdef TableObject obtain_table(self, str table_name):
        if self.has_table(table_name):
            return self.table_objects[table_name]
        return None

    cpdef TableObject get_item(self, index):
        cdef TableObject table
        if isinstance(index, int):
            for table in self.table_objects.values():
                if table.tid == index:
                    return table
        elif isinstance(index, str):
            return self.obtain_table(index)
        return None

    def __getitem__(self, item):
        return self.get_item(item)

    cpdef list present_tables(self):
        return self.table_objects.keys()

    cpdef bytes to_bytes(self):
        cdef bytes result
        cdef int table_id
        cdef int amt_rows
        cdef str table_name
        result = self.table_header.to_bytes()
        for table_id, amt_rows in self.table_header.table_amt_rows:
            table_name, _ = NET_METADATA_TABLE_HANDLERS[table_id]
            result += self.obtain_table(table_name).to_bytes()
        return result
    
    cpdef dict get_tables(self):
        return self.table_objects

    def __iter__(self):
        return iter(self.table_objects.values())
