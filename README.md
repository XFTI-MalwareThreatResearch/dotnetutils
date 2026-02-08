# dotnetutils

DotNetUtils is a library for parsing, manipulating and emulating .NET pe files.  Dotnetutils was primarily built with malicious .NET pe files in mind, although it can be used to manipulate any .NET PE file.  Dotnetutils can parse all data from the .NET metadata structures, including the metadata table, user strings and others.  Additionally, dotnetutils can emulate most .NET CIL instructions, with the emulator specifically being tested on popular obfuscators such as confuserex, eazfuscator and dotnetreactor.  The emulator is also written in Cython for speed.  In addition to emulating and parsing .NET PE files, dotnetutils can patch various components of .NET files, including methods and the various metadata heaps.  DotNetUtils can be used to change method names, patch method code, insert various strings and remove various items from the metadata heaps.

## Installation

DotNetUtils can be installed using python -m pip install ./

## Usage

### Initializing a DotNetPeFile object

The primary object used to manipulate dotnet files by dotnetutils is the dotnetpefile.DotNetPeFile object.  

The dotnetutils.DotNetPeFile object can be created using one of the following methods:

    from dotnetutils import dotnetpefile

    dotnet = dotnetpefile.try_get_dotnetpe(pe_data=<byte data>, file_path=<pe file path>)
    #This method will return None if theres an issue creating the DotNetPeFile object.

    dotnet = dotnetpefile.DotNetPeFile(pe_data=<byte data>, file_path=<pe file path>)
    #This method raises Exceptions if theres an issue creating the DotNetPeFile object.

The DotNetPeFile object contains all of the base methods that may be needed to manipulate the PE file.

### Parsing and manipulating metadata tables.

For a good refernce on the .NET metadata tables, please see this: https://www.ntcore.com/files/dotnetformat.htm

Metadata tables can be accessed using dotnetpefile.DotNetPeFile.get_metadata_table().  get_metadata_table() returns a net_table_objects.TableObject class.

    table_object = dotnet.get_metadata_table('MethodDef') #Grab the MethodDef table, containing all method definitions.

Rows in a metadata table are represented by net_row_objects.RowObject.  Rows can be accessed through any of the following methods:
    #Because RIDs default to 1, any indexing of TableObjects must also begin at 1.
    for x in range(1, len(table_object) + 1):
        row_obj = table_object.get(x)

    for row_obj in table_object:
        pass

Row objects contain information about a specific row in a metadata table.  In order to obtain the value of a specific member of the row, get_column() can be used.  net_row_objects.ColumnValue is used to represent the various items stored within a metadata table row entry.

    col_obj = row_obj.get_column('Name') #For if we want the name of our method

    col_obj = row_obj['Name']

Now that the column object is obtained, we can manipulate or obtain its value.

    current_name = col_obj.get_value() #get_value() can be used to obtain the value of any metadata row.

To change the value of a column, including accounting for patching, the following can be done:
    
    col_val.change_value(b'NewMethodName') #This automatically updates the binary to change the specific method object's name.

    col_val.set_raw_value(new_index) # Set the column value by raw index.  Call reconstruct_executable() after using set_raw_value() for changes to reflect.
    new_exe = dotnet.reconstruct_executable() #For manipulations using change_value(), reconstruct executable can be called.  
    #Calling reconstruct_executable() ensures that any pending changes are placed into the resulting executable.  It will also update the internal data for the DotNetPeFile object.

Various metadata tables have their own specialized TableObjects and RowObjects, which contain helper methods that may be used to note relationships between the various items throughout the metadata tables.  For instance:

    parent_type = row_obj.get_parent_type() #MethodDef objects have a method get_parent_type(), which returns the TypeDef that defines the method.

Refer to the docs for more information about these methods.


### Manipulating various metadata heaps

DotNetUtils is capable of parsing and manipulating other heaps besides #~ as well.  For instance, one may obtain the string heap using the following:

    #Of note: ColumnValue.get_value() handles obtaining strings internally.
    string_heap = dotnet.get_heap('#Strings')

    #Obtain all the items in a metadata heap
    items = string_heap.get_items()

    #obtain a single item by index
    item = string_heap.get_item(index)

    #delete an item (internally handled by change_value())
    amt_difference = string_heap.del_item(index)

    #append an item

    new_index = string_heap.append_item(b'AppendThisString')

    # After any changes, reconstruct_executable() should be called.

### Patching methods

A better method patching system may be added eventually, but for now dotnetpe.patch_instruction() can be used to safely replace instructions within a method.

### Emuulation

DotNetUtils contains a emulator, DotNetEmulator.

    from dotnetutils import net_emulator

    emulator = net_emulator.DotNetEmulator(method_object) #Setup the emulator.  Only required parameter is a method object.

    emulator.setup_method_params([<method_params>]) #setup method params.

    emulator.run_function() #Run the emulator.  Will raise net_exceptions.EmulatorEndExecutionException if it ends due to user specified settings (using end_offset etc.)

    item = emulator.get_stack().pop_obj() #Pop the return value off the stack once finished.


### net_deobfuscate.py

net_deobfuscate.py contains some common utilities for removing the most common .NET obfuscation such as name obfuscation, useless conditionals and useless functions.  net_deobfuscate_funcs.pyx implements the functions on an api level, while net_deobfuscate.py contains a command line utility to use them.

### Experimental Features
Control flow deobfuscation, implemented by net_graphing.py, net_graph_analyzer.py is currently experimental.
It seems to work pretty well for confuserex control flow deobfuscation but its still a work in progress.  It also outputs instructions in weird orders currently.

There are deobfuscators for NET Reactor and ConfuserEx in the deobfuscators folder.  Those are work in progress as well.

### Documentation

All functions have docstrings which describe what they do and their parameters etc.  HTML documentation can be found in docs/html.




