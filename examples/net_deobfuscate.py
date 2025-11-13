import sys
from dotnetutils import net_deobfuscate_funcs, net_exceptions, dotnetpefile, net_graphing

def main():
    if len(sys.argv) < 4:
        print('Usage: net_deobfuscate.py <deob type> <input file> <output file> <extra args>')
        print('Types:')
        print('conditional: Removes certain conditional statements that arent needed.')
        print('names: cleans up type, method names etc.')
        print('dumbfuncs: Cleans up function calls which only purpose is to call another function.')
        print(
            'switch: Deobfuscates switch statements that are meant to obfuscate control flow.  Work In Progress, Not currently implemented.')
        print('printgraph: Prints a function graph of a fucntion within a exe.')
        print(
            'unk_obf_1: a currently unknown obfuscator.  Example hash: e6579d0717d17f39f2024280100c9fffb8be1699ccf14d9c708150c0a54fcedb')
        exit()
    deob_type = sys.argv[1]
    obf_exe = sys.argv[2]
    output_exe = sys.argv[3]
    with open(obf_exe, 'rb') as infile:
        data = infile.read()
    if deob_type == 'conditional':
        print('Attempting to remove useless conditionals')
        new_data = net_deobfuscate_funcs.remove_useless_conditionals(data)
    elif deob_type == 'names':
        print('Cleaning up various names throughout the binary.')
        new_data = net_deobfuscate_funcs.cleanup_names(data)
    elif deob_type == 'dumbfuncs':
        print('Cleaning up useless function calls')
        new_data = net_deobfuscate_funcs.remove_useless_functions(data)
    elif deob_type == 'switch':
        print('Removing switch statements with constant outcomes.')
        # new_data = deobfuscate_method_control_flow(data)
        raise net_exceptions.OperationNotSupportedException()
    elif deob_type == 'printgraph':
        method_rid = int(output_exe, 10)
        dpe = dotnetpefile.DotNetPeFile(pe_data=data)
        mobj = dpe.get_method_by_rid(method_rid)
        fgraph = net_graphing.FunctionGraph(mobj)
        #fanalyzer = net_graphing.GraphAnalyzer(mobj, fgraph)
        #fanalyzer.remove_useless_math()
        #fanalyzer.repair_blocks()
        fgraph.print_root()
        print('done')
        exit(0)
    elif deob_type == 'dumbmath':
        #Remove useless math expressions.
        dpe = dotnetpefile.DotNetPeFile(pe_data=data)
        for mobj in dpe.get_metadata_table('MethodDef'):
            if not mobj.has_body():
                continue
            print('checking for useless math from method {}'.format(hex(mobj.get_token())))
            fgraph = net_graphing.FunctionGraph(mobj)
            fanalyzer = net_graphing.GraphAnalyzer(mobj, fgraph)
            fanalyzer.repair_blocks()
            has_math = fanalyzer.remove_useless_math()
            if has_math:
                fanalyzer.repair_blocks()
                localvartok = mobj.disassemble_method().get_local_var_sig_token()
                instrs = fgraph.emit_instructions_as_list()
                exc_blocks = fgraph.get_exception_blocks()
                recompiler = net_graphing.MethodRecompiler(instrs, exc_blocks, localvartok)
                data = recompiler.compile_method()
                mobj.set_method_data(data)
                print('patched method {}'.format(hex(mobj.get_token())))
            else:
                print('method {} has no useless math.'.format(hex(mobj.get_token())))
        new_data = dpe.get_exe_data()

    elif deob_type == 'printallgraphs':
        print('Printing graphs for all methods in the executable.')
        print()
        dpe = dotnetpefile.try_get_dotnetpe(pe_data=data)
        if dpe is None:
            print('error: invalid dotnet pe.')
        else:
            for method in dpe.get_metadata_table('MethodDef'):
                if method.has_body():
                    fgraph = net_graphing.FunctionGraph(method)
                    fgraph.print_root()
                    print()
                    print()
        print('done')
        exit(0)
    elif deob_type == 'unk_obf_1':
        print('Attempting to remove obfuscation using unk_obf_1.')
        new_data = net_deobfuscate_funcs.remove_useless_bytearray_conditionals(data)
        new_data = net_deobfuscate_funcs.cleanup_names(new_data)
        new_data = net_deobfuscate_funcs.remove_unk_obf_1_obfuscation(new_data)
    else:
        print('invalid mode')
        exit()

    if new_data != None:
        with open(output_exe, 'wb') as outfile:
            outfile.write(new_data)
        print('Done')
    else:
        print('Error deobfuscating: returned None.')


if __name__ == '__main__':
    main()
