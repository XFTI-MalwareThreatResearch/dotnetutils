import sys
import os
import hashlib
from dotnetutils.deobfuscators.confuserex import ConfuserExDeobfuscator
from dotnetutils import net_deobfuscate_funcs, net_exceptions, dotnetpefile, net_graphing, net_graph_analyzer

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
        print('dumbmath: Removes redundant math expressions.  Example: 7005baba5671e99eb677bc7dff5b2e15527cb196668ad0340e9f015903430625')
        print('deob:: Runs a file against a list of deobfuscators.')
        exit()
    deob_type = sys.argv[1]
    obf_exe = sys.argv[2]
    output_exe = sys.argv[3]
    with open(obf_exe, 'rb') as infile:
        data = infile.read()
    dotnet = dotnetpefile.try_get_dotnetpe(pe_data=data)
    if dotnet is None:
        print('Not a dotnet file.')
        exit(0)
    if deob_type == 'conditional':
        print('Attempting to remove useless conditionals')
        net_deobfuscate_funcs.remove_useless_conditionals(dotnet)
    elif deob_type == 'names':
        print('Cleaning up various names throughout the binary.')
        net_deobfuscate_funcs.cleanup_names(dotnet)
    elif deob_type == 'dumbfuncs':
        print('Cleaning up useless function calls')
        net_deobfuscate_funcs.remove_useless_functions(dotnet)
    elif deob_type == 'switch':
        print('Removing switch statements with constant outcomes.')
        # new_data = deobfuscate_method_control_flow(data)
        raise net_exceptions.OperationNotSupportedException()
    elif deob_type == 'printgraph':
        method_rid = int(output_exe, 10)
        mobj = dotnet.get_method_by_rid(method_rid)
        fgraph = net_graphing.FunctionGraph(mobj)
        fgraph.print_root()
        print('done')
        exit(0)
    elif deob_type == 'cflow':
        """
        Current state of control flow deobfuscation:
        It seems to work for non try / catch finally filter methods
        Adds a useless br instruction after every block though.  Need to fix that.
        Currently need to fix stuff for try catch finally to work.
        """
        mspec_table = dotnet.get_metadata_table('MethodSpec')
        mspec_methods = set()
        for mspec in mspec_table:
            mspec_methods.add(mspec.get_method().get_rid())
        for mobj in dotnet.get_metadata_table('MethodDef'):
            if not mobj.has_body():
                continue
            if mobj.get_rid() in mspec_methods:
                continue
            if mobj.disassemble_method() is None:
                continue
            if mobj.get_token() != 0x06000060:
                #TODO: so far it works for one try block but its omitting a bunch of other ones.
                #Might be a compiler issue
                continue
            #Check  0x06000009  for e2f0 - weird output TODO
            #TODO: 0x0600003d has nonremoved switches, my guess is because its a methodspec that isnt referenced.
            print('doing method 1', hex(mobj.get_token()))
            fgraph = net_graphing.FunctionGraph(mobj)
            fgraph.validate_blocks()
            fanalyzer = net_graph_analyzer.GraphAnalyzer(mobj, fgraph)
            try:
                new_graph = fanalyzer.simplify_control_flow()
                if new_graph is None:
                    print('function is not obfuscated.')
                    continue
            except net_exceptions.EmulatorExecutionException as e:
                print('emulation failed due to error')
                continue
            except net_exceptions.ControlFlowDeobfuscationMisidentify as e:
                print('Possible control flow misidentification:', str(e))
                continue
            #new_graph.print_root()
            print('Done with flow check')
        mspecs_completed = set()
        for mspec in mspec_table:
            continue
            method = mspec.get_method()
            if method.get_rid() in mspecs_completed:
                continue
            mspecs_completed.add(method.get_rid())
            if method.disassemble_method() is None:
                continue
            if not method.has_body():
                continue

            fgraph = net_graphing.FunctionGraph(mspec)
            fgraph.validate_blocks()
            fanalyzer = net_graph_analyzer.GraphAnalyzer(mspec, fgraph)
            try:
                new_graph = fanalyzer.simplify_control_flow()
                if new_graph is None:
                    print('function is not obfuscated.')
                    continue
            except net_exceptions.EmulatorExecutionException as e:
                print('emulation failed due to error', str(e))
                continue
            except net_exceptions.ControlFlowDeobfuscationMisidentify as e:
                print('Possible control flow misidentification:', str(e))
                continue
    elif deob_type == 'dumbmath':
        #Remove useless math expressions.
        """
        Removes multiple math expressions chained after eachother with a single ldc.i4
        e.x
        ldc.i4 x
        not
        neg
        not 

        Is replaced to a single ldc.i4 with the result.
        """
        for mobj in dotnet.get_metadata_table('MethodDef'):
            if not mobj.has_body():
                continue
            print('checking for useless math from method {}'.format(hex(mobj.get_token())))
            fgraph = net_graphing.FunctionGraph(mobj)
            #fgraph.print_root()
            fgraph.validate_blocks()
            fanalyzer = net_graph_analyzer.GraphAnalyzer(mobj, fgraph)
            has_math = fanalyzer.remove_useless_math()
            if has_math:
                fanalyzer.repair_blocks()
                #fgraph.print_root()
                localvartok = mobj.disassemble_method().get_local_var_sig_token()
                instrs = fgraph.emit_instructions_as_list()
                exc_blocks = fgraph.get_raw_exception_clauses()
                recompiler = net_graph_analyzer.MethodRecompiler(instrs, exc_blocks, localvartok)
                data = recompiler.compile_method()
                mobj.set_method_data(data)
                print('patched method {}'.format(hex(mobj.get_token())))
            else:
                print('method {} has no useless math.'.format(hex(mobj.get_token())))
    elif deob_type == 'printallgraphs':
        print('Printing graphs for all methods in the executable.')
        print()
        if dotnet is None:
            print('error: invalid dotnet pe.')
        else:
            for method in dotnet.get_metadata_table('MethodDef'):
                if method.has_body():
                    fgraph = net_graphing.FunctionGraph(method)
                    fgraph.print_root()
                    print()
                    print()
        print('done')
        exit(0)
    elif deob_type == 'unk_obf_1':
        print('Attempting to remove obfuscation using unk_obf_1.')
        net_deobfuscate_funcs.remove_useless_bytearray_conditionals(dotnet)
        net_deobfuscate_funcs.cleanup_names(dotnet)
        net_deobfuscate_funcs.remove_unk_obf_1_obfuscation(dotnet)
    elif deob_type == 'deob':
        deobfuscators = [ConfuserExDeobfuscator]
        results = set()
        work = [dotnet]
        if not os.path.isdir(output_exe):
            print('error: invalid directory for results')
            exit(0)
        while work:
            current_dotnet = work.pop()
            for deob_type in deobfuscators:
                deob = deob_type()
                if deob.identify_unpack(current_dotnet):
                    print('Executable recognized as {} packed executable.'.format(deob.NAME))
                    unpacked_exes = deob.unpack(current_dotnet)
                    for unpacked_exe in unpacked_exes:
                        results.add(unpacked_exe)
                        dpe = dotnetpefile.try_get_dotnetpe(pe_data=unpacked_exe)
                        if dpe is not None:
                            work.append(dpe)
                    print('Extracted {} files'.format(len(unpacked_exes)))
                    break

                if deob.identify_deobfuscate(current_dotnet):
                    print('Executable recognized as {} obfuscated executable.'.format(deob.NAME))
                    if deob.deobfuscate(current_dotnet):
                        print('Deobfuscation completed for {}'.format(deob.NAME))
                        results.add(current_dotnet.get_exe_data())
                    else:
                        print('Deobfuscation failed for {}'.format(deob.NAME))

                    #Files can use multiple obfuscators.
        print('Outputting {} files to directory {}'.format(len(results), output_exe))
        for data in results:
            sha_obj = hashlib.sha256()
            sha_obj.update(data)
            filename = sha_obj.hexdigest()
            result_path = os.path.join(output_exe, filename)
            print('Saving outputted file to {}'.format(result_path))
            fd = open(result_path, 'wb')
            fd.write(data)
            fd.close()
        print('Done')
        exit(0)
                    
    else:
        print('invalid mode')
        exit()
    new_data = dotnet.get_exe_data()
    if new_data != None:
        with open(output_exe, 'wb') as outfile:
            outfile.write(new_data)
        print('Done')
    else:
        print('Error deobfuscating: returned None.')


if __name__ == '__main__':
    main()
