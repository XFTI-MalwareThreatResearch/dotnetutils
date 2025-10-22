from dotnetutils import dotnetpefile, net_emulator, net_emu_types, net_exceptions
import sys
path = 'C:\\Users\\research\\Documents\\Code\\extmir-DC3-MWCP\\xfti_parsers\\parsers\\samples\\0de5\\0de50e648e2d813a40f4342dff9b00b0'

print('starting')

dotnet = dotnetpefile.try_get_dotnetpe(file_path=path)

ep_method = dotnet.get_entry_point()
end_offset = -1
for instr in ep_method.disassemble_method():
    if instr.get_name() == 'call' and instr.get_argument().get_full_name() == b'System.Runtime.InteropServices.GCHandle.get_Target':
        end_offset = instr.get_instr_offset() + len(instr)
        break

if end_offset == -1:
    print('Could not find offset to end emulation.')
    exit(0)
emu_obj = net_emulator.DotNetEmulator(ep_method, end_offset=end_offset, dont_execute_cctor=True)
worked = False
emu_obj.set_print_debugging(False, False, print_debug_methods=[23])
try:
    emu_obj.run_function()
except net_exceptions.EmulatorEndExecutionException:
    worked = True
if not worked:
    print('Emulation failed.')
    exit(0)

result = emu_obj.get_stack().pop_obj()
if not isinstance(result, net_emu_types.DotNetArray):
    print('Emulation failed to get array.')
    exit(0)
result = result.as_bytes()
result_dpe = dotnetpefile.try_get_dotnetpe(pe_data=result)
if result_dpe is None:
    print('Obtained weird result data')
else:
    fd = open('result.bin', 'wb')
    fd.write(result)
    fd.close()
    print('wrote result')