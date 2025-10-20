import hashlib
import binascii
from dotnetutils import dotnetpefile
from dotnetutils import net_emulator, net_exceptions
from datetime import datetime
start = datetime.now()
dpe = dotnetpefile.try_get_dotnetpe('EmulatorTesting_Cex_BasicCompressed.exe')
end = datetime.now()
print('took {} to parse'.format(end - start))
start = end
ep = dpe.get_entry_point()
print('entry point {}'.format(ep))
emu = net_emulator.DotNetEmulator(ep, end_method_rid=2, end_offset=0x4b)
emu.set_print_debugging(True, True)
try:
    emu.run_function()
except net_exceptions.EmulatorEndExecutionException as e:
    emu = e.get_emu_obj()
end = datetime.now()
print('Took {} to emulate'.format(end - start))
array_obj = emu.get_stack().pop()
result = array_obj.as_bytes()

expected_hash = 'db2a84c286cc2d43d36f782c2fe0a2dddabc1187985b3c2956ce524b3e16b794'
result_hash = hashlib.sha256()
result_hash.update(result)
result_hash = result_hash.hexdigest()
#fd = open('result_actual.bin', 'wb')
#fd.write(result)
#fd.close()
assert expected_hash == result_hash
print('Worked!!!')