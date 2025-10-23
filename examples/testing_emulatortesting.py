from dotnetutils import dotnetpefile
from dotnetutils import net_emulator, net_exceptions
from datetime import datetime
start = datetime.now()
dpe = dotnetpefile.try_get_dotnetpe('EmulatorTesting.exe')
end = datetime.now()
print('took {} to parse'.format(end - start))
start = end
ep = dpe.get_entry_point()
print('entry point {}'.format(ep))
emu = net_emulator.DotNetEmulator(ep)
#emu.set_print_debugging(True, True)
emu.run_function()
end = datetime.now()
print('Took {} to emulate'.format(end - start))
print('Worked!!!')