import hashlib
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
ep['Name'].change_value(b'ILovePieVeryMuch')
data = dpe.get_exe_data()
data_hash = hashlib.sha256()
data_hash.update(data)
data_hash = data_hash.hexdigest()
assert data_hash == '3cbbe7c3f54960cb0e893aa96b73a4d17736def4f311a71f0f12aa0e90eefb72'
print('Done!!!')

"""
dpe.get_heap('#Strings').append_item(b'ILovePieVeryMuch')

fd = open('result.bin', 'wb')
fd.write(dpe.get_exe_data())
fd.close()
print('done')
"""