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
assert data_hash == '8063E51CF9C3ADA9C915DA878C221A332C90670C527CD05AFE5D24B02E14A46D'.lower()
print('Done!!!')