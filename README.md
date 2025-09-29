# dotnetutils

Offline install: python -m pip install --no-build-isolation --no-deps -e ./

TODO:
- remove usage of [] for fields, localvars and static_fields in DotNetEmulator
- remove usages of lists and dicts where possible.
- may want to look into using dict instead of unordered_map for non c++ types.
- Maybe make delete_user_string() call net_patch.
- remove all raise Exception()
- Change method names to use '::' notation instead of periods when splitting the class and method name.
- Have change_value() calls update the value in raw executable data.  This way we can return raw_data when doing reconstruct executable.
    - Maybe add some sort of token translator mapping that goes through and updates all token to their proper values from the original?
- Rework how instruction arguments are handled a bit.
- Go through and standardize integer type usage (signed vs unsigned etc)
- Before to_bytes(), add something that cleans off any extra strings or other items from the heaps in order to keep binary size down.
- Expand indexes to int64_t for ArrayAddress to be safe.
- Add support for MemberRef fields for cleanup_names()
- double check that cctors arent being called twice.