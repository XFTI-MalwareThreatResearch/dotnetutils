from dotnetutils import net_exceptions

class DeobfuscatorContext:
    def __init__(self):
        self.__data_store = dict()
    
    def get_item(self, name):
        return self.__data_store[name]
    
    def set_item(self, name, v):
        self.__data_store[name] = v

    def has_item(self, name):
        return name in self.__data_store

class Deobfuscator:

    NAME = None

    def __init__(self):
        pass

    def identify_unpack(self, dotnet, ctx):
        raise net_exceptions.FeatureNotImplementedException()
    
    def identify_deobfuscate(self, dotnet, ctx):
        raise net_exceptions.FeatureNotImplementedException()

    def unpack(self, dotnet, ctx):
        raise net_exceptions.FeatureNotImplementedException()
    
    def deobfuscate(self, dotnet, ctx):
        raise net_exceptions.FeatureNotImplementedException()