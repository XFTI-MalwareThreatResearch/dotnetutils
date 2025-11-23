from dotnetutils import net_exceptions

class Deobfuscator:

    NAME = None

    def __init__(self):
        pass

    def identify_unpack(self, dotnet):
        raise net_exceptions.FeatureNotImplementedException()
    
    def identify_deobfuscate(self, dotnet):
        raise net_exceptions.FeatureNotImplementedException()

    def unpack(self, dotnet):
        raise net_exceptions.FeatureNotImplementedException()
    
    def deobfuscate(self, dotnet):
        raise net_exceptions.FeatureNotImplementedException()