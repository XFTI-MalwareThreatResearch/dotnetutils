class DotNetUtilsException(Exception):
    def __init__(self):
        Exception.__init__(self, "Generic Dotnetutils Exception")

class EmulatorExecutionException(DotNetUtilsException):
    def __init__(self, emu_obj, msg):
        self.__emu_obj = emu_obj
        Exception.__init__(self, msg)
    
    def get_emu_obj(self):
        return self.__emu_obj
    
class EmulatorTimeoutException(EmulatorExecutionException):
    def __init__(self, emu_obj):
        EmulatorExecutionException.__init__(self, emu_obj, 'Emulator execution timed out.')

class EmulatorEndExecutionException(DotNetUtilsException):
    def __init__(self, emu_obj, method_rid, end_method_rid, end_offset, current_offset):
        Exception.__init__(self, "Emulator ending at method RID {}, end method RID {}, end offset {}, current offset {}".format(method_rid, end_method_rid, hex(end_offset), hex(current_offset)))
        self.__emu_obj = emu_obj
    
    def get_emu_obj(self):
        return self.__emu_obj

class InvalidAssemblyException(DotNetUtilsException):
    def __init__(self, token=0):
        Exception.__init__(self, "Invalid IL assembly detected on method {}".format(hex(token)))

class InvalidTokenException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Invalid token")

class InvalidPatchException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "attempted to patch a binary with an invalid value.")

class InvalidVirtualAddressException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Attempted to supply an invalid virtual address")

class FeatureNotImplementedException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Attempted to use a functionality that is not yet implemented.")

class CannotCompressSizeException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Attempted to compress an invalid size")

class InvalidHeapNameException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "attempted to parse a heap that cannot be parsed by this library")

class InvalidArgumentsException(DotNetUtilsException):
    def __init__(self, expected=None, actual=None):
        if expected == None and actual == None:
            Exception.__init__(self, "invalid arguments")
        else:
            Exception.__init__(self, 'Invalid arguments: expected={}, actual={}'.format(expected, actual))

class DeserializationException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Failed to parse serialized object.")


class InvalidHeaderException(DotNetUtilsException):
    def __init__(self, token=0):
        Exception.__init__(self, "Failed to process header. Method Token {}".format(hex(token)))

class InvalidMetadataException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Failed to process metadata.")

class ReconstructionFailedException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Failed to reconstruct executable.")

class DisassemblyFailedException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Failed to disassemble method.")

class ObjectTypeException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Object does not have the expected type.")

class EncodingMismatchException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Object's encoding does not match what is expected.")

class MethodTooLargeException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Method too large to process.")

class DotNetIOException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Error during IO operation.")

class OpcodeLookupException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Could not find usable opcode in NET_OPCODE_DB.")

class MethodLookupException(DotNetUtilsException):
    def __init__(self, full_name):
        Exception.__init__(self, 'The method {} could not be found.'.format(full_name))

class InvalidBlockException(DotNetUtilsException):
    def __init__(self): 
        Exception.__init__(self, "The .NET block is invalid (or has an unexpected structure).")

class OpcodeNotInitializedException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "Attempted to call obtain_opcode on an unititialized opcode object.")

class NotADotNetFile(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "The provided file is either corrupted or not a dotnet file.")

class OperationNotSupportedException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "The operation attempted is not currently supported.")

class DotNetOverflowException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "An .NET CIL instruction generated an overflow exception.")

class InstructionNotSupportedException(DotNetUtilsException):
    def __init__(self, instr_name):
        Exception.__init__(self, "An .NET CIL instruction is not supported by the emulator: {}".format(instr_name))

class EmulatorSecurityException(DotNetUtilsException):
    def __init__(self, instr_string='unknown'):
        Exception.__init__(self, "A .NET instruction could not be emulated for security purposes: {}".format(instr_string))

class EmulatorTypeNotFoundException(DotNetUtilsException):
    def __init__(self, type_name):
        Exception.__init__(self, 'The type {} does not exist in the external types registry.'.format(type_name))

class EmulatorMethodNotFoundException(DotNetUtilsException):
    def __init__(self, full_name):
        Exception.__init__(self, 'The method {} could not be found.'.format(full_name))

class EmualatorMaxStackSizeViolated(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, 'The max stack size has been violated.')

class EmulatorFailureException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, "The emulator encountered an unexpected scenario and failed to emulate the targeted code.")

class EmulatorStackTypeUnknown(DotNetUtilsException):
    def __init__(self, obj_type):
        Exception.__init__(self, 'An object with a unknown type ({}) has been added to the stack.'.format(obj_type))

class InvalidTokenException(DotNetUtilsException):
    def __init__(self, token_type, value):
        Exception.__init__(self, 'A token with value {} is invalid for type {}'.format(hex(value), token_type))

class InvalidSignatureException(DotNetUtilsException):
    def __init__(self, sig_type):
        Exception.__init__(self, 'Attempted to parse an invalid signature of type {}'.format(sig_type))

class EmulatorMethodBreakException(DotNetUtilsException):
    def __init__(self):
        Exception.__init__(self, 'This exception is for internal use only.  Method execution has been stopped before ret instruction.')

class TooManyMethodParameters(DotNetUtilsException):
    def __init__(self, method_param_count):
        Exception.__init__(self, f"Attempted to parse a DotNet file with {method_param_count} method params")