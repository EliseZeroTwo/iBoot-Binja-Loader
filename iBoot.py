from binaryninja import *
from time import sleep

class iBootView(BinaryView):
    long_name  = 'iBoot'
    name       = 'iBoot'
    PROLOGUES  = [b'\x7F\x23\x03\xD5', b'\xBD\xA9', b'\xBF\xA9']

    def log(self, msg, error=False):
        msg = f'[iBoot-Loader] {msg}'
        if not error:
            log_info(msg)
        else:
            log_error(msg)

    def __init__(self, data):
        self.raw = data
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        self.writer = BinaryWriter(data, Endianness.LittleEndian)
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
    
    @classmethod
    def is_valid_for_data(cls, data):
        if data.read(0x200, 5) == b'iBoot' or data.read(0x200, 9) == b'SecureROM':
            return True
        return False

    def set_name_from_func_xref(self, name, addr):
        refs = self.get_code_refs(addr)
        if len(refs) != 0:
            functions = self.get_functions_containing(refs[0].address)
            if len(functions) != 0:
                functions[0].name = name
                return functions[0].lowest_address
        return None

    def set_name_from_str_xref(self, name, string):
        string_offset = self.binary.find(string.encode('ascii'), 0)
        if string_offset != -1:
            refs = self.get_code_refs(self.base + string_offset)
            if len(refs) != 0:
                functions = self.get_functions_containing(refs[0].address)
                if len(functions) != 0:
                    functions[0].name = name
                    return self.base + string_offset
        return None

    def set_name_from_pattern(self, name, pattern):
        pattern_offset = self.binary.find(pattern, 0)
        if pattern_offset != -1:
            functions = self.get_functions_containing(self.base + pattern_offset)
            if len(functions) != 0:
                functions[0].name = name
                return functions[0].lowest_address
        return None

    def on_complete(self):
        self.log("AA Complete")
        macho_valid_addr = self.set_name_from_pattern('_macho_valid', b'\x49\x01\x8B\x9A')
        if macho_valid_addr != None:
            loaded_kernelcache_addr = self.set_name_from_func_xref('_loaded_kernelcache', macho_valid_addr)
            if loaded_kernelcache_addr != None:
                self.set_name_from_func_xref('_load_kernelcache', loaded_kernelcache_addr)

        self.set_name_from_str_xref('_panic', '\n[iBoot Panic]: ')
        self.binary = b''
    
    def init(self):
        self.arch        = Architecture['aarch64']
        self.platform    = Architecture['aarch64'].standalone_platform
        self.isSecureROM = self.raw.read(0x200, 9) == b'SecureROM'

        self.log(f"Loading {'SecureROM' if self.isSecureROM else 'iBoot'}")

        addr = 0
        self.base = None
        while(addr <= 0x200):
            inst = self.raw.get_disassembly(addr, Architecture['aarch64'])
            if inst is not None:
                if "ldr" in inst:
                    self.reader.seek(int(inst.split(' ')[-1], 16))
                    self.base = self.reader.read64()
                    break
            addr += 4
        
        if self.base == None:
            self.log("Failed to find entry point", error=True)
            return False

        self.log(f"Found base {hex(self.base)}")
        
        self.add_user_segment(self.base, len(self.raw), 0, len(self.raw), SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
        self.add_user_section(self.name, self.base, len(self.raw), SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.binary = self.raw.read(0, len(self.raw))

        for prologue in self.PROLOGUES:
            offset = self.binary.find(prologue, 0)
            while offset != -1:
                func_off = offset - 2

                if (func_off % 4) == 0:
                    self.add_function(self.base + func_off)
                    offset = self.binary.find(prologue, offset + 2)
        

        AnalysisCompletionEvent(self, self.on_complete)
        self.add_entry_point(self.base)
        self.get_function_at(self.base).name = 'start'
        return True