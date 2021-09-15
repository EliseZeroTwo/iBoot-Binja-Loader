from binaryninja import *
from time import sleep


class iBootView(BinaryView):
    long_name = "iBoot"
    name = "iBoot"
    PROLOGUES = [b"\x7F\x23\x03\xD5", b"\xBD\xA9", b"\xBF\xA9"]

    def log(self, msg, error=False):
        msg = f"[iBoot-Loader] {msg}"
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
        if data.read(0x200, 5) == b"iBoot" or data.read(0x200, 9) == b"SecureROM":
            return True
        return False

    def set_name_from_func_xref(self, name, addr):
        refs = list(self.get_code_refs(addr))
        if len(refs) != 0:
            functions = self.get_functions_containing(refs[0].address)
            if len(functions) != 0:
                functions[0].name = name
                return functions[0].lowest_address
        return None

    def set_name_from_str_xref(self, name, string):
        string_offset = self.binary.find(string.encode("ascii"), 0)
        if string_offset != -1:
            refs = list(self.get_code_refs(self.base + string_offset))
            if len(refs) != 0:
                functions = list(self.get_functions_containing(refs[0].address))
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
        macho_valid_addr = self.set_name_from_pattern(
            "_macho_valid", b"\x49\x01\x8B\x9A"
        )
        if macho_valid_addr != None:
            loaded_kernelcache_addr = self.set_name_from_func_xref(
                "_loaded_kernelcache", macho_valid_addr
            )
            if loaded_kernelcache_addr != None:
                self.set_name_from_func_xref(
                    "_load_kernelcache", loaded_kernelcache_addr
                )

        self.set_name_from_str_xref("_panic", "\n[iBoot Panic]: ")
        self.set_name_from_str_xref("_platform_get_usb_serial_number_string", "CPID:")
        self.set_name_from_str_xref("_platform_get_usb_more_other_string", " NONC:")
        self.set_name_from_str_xref("_image4_get_partial", "IMG4")
        self.set_name_from_str_xref("_UpdateDeviceTree", "fuse-revision")
        self.set_name_from_str_xref("_main_task", "debug-uarts")
        self.set_name_from_str_xref("_print_boot_banner", "::\tBUILD_TAG: %s\n")
        self.set_name_from_pattern("_plaform_early_init", b"\x60\x02\x40\x39")
        self.set_name_from_str_xref("_task_init", "idle task")
        self.set_name_from_pattern("_aes_crypto_cmd", b"\x89\x2C\x00\x72")

        usb_vendor_id = self.set_name_from_pattern(
            "_platform_get_usb_vendor_id", b"\x80\xb5\x80\x52"
        )
        usb_core_init = self.set_name_from_func_xref("_usb_core_init", usb_vendor_id)
        self.set_name_from_func_xref("_usb_init_with_controller", usb_core_init)

        self.binary = b""

    def init(self):
        self.arch = Architecture["aarch64"]
        self.platform = Architecture["aarch64"].standalone_platform
        self.isSecureROM = self.raw.read(0x200, 9) == b"SecureROM"

        self.log(f"Loading {'SecureROM' if self.isSecureROM else 'iBoot'}")

        addr = 0
        self.base = None
        for inst in self.raw.disassembly_text(0x0, Architecture["aarch64"]):
            # inst is a tuple, which looks like this : ('ldr     x1, 0x300', 4)
            # it contains the instruction and its size
            if "ldr" in inst[0]:
                self.reader.seek(int(inst[0].split(" ")[-1], 16))
                self.base = self.reader.read64()

        if self.base == None:
            self.log("Failed to find entry point", error=True)
            return False

        self.log(f"Found base {hex(self.base)}")
        self.add_auto_segment(
            self.base,
            len(self.parent_view),
            0,
            len(self.parent_view),
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
        )
        self.add_user_section(
            self.name,
            self.base,
            len(self.raw),
            SectionSemantics.ReadOnlyCodeSectionSemantics,
        )
        self.add_entry_point(self.base)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.base, "_start"))

        self.binary = self.raw.read(0, len(self.raw))
        bin_start = self.start
        for prologue in self.PROLOGUES:
            while True:
                _next = self.find_next_data(
                    bin_start, b"\x7f\x23\x03\xd5", FindFlag.FindCaseSensitive
                )
                if _next == bin_start:
                    break
                else:
                    self.create_user_function(_next)
                    bin_start = _next

        AnalysisCompletionEvent(self, self.on_complete)
        self.add_entry_point(self.base)
        self.get_function_at(self.base).name = "start"
        return True
