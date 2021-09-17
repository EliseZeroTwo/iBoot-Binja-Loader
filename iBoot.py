from binaryninja import *

class iBootView(BinaryView):
    long_name = "iBoot"
    name = "iBoot"
    PROLOGUES = [b"\xBD\xA9", b"\xBF\xA9"]

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
        if (
            data.read(0x200, 5) == b'iBoot'
            or data.read(0x200, 4) == (b'iBEC' or b'iBSS')
            or data.read(0x200, 9) == b'SecureROM'
            or data.read(0x200, 9) == b'AVPBooter'
        ):
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

    def set_name_from_str_xref(self, name, string, partial=0):
        if partial:
            string_offset = [str_.start for str_ in self.strings if string in str_.value]
        else:
            string_offset = [str_.start for str_ in self.strings if str_.value == string]

        if len(string_offset) != 0:
            refs = list(self.get_code_refs(string_offset[0]))
            if len(refs) != 0:
                functions = list(self.get_functions_containing(refs[0].address))
                if len(functions) != 0:
                    functions[0].name = name
                    return string_offset
        return None

    def set_name_from_pattern(self, name, pattern):
        pattern_offset = self.find_next_data(0, pattern)
        if pattern_offset is not None:
            functions = self.get_functions_containing(pattern_offset)
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

        self.set_name_from_str_xref("_panic", "double panic in ")
        self.set_name_from_str_xref("_platform_get_usb_serial_number_string", "CPID:")
        self.set_name_from_str_xref("_platform_get_usb_more_other_string", " NONC:")
        self.set_name_from_str_xref("_image4_get_partial", "IMG4")
        self.set_name_from_str_xref("_UpdateDeviceTree", "fuse-revision")
        self.set_name_from_str_xref("_main_task", "debug-uarts")
        self.set_name_from_str_xref("_platform_init_display", "backlight-level")
        self.set_name_from_str_xref('_do_printf', '<null>')
        self.set_name_from_str_xref('_do_memboot', 'Combo image too large\n')
        self.set_name_from_str_xref('_do_go', 'Memory image not valid\n')
        self.set_name_from_str_xref("_task_init", "idle task")
        self.set_name_from_str_xref(
            '_sys_setup_default_environment',
            '/System/Library/Caches/com.apple.kernelcaches/kernelcache',
        )
        self.set_name_from_str_xref(
            '_check_autoboot', 'aborting autoboot due to user intervention.\n'
        )
        self.set_name_from_str_xref(
            '_do_setpict', 'picture too large, size:%zu\n'
        )
        self.set_name_from_str_xref(
            '_arm_exception_abort', 'ARM %s abort at 0x%016llx:', 1
        )
        self.set_name_from_str_xref(
            '_do_devicetree', 'Device Tree image not valid\n'
        )
        self.set_name_from_str_xref('_do_ramdisk', 'Ramdisk image not valid\n')
        self.set_name_from_str_xref(
            '_usb_serial_init', 'Apple USB Serial Interface'
        )
        self.set_name_from_str_xref(
            '_nvme_bdev_create',
            'Couldn\'t construct blockdev for namespace %d',
        )
        self.set_name_from_str_xref(
            '_image4_dump_list',
            'image %p: bdev %p type %c%c%c%c offset 0x%llx',
        )
        self.set_name_from_str_xref("_prepare_and_jump", "======== End of %s serial output. ========\n")
        self.set_name_from_str_xref('_boot_upgrade_system', '/boot/kernelcache')

        self.set_name_from_pattern("_plaform_early_init", b"\x60\x02\x40\x39")
        self.set_name_from_pattern("_aes_crypto_cmd", b"\x89\x2C\x00\x72")


        usb_vendor_id = self.set_name_from_pattern(
            "_platform_get_usb_vendor_id", b"\x80\xb5\x80\x52"
        )
        usb_core_init = self.set_name_from_func_xref("_usb_core_init", usb_vendor_id)
        self.set_name_from_func_xref("_usb_init_with_controller", usb_core_init)

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
                break

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

        bin_start = self.start
        _next = 0

        if self.find_next_text(0, "pacibsp"):
            self.PROLOGUES.append(self.start, b"\x7F\x23\x03\xD5")

        for prologue in self.PROLOGUES:
            while True:
                _next = self.find_next_data(
                    bin_start, prologue, FindFlag.FindCaseSensitive
                )
                if _next == bin_start:
                    break
                elif _next is None:
                    continue
                else:
                    self.create_user_function(_next)
                    bin_start = _next

        AnalysisCompletionEvent(self, self.on_complete)
        self.add_entry_point(self.base)
        self.get_function_at(self.base).name = "start"
        return True
