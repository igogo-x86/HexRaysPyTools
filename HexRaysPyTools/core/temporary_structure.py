import bisect
import idc
import idaapi
import re
import itertools
# import PySide.QtCore as QtCore
# import PySide.QtGui as QtGui
import cache
from HexRaysPyTools.cute import *
import const
import helper
import variable_scanner
import HexRaysPyTools.api as api
import common
from HexRaysPyTools.forms import MyChoose


SCORE_TABLE = dict((v, k) for k, v in enumerate(
    ['unsigned __int8 *', 'unsigned __int8', '__int8 *', '__int8', '_BYTE', '_BYTE *', '_BYTE **', 'const char **',
     'signed __int16', 'unsigned __int16', '__int16', 'signed __int16 *', 'unsigned __int16 *', '__int16 *',
     '_WORD *', '_WORD **',
     'signed int*', 'signed int', 'unsigned int *', 'unsigned int', 'int **', 'char **', 'int *', 'void **',
     'int', '_DWORD *', 'char', '_DWORD', '_WORD', 'void *', 'char *']
))


def parse_vtable_name(address):
    name = idaapi.get_name(address)
    if idaapi.is_valid_typename(name):
        if name[0:3] == 'off':
            # off_XXXXXXXX case
            return "Vtable" + name[3:], False
        elif "table" in name:
            return name, True
        print "[Warning] Weird virtual table name -", name
        return "Vtable_" + name, False
    name = idc.demangle_name(idaapi.get_name(address), idc.INF_SHORT_DN)
    assert name, "Virtual table must have either legal c-type name or mangled name"
    return common.demangled_name_to_c_str(name), True


class AbstractMember:
    def __init__(self, offset, scanned_variable, origin):
        """
        Offset is the very very base of the structure
        Origin is from which offset of the base structure the variable have been scanned
        scanned_variable - information about context in which this variable was scanned. This is necessary for final
        applying type after packing or finalizing structure.

        :param offset: int
        :param scanned_variable: ScannedVariable
        :param origin: int
        """
        self.offset = offset
        self.origin = origin
        self.enabled = True
        self.is_array = False
        self.scanned_variables = {scanned_variable} if scanned_variable else set()
        self.tinfo = None

    def type_equals_to(self, tinfo):
        return self.tinfo.equals_to(tinfo)

    def switch_array_flag(self):
        self.is_array ^= True

    def activate(self):
        pass

    def set_enabled(self, enable):
        self.enabled = enable
        self.is_array = False

    def has_collision(self, other):
        if self.offset <= other.offset:
            return self.offset + self.size > other.offset
        return other.offset + other.size >= self.offset

    @property
    def score(self):
        """ More score of the member - it better suits as candidate for this offset """
        try:
            return SCORE_TABLE[self.type_name]
        except KeyError:
            if self.tinfo and self.tinfo.is_funcptr():
                return 0x1000 + len(self.tinfo.dstr())
            return 0xFFFF

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        size = self.tinfo.get_size()
        return size if size != idaapi.BADSIZE else 1

    @property
    def font(self):
        return None

    def __repr__(self):
        return hex(self.offset) + ' ' + self.type_name

    def __eq__(self, other):
        """ I'm aware that it's dirty but have no time to refactor whole file to nice one """

        if self.offset == other.offset and self.type_name == other.type_name:
            self.scanned_variables |= other.scanned_variables
            return True
        return False

    __ne__ = lambda self, other: self.offset != other.offset or self.type_name != other.type_name
    __lt__ = lambda self, other: self.offset < other.offset or \
                                 (self.offset == other.offset and self.type_name < other.type_name)
    __le__ = lambda self, other: self.offset <= other.offset
    __gt__ = lambda self, other: self.offset > other.offset or \
                                 (self.offset == other.offset and self.type_name < other.type_name)
    __ge__ = lambda self, other: self.offset >= other.offset


class VirtualFunction:
    def __init__(self, address, offset):
        self.address = address
        self.offset = offset
        self.visited = False

    def get_ptr_tinfo(self):
        # print self.tinfo.dstr()
        ptr_tinfo = idaapi.tinfo_t()
        ptr_tinfo.create_ptr(self.tinfo)
        return ptr_tinfo

    def get_udt_member(self):
        udt_member = idaapi.udt_member_t()
        udt_member.type = self.get_ptr_tinfo()
        udt_member.offset = self.offset
        udt_member.name = self.name
        udt_member.size = const.EA_SIZE
        return udt_member

    def get_information(self):
        return [helper.to_hex(self.address), self.name, self.tinfo.dstr()]

    @property
    def name(self):
        name = idaapi.get_name(self.address)
        if idaapi.is_valid_typename(name):
            return name
        name = idc.Demangle(name, idc.INF_SHORT_DN)
        return common.demangled_name_to_c_str(name)

    @property
    def tinfo(self):
        try:
            decompiled_function = idaapi.decompile(self.address)
            if decompiled_function:
                return idaapi.tinfo_t(decompiled_function.type)
            return const.DUMMY_FUNC
        except idaapi.DecompilationFailure:
            pass
        print "[ERROR] Failed to decompile function at 0x{0:08X}".format(self.address)
        return const.DUMMY_FUNC

    def show_location(self):
        idaapi.open_pseudocode(self.address, 1)


class ImportedVirtualFunction(VirtualFunction):
    def __init__(self, address, offset):
        VirtualFunction.__init__(self, address, offset)

    @property
    def tinfo(self):
        print "[INFO] Ignoring import function at 0x{0:08X}".format(self.address)
        tinfo = idaapi.tinfo_t()
        if idaapi.guess_tinfo2(self.address, tinfo):
            return tinfo
        return const.DUMMY_FUNC

    def show_location(self):
        idaapi.jumpto(self.address)


class VirtualTable(AbstractMember):
    class VirtualTableChoose(MyChoose):
        def __init__(self, items, temp_struct, virtual_table):
            MyChoose.__init__(
                self,
                items,
                "Select Virtual Function",
                [["Address", 10], ["Name", 15], ["Declaration", 45]],
                13
            )
            self.popup_names = ["Scan All", "-", "Scan", "-"]
            self.__temp_struct = temp_struct
            self.__virtual_table = virtual_table

        def OnGetLineAttr(self, n):
            return [0xd9d9d9, 0x0] if self.__virtual_table.virtual_functions[n].visited else [0xffffff, 0x0]

        def OnGetIcon(self, n):
            return 32 if self.__virtual_table.virtual_functions[n].visited else 160

        def OnInsertLine(self):
            """ Scan All Functions menu """
            self.__virtual_table.scan_virtual_functions()

        def OnEditLine(self, n):
            """ Scan menu """
            self.__virtual_table.scan_virtual_function(n)

    def __init__(self, offset, address, scanned_variable=None, origin=0):
        AbstractMember.__init__(self, offset + origin, scanned_variable, origin)
        self.address = address
        self.virtual_functions = []
        self.name = "vtable" + ("_{0:X}".format(self.offset) if self.offset else '')
        self.vtable_name, self.have_nice_name = parse_vtable_name(address)
        self.populate()

    def populate(self):
        address = self.address
        while True:
            if const.EA64:
                func_address = idaapi.get_64bit(address)
            else:
                func_address = idaapi.get_32bit(address)

            if helper.is_code_ea(func_address):
                self.virtual_functions.append(VirtualFunction(func_address, address - self.address))
            elif helper.is_imported_ea(func_address):
                self.virtual_functions.append(ImportedVirtualFunction(func_address, address - self.address))
            else:
                break
            address += const.EA_SIZE

            if idaapi.get_first_dref_to(address) != idaapi.BADADDR:
                break

    def create_tinfo(self):
        # print "(Virtual table) at address: 0x{0:08X} name: {1}".format(self.address, self.name)
        udt_data = idaapi.udt_type_data_t()
        for function in self.virtual_functions:
            udt_data.push_back(function.get_udt_member())

        for duplicates in helper.search_duplicate_fields(udt_data):
            first_entry_idx = duplicates.pop(0)
            print "[Warning] Found duplicate virtual functions", udt_data[first_entry_idx].name
            for num, dup in enumerate(duplicates):
                udt_data[dup].name = "duplicate_{0}_{1}".format(first_entry_idx, num + 1)
                tinfo = idaapi.tinfo_t()
                tinfo.create_ptr(const.DUMMY_FUNC)
                udt_data[dup].type = tinfo

        final_tinfo = idaapi.tinfo_t()
        if final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT):
            # print "\n\t(Final structure)\n" + idaapi.print_tinfo('\t', 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE
            #                                                      | idaapi.PRTYPE_SEMI, final_tinfo, self.name, None)
            return final_tinfo
        print "[ERROR] Virtual table creation failed"

    def import_to_structures(self, ask=False):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                           self.create_tinfo(), self.vtable_name, None)
        if ask:
            cdecl_typedef = idaapi.asktext(0x10000, cdecl_typedef, "The following new type will be created")
            if not cdecl_typedef:
                return
        previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, self.vtable_name)
        if previous_ordinal:
            idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
            ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
        else:
            ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)

        if ordinal:
            print "[Info] Virtual table " + self.vtable_name + " added to Local Types"
            return idaapi.import_type(idaapi.cvar.idati, -1, self.vtable_name)
        else:
            print "[Error] Failed to create virtual table " + self.vtable_name
            print "*" * 100
            print cdecl_typedef
            print "*" * 100

    def show_virtual_functions(self):
        function_chooser = self.VirtualTableChoose(
            [function.get_information() for function in self.virtual_functions], cache.temporary_structure, self)

        idx = function_chooser.Show(True)
        if idx != -1:
            virtual_function = self.virtual_functions[idx]
            virtual_function.visited = True
            virtual_function.show_location()

    def scan_virtual_function(self, index):
        if helper.is_imported_ea(self.virtual_functions[index].address):
            print "[INFO] Ignoring import function at 0x{0:08X}".format(self.address)
            return
        try:
            function = idaapi.decompile(self.virtual_functions[index].address)
        except idaapi.DecompilationFailure:
            print "[ERROR] Failed to decompile function at 0x{0:08X}".format(self.address)
            return
        if helper.FunctionTouchVisitor(function).process():
            function = idaapi.decompile(self.virtual_functions[index].address)
        if function.arguments and function.arguments[0].is_arg_var and helper.is_legal_type(function.arguments[0].tif):
            print "[Info] Scanning virtual function at 0x{0:08X}".format(function.entry_ea)
            # TODO: Remove usage `temporary_structure' as global
            obj = api.VariableObject(function.get_lvars()[0], 0)
            scanner = variable_scanner.NewDeepSearchVisitor(function, self.offset, obj, cache.temporary_structure)
            scanner.process()
        else:
            print "[Warning] Bad type of first argument in virtual function at 0x{0:08X}".format(function.entry_ea)

    def scan_virtual_functions(self):
        for idx in xrange(len(self.virtual_functions)):
            self.scan_virtual_function(idx)

    def get_udt_member(self, offset=0):
        udt_member = idaapi.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name
            tmp_tinfo = idaapi.create_typedef(self.vtable_name)
            tmp_tinfo.create_ptr(tmp_tinfo)
            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset - offset
            udt_member.size = const.EA_SIZE
        return udt_member

    def type_equals_to(self, tinfo):
        udt_data = idaapi.udt_type_data_t()
        if tinfo.is_ptr() and tinfo.get_pointed_object().get_udt_details(udt_data):
            if udt_data[0].type.is_funcptr():
                return True
        return False

    def switch_array_flag(self):
        pass

    def activate(self):
        self.show_virtual_functions()

    @staticmethod
    def check_address(address):
        # Checks if given address contains virtual table. Returns True if more than 2 function pointers found
        # Also if table's addresses point to code in executable section, than tries to make functions at that addresses
        if helper.is_code_ea(address):
            return False

        functions_count = 0
        while True:
            func_address = idaapi.get_64bit(address) if const.EA64 else idaapi.get_32bit(address)
            # print "[INFO] Address 0x{0:08X}".format(func_address)
            if helper.is_code_ea(func_address) or helper.is_imported_ea(func_address):
                functions_count += 1
                address += const.EA_SIZE
            else:
                segment = idaapi.getseg(func_address)
                if segment and segment.perm & idaapi.SEGPERM_EXEC:
                    idc.MakeUnknown(func_address, 1, idaapi.DOUNK_SIMPLE)
                    if idc.MakeFunction(func_address):
                        functions_count += 1
                        address += const.EA_SIZE
                        continue
                break
            idaapi.autoWait()
        return functions_count

    @property
    def score(self):
        return 0x2000

    @property
    def type_name(self):
        return self.vtable_name + " *"

    @property
    def font(self):
        return QtGui.QFont("Consolas", 10, QtGui.QFont.Bold)

    @property
    def size(self):
        return const.EA_SIZE


class Member(AbstractMember):
    def __init__(self, offset, tinfo, scanned_variable, origin=0):
        AbstractMember.__init__(self, offset + origin, scanned_variable, origin)
        self.tinfo = tinfo
        self.name = "field_{0:X}".format(self.offset)

    def get_udt_member(self, array_size=0, offset=0):
        udt_member = idaapi.udt_member_t()
        udt_member.name = "field_{0:X}".format(self.offset - offset) if self.name[:6] == "field_" else self.name
        udt_member.type = self.tinfo
        if array_size:
            tmp = idaapi.tinfo_t(self.tinfo)
            tmp.create_array(self.tinfo, array_size)
            udt_member.type = tmp
        udt_member.offset = self.offset - offset
        udt_member.size = self.size
        return udt_member

    def activate(self):
        new_type_declaration = idaapi.askstr(0x100, self.type_name, "Enter type:")
        if new_type_declaration is None:
            return

        result = idc.ParseType(new_type_declaration, 0)
        if result is None:
            return
        _, tp, fld = result
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(idaapi.cvar.idati, tp, fld, None)
        self.tinfo = tinfo
        self.is_array = False


class VoidMember(Member):
    def __init__(self, offset, scanned_variable, origin=0, char=False):
        tinfo = const.CHAR_TINFO if char else const.BYTE_TINFO
        Member.__init__(self, offset, tinfo, scanned_variable, origin)
        self.is_array = True

    def type_equals_to(self, tinfo):
        return True

    def switch_array_flag(self):
        pass

    def set_enabled(self, enable):
        self.enabled = enable

    @property
    def font(self):
        return QtGui.QFont("Consolas", 10, italic=True)


class TemporaryStructureModel(QtCore.QAbstractTableModel):

    def __init__(self, *args):
        """
        Keeps information about currently found fields in possible structure
        main_offset - is the base from where variables scanned. Can be set to different value if some field is passed by
                      reverence
        items - array of candidates to fields
        """
        super(TemporaryStructureModel, self).__init__(*args)
        self.main_offset = 0
        self.headers = ["Offset", "Type", "Name"]
        self.items = []
        self.collisions = []
        self.structure_name = "CHANGE_MY_NAME"

    # OVERLOADED METHODS #

    def rowCount(self, *args):
        return len(self.items)

    def columnCount(self, *args):
        return len(self.headers)

    def data(self, index, role):
        row, col = index.row(), index.column()
        item = self.items[row]
        if role == QtCore.Qt.DisplayRole:
            if col == 0:
                return "0x{0:08X}".format(item.offset)
            elif col == 1:
                if item.is_array and item.size > 0:
                    array_size = self.calculate_array_size(row)
                    if array_size:
                        return item.type_name + "[{}]".format(array_size)
                return item.type_name
            elif col == 2:
                return item.name
        elif role == QtCore.Qt.ToolTipRole:
            if col == 0:
                return self.items[row].offset
            elif col == 1:
                return self.items[row].size * (self.calculate_array_size(row) if self.items[row].is_array else 1)
        elif role == QtCore.Qt.EditRole:
            if col == 2:
                return self.items[row].name
        elif role == QtCore.Qt.FontRole:
            if col == 1:
                return item.font
        elif role == QtCore.Qt.BackgroundRole:
            if not item.enabled:
                return QtGui.QColor(QtCore.Qt.gray)
            if item.offset == self.main_offset:
                if col == 0:
                    return QtGui.QBrush(QtGui.QColor("#ff8080"))
            if self.have_collision(row):
                return QtGui.QBrush(QtGui.QColor("#ffff99"))
        elif role == QtCore.Qt.ForegroundRole:
            if self.have_collision(row):
                return QtGui.QBrush(QtGui.QColor("#191919"))

    def setData(self, index, value, role):
        row, col = index.row(), index.column()
        if role == QtCore.Qt.EditRole and idaapi.isident(str(value)):
            self.items[row].name = str(value)
            self.dataChanged.emit(index, index)
            return True
        return False

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]

    def flags(self, index):
        if index.column() == 2:
            return super(TemporaryStructureModel, self).flags(index) | QtGui.QAbstractItemView.DoubleClicked
        return super(TemporaryStructureModel, self).flags(index)

    # HELPER METHODS #

    def pack(self, start=0, stop=None):
        if self.collisions[start:stop].count(True):
            print "[Warning] Collisions detected"
            return

        final_tinfo = idaapi.tinfo_t()
        udt_data = idaapi.udt_type_data_t()
        origin = self.items[start].offset if start else 0
        offset = origin

        for item in filter(lambda x: x.enabled, self.items[start:stop]):    # Filter disabled members
            gap_size = item.offset - offset
            if gap_size:
                udt_data.push_back(TemporaryStructureModel.get_padding_member(offset - origin, gap_size))
            if item.is_array:
                array_size = self.calculate_array_size(bisect.bisect_left(self.items, item))
                if array_size:
                    udt_data.push_back(item.get_udt_member(array_size, offset=origin))
                    offset = item.offset + item.size * array_size
                    continue
            udt_data.push_back(item.get_udt_member(offset=origin))
            offset = item.offset + item.size

        final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        cdecl = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                   final_tinfo, self.structure_name, None)
        cdecl = idaapi.asktext(0x10000, '#pragma pack(push, 1)\n' + cdecl, "The following new type will be created")

        if cdecl:
            structure_name = idaapi.idc_parse_decl(idaapi.cvar.idati, cdecl, idaapi.PT_TYP)[0]
            previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, structure_name)

            if previous_ordinal:
                reply = QtGui.QMessageBox.question(
                    None,
                    "HexRaysPyTools",
                    "Structure already exist. Do you want to overwrite it?",
                    QtGui.QMessageBox.Yes | QtGui.QMessageBox.No
                )
                if reply == QtGui.QMessageBox.Yes:
                    idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
                    ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl, idaapi.PT_TYP)
                else:
                    return
            else:
                ordinal = idaapi.idc_set_local_type(-1, cdecl, idaapi.PT_TYP)
            if ordinal:
                print "[Info] New type {0} was added to Local Types".format(structure_name)
                tid = idaapi.import_type(idaapi.cvar.idati, -1, structure_name)
                if tid:
                    tinfo = idaapi.create_typedef(structure_name)
                    ptr_tinfo = idaapi.tinfo_t()
                    ptr_tinfo.create_ptr(tinfo)
                    for scanned_var in self.get_unique_scanned_variables(origin):
                        scanned_var.apply_type(ptr_tinfo)
                    return tinfo
            else:
                print "[ERROR] Structure {0} probably already exist".format(structure_name)

    def have_member(self, member):
        if self.items:
            idx = bisect.bisect_left(self.items, member)
            if idx < self.rowCount():
                return self.items[idx] == member
        return False

    def have_collision(self, row):
        return self.collisions[row]

    def refresh_collisions(self):
        self.collisions = [False for _ in xrange(len(self.items))]
        if (len(self.items)) > 1:
            curr = 0
            while curr < len(self.items):
                if self.items[curr].enabled:
                    break
                curr += 1
            next = curr + 1
            while next < len(self.items):
                if self.items[next].enabled:
                    if self.items[curr].offset + self.items[curr].size > self.items[next].offset:
                        self.collisions[curr] = True
                        self.collisions[next] = True
                        if self.items[curr].offset + self.items[curr].size < self.items[next].offset + self.items[next].size:
                            curr = next
                    else:
                        curr = next
                next += 1

    def add_row(self, member):
        if not self.have_member(member):
            bisect.insort(self.items, member)
            self.refresh_collisions()
            self.modelReset.emit()

    def get_unique_scanned_variables(self, origin=0):
        scan_objects = itertools.chain.from_iterable(
            [list(item.scanned_variables) for item in self.items if item.origin == origin])
        return dict(((item.function_name, item.name), item) for item in scan_objects).values()

    def get_next_enabled(self, row):
        row += 1
        while row < self.rowCount():
            if self.items[row].enabled:
                return row
            row += 1
        return None

    def calculate_array_size(self, row):
        next_row = self.get_next_enabled(row)
        if next_row:
            return (self.items[next_row].offset - self.items[row].offset) / self.items[row].size
        return 0

    def get_recognized_shape(self, start=0, stop=-1):
        if not self.items:
            return None
        result = []
        if stop != -1:
            base = self.items[start].offset
            enabled_items = filter(lambda x: x.enabled, self.items[start:stop])
        else:
            base = 0
            enabled_items = filter(lambda x: x.enabled, self.items)
        offsets = set(map(lambda x: x.offset, enabled_items))
        if not enabled_items:
            return
        min_size = enabled_items[-1].offset + enabled_items[-1].size - base
        tinfo = idaapi.tinfo_t()
        for ordinal in xrange(1, idaapi.get_ordinal_qty(idaapi.cvar.idati)):
            tinfo.get_numbered_type(idaapi.cvar.idati, ordinal)
            if tinfo.is_udt() and tinfo.get_size() >= min_size:
                is_found = False
                for offset in offsets:
                    is_found = False
                    items = filter(lambda x: x.offset == offset, enabled_items)
                    potential_members = helper.get_fields_at_offset(tinfo, offset - base)
                    for item in items:
                        for potential_member in potential_members:
                            if item.type_equals_to(potential_member):
                                is_found = True
                                break
                        if is_found:
                            break
                    if not is_found:
                        break
                if is_found:
                    result.append((ordinal, idaapi.tinfo_t(tinfo)))
        chooser = MyChoose(
            [[str(x), "0x{0:08X}".format(y.get_size()), y.dstr()] for x, y in result],
            "Select Structure",
            [["Ordinal", 5], ["Size", 10], ["Structure name", 50]]
        )
        idx = chooser.Show(modal=True)
        if idx != -1:
            return result[idx][1]
        return None

    @staticmethod
    def get_padding_member(offset, size):
        udt_member = idaapi.udt_member_t()
        if size == 1:
            udt_member.name = "gap_{0:X}".format(offset)
            udt_member.type = const.BYTE_TINFO
            udt_member.size = const.BYTE_TINFO.get_size()
            udt_member.offset = offset
            return udt_member

        array_data = idaapi.array_type_data_t()
        array_data.base = 0
        array_data.elem_type = const.BYTE_TINFO
        array_data.nelems = size
        tmp_tinfo = idaapi.tinfo_t()
        tmp_tinfo.create_array(array_data)

        udt_member.name = "gap_{0:X}".format(offset)
        udt_member.type = tmp_tinfo
        udt_member.size = size
        udt_member.offset = offset
        return udt_member

    # SLOTS #

    def finalize(self):
        if self.pack():
            self.clear()

    def disable_rows(self, indices):
        for idx in indices:
            if self.items[idx.row()].enabled:
                self.items[idx.row()].set_enabled(False)
        self.refresh_collisions()
        self.modelReset.emit()

    def enable_rows(self, indices):
        for idx in indices:
            if not self.items[idx.row()].enabled:
                self.items[idx.row()].enabled = True
        self.refresh_collisions()
        self.modelReset.emit()

    def set_origin(self, indices):
        if indices:
            self.main_offset = self.items[indices[0].row()].offset
            self.modelReset.emit()

    def make_array(self, indices):
        if indices:
            self.items[indices[0].row()].switch_array_flag()
            self.dataChanged.emit(indices[0], indices[0])

    def pack_substructure(self, indices):
        if indices:
            indices = sorted(indices)
            self.dataChanged.emit(indices[0], indices[-1])
            start, stop = indices[0].row(), indices[-1].row() + 1
            tinfo = self.pack(start, stop)
            if tinfo:
                offset = self.items[start].offset
                self.items = self.items[0:start] + self.items[stop:]
                self.add_row(Member(offset, tinfo, None))

    def unpack_substructure(self, indices):

        if indices is None or len(indices) != 1:
            return

        item = self.items[indices[0].row()]
        if item.tinfo is not None and item.tinfo.is_udt():

            self.remove_items(indices)
            offset = item.offset
            udt_data = idaapi.udt_type_data_t()
            if item.tinfo.get_udt_details(udt_data):
                for udt_item in udt_data:
                    member = Member(offset + udt_item.offset / 8, udt_item.type, None)
                    member.name = udt_item.name
                    self.add_row(member)

    def resolve_types(self):
        current_item = None
        current_item_score = 0

        for item in self.items:
            if not item.enabled:
                continue

            if current_item is None:
                current_item = item
                current_item_score = current_item.score
                continue

            item_score = item.score
            if current_item.has_collision(item):
                if item_score <= current_item_score:
                    item.set_enabled(False)
                    continue
                elif item_score > current_item_score:
                    current_item.set_enabled(False)

            current_item = item
            current_item_score = item_score

        self.refresh_collisions()
        self.modelReset.emit()

    def remove_items(self, indices):
        rows = map(lambda x: x.row(), indices)
        if rows:
            self.items = [item for item in self.items if self.items.index(item) not in rows]
            self.modelReset.emit()

    def clear(self):
        self.items = []
        self.main_offset = 0
        self.modelReset.emit()

    def recognize_shape(self, indices):
        min_idx = max_idx = None
        if indices:
            min_idx, max_idx = min(indices), max(indices, key=lambda x: (x.row(), x.column()))

        if min_idx == max_idx:
            tinfo = self.get_recognized_shape()
            if tinfo:
                tinfo.create_ptr(tinfo)
                for scanned_var in self.get_unique_scanned_variables(origin=0):
                    scanned_var.apply_type(tinfo)
                self.clear()
        else:
            # indices = sorted(indices)
            start, stop = min_idx.row(), max_idx.row() + 1
            base = self.items[start].offset
            tinfo = self.get_recognized_shape(start, stop)
            if tinfo:
                ptr_tinfo = idaapi.tinfo_t()
                ptr_tinfo.create_ptr(tinfo)
                for scanned_var in self.get_unique_scanned_variables(base):
                    scanned_var.apply_type(ptr_tinfo)
                self.items = filter(lambda x: x.offset < base or x.offset >= base + tinfo.get_size(), self.items)
                self.add_row(Member(base, tinfo, None))

    def activated(self, index):
        # Double click on offset, opens window with variables
        if index.column() == 0:
            item = self.items[index.row()]
            scanned_variables = list(item.scanned_variables)
            variable_chooser = MyChoose(
                map(lambda x: x.to_list(), scanned_variables),
                "Select Variable",
                [["Origin", 4], ["Function name", 25], ["Variable name", 25], ["Expression address", 10]]
            )
            row = variable_chooser.Show(modal=True)
            if row != -1:
                idaapi.open_pseudocode(scanned_variables[row].expression_address, 0)

        # Double click on type. If type is virtual table than opens windows with virtual methods
        elif index.column() == 1:
            self.items[index.row()].activate()
