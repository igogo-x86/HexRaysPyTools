import bisect
import idc
import idaapi
import re
import PySide.QtCore as QtCore
import PySide.QtGui as QtGui
import HexRaysPyTools.Core.Const as Const

from HexRaysPyTools.Forms import MyChoose


def parse_vtable_name(name):
    if name[0:3] == 'off':
        # off_XXXXXXXX case
        return "Vtable" + name[3:], False
    m = re.search(' (\w+)::', name)
    if m:
        # const class_name:`vftable' case
        return "Vtable_" + m.group(1), True
    return name, True


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
        self.scanned_variable = scanned_variable
        self.tinfo = None

    def type_equals_to(self, tinfo):
        return self.tinfo.equals_to(tinfo)

    def switch_array_flag(self):
        self.is_array ^= True

    def activate(self):
        pass

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        return self.tinfo.get_size()

    @property
    def font(self):
        return None

    def __repr__(self):
        return hex(self.offset) + ' ' + self.type_name

    __eq__ = lambda self, other: self.offset == other.offset and self.type_name == other.type_name
    __ne__ = lambda self, other: self.offset != other.offset or self.type_name != other.type_name
    __lt__ = lambda self, other: self.offset < other.offset or \
                                 (self.offset == other.offset and self.type_name < other.type_name)
    __le__ = lambda self, other: self.offset <= other.offset
    __gt__ = lambda self, other: self.offset > other.offset or \
                                 (self.offset == other.offset and self.type_name < other.type_name)
    __ge__ = lambda self, other: self.offset >= other.offset


class VirtualFunction:
    def __init__(self, address, offset, tinfo=None):
        self.address = address
        self.offset = offset
        self.visited = False
        if tinfo:
            self.tinfo = tinfo
        else:
            decompiled_function = idaapi.decompile(self.address)
            if decompiled_function:
                self.tinfo = idaapi.tinfo_t(decompiled_function.type)
            else:
                print "[ERROR] Failed to decompile function at 0x{0:08X}".format(self.address)

    def __int__(self):
        return self.address

    def get_ptr_tinfo(self):
        ptr_tinfo = idaapi.tinfo_t()
        ptr_tinfo.create_ptr(self.tinfo)
        return ptr_tinfo

    def get_udt_member(self):
        udt_member = idaapi.udt_member_t()
        udt_member.type = self.get_ptr_tinfo()
        udt_member.offset = self.offset
        udt_member.name = self.name
        udt_member.size = Const.EA_SIZE
        return udt_member

    def get_information(self):
        return ["0x{0:08X}".format(self.address), self.name, self.tinfo.dstr()]

    @property
    def name(self):
        name = idaapi.get_short_name(self.address)
        name = name.split('(')[0]
        name = name.replace("`", '').replace(" ", '_').replace("'", '')
        return name


class VirtualTable(AbstractMember):
    def __init__(self, offset, address, scanned_variable=None, origin=0):
        AbstractMember.__init__(self, offset + origin, scanned_variable, origin)
        self.address = address
        self.virtual_functions = []
        self.name = "vtable"
        self.vtable_name, self.have_nice_name = parse_vtable_name(idaapi.get_short_name(address))
        self.populate()
        self.tinfo = self.create_tinfo()

    def populate(self):
        # TODO: Check if address of virtual function is in code section and then try to make function
        address = self.address
        while True:
            if Const.EA64:
                func_address = idaapi.get_64bit(address)
            else:
                func_address = idaapi.get_32bit(address)
            flags = idaapi.getFlags(func_address)  # flags_t
            if idaapi.isCode(flags):
                self.virtual_functions.append(VirtualFunction(func_address, address - self.address))
                address += Const.EA_SIZE
            else:
                break

    def create_tinfo(self):
        # print "(Virtual table) at address: 0x{0:08X} name: {1}".format(self.address, self.name)
        udt_data = idaapi.udt_type_data_t()
        for function in self.virtual_functions:
            udt_data.push_back(function.get_udt_member())

        final_tinfo = idaapi.tinfo_t()
        if final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT):
            # print "\n\t(Final structure)\n" + idaapi.print_tinfo('\t', 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE
            #                                                      | idaapi.PRTYPE_SEMI, final_tinfo, self.name, None)
            return final_tinfo
        else:
            print "[ERROR] Virtual table creation failed"

    def import_to_structures(self, ask=False):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                           self.tinfo, self.vtable_name, None)
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
            print "[Warning] Virtual table " + self.vtable_name + " probably already exist"

    def show_virtual_functions(self):
        function_chooser = MyChoose(
            [function.get_information() for function in self.virtual_functions],
            "Select Virtual Function",
            [["Address", 10], ["Name", 15], ["Declaration", 45]],
            13
        )
        function_chooser.OnGetIcon = lambda n: 32 if self.virtual_functions[n].visited else 160
        function_chooser.OnGetLineAttr = \
            lambda n: [0xd9d9d9, 0x0] if self.virtual_functions[n].visited else [0xffffff, 0x0]

        idx = function_chooser.Show(True)
        if idx != -1:
            self.virtual_functions[idx].visited = True
            idaapi.open_pseudocode(int(self.virtual_functions[idx]), 1)

    def get_udt_member(self, offset=0):
        udt_member = idaapi.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name
            tmp_tinfo = idaapi.create_typedef(self.vtable_name)
            tmp_tinfo.create_ptr(tmp_tinfo)
            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset - offset
            udt_member.size = Const.EA_SIZE
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
        functions_count = 0
        while True:
            func_address = idaapi.get_64bit(address) if Const.EA64 else idaapi.get_32bit(address)
            flags = idaapi.getFlags(func_address)  # flags_t
            # print "[INFO] Address 0x{0:08X}".format(func_address)
            if idaapi.isCode(flags):
                functions_count += 1
                address += Const.EA_SIZE
            else:
                segment = idaapi.getseg(func_address)
                if segment and segment.perm & idaapi.SEGPERM_EXEC:
                    idc.MakeUnknown(func_address, 1, idaapi.DOUNK_SIMPLE)
                    if idc.MakeFunction(func_address):
                        functions_count += 1
                        address += Const.EA_SIZE
                        continue
                break
            idaapi.autoWait()
        return functions_count >= 2

    @property
    def type_name(self):
        return self.vtable_name + " *"

    @property
    def font(self):
        return QtGui.QFont("Consolas", 10, QtGui.QFont.Bold)

    @property
    def size(self):
        return Const.EA_SIZE


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


class VoidMember(Member):
    def __init__(self, offset, scanned_variable, origin=0):
        Member.__init__(self, offset, Const.BYTE_TINFO, scanned_variable, origin)
        self.is_array = True

    def type_equals_to(self, tinfo):
        return True

    def switch_array_flag(self):
        pass

    @property
    def font(self):
        return QtGui.QFont("Consolas", 10, italic=True)


class ScannedVariable:
    def __init__(self, function, variable):
        """
        Class for storing variable and it's function that have been scanned previously.
        Need to think whether it's better to store address and index, or cfunc_t and lvar_t

        :param function: idaapi.cfunc_t
        :param variable: idaapi.vdui_t
        """
        self.function = function
        self.lvar = variable

    def apply_type(self, tinfo):
        """
        Finally apply Class'es tinfo to this variable

        :param tinfo: idaapi.tinfo_t
        """
        hx_view = idaapi.open_pseudocode(self.function.entry_ea, -1)
        if hx_view:
            print "[Info] Applying tinfo to variable {0} in function {1}".format(
                self.lvar.name,
                idaapi.get_short_name(self.function.entry_ea)
            )
            # Finding lvar of new window that have the same name that saved one and applying tinfo_t
            lvar = filter(lambda x: x == self.lvar, hx_view.cfunc.get_lvars())
            if lvar:
                print "+++++++++++"
                hx_view.set_lvar_type(lvar[0], tinfo)
            else:
                print "-----------"
            # idaapi.close_pseudocode(hx_view.form)
        else:
            print "[Warning] Failed to apply type"

    def __eq__(self, other):
        return self.function.entry_ea == other.function.entry_ea and self.lvar == other.lvar

    def __hash__(self):
        return hash((self.function.entry_ea, self.lvar.name))


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
            if col == 1:
                return self.items[row].size * (self.calculate_array_size(row) if self.items[row].is_array else 1)
        elif role == QtCore.Qt.EditRole:
            if col == 2:
                return self.items[row].name
        elif role == QtCore.Qt.FontRole:
            if col == 1:
                return item.font
        elif role == QtCore.Qt.BackgroundColorRole:
            if not item.enabled:
                return QtGui.QColor(QtCore.Qt.gray)
            if item.offset == self.main_offset:
                if col == 0:
                    return QtGui.QBrush(QtGui.QColor("#ff8080"))
            if self.have_collision(row):
                return QtGui.QBrush(QtGui.QColor("#ffff99"))

    def setData(self, index, value, role):
        row, col = index.row(), index.column()
        if role == QtCore.Qt.EditRole:
            self.items[row].name = str(value)
            self.dataChanged.emit(index, index)
            return True
        return False

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]

    # HELPER METHODS #

    def pack(self, start=0, stop=None):
        if self.collisions[start:stop].count(True):
            print "[Warning] Collisions detected"
            return

        final_tinfo = idaapi.tinfo_t()
        udt_data = idaapi.udt_type_data_t()
        origin = self.items[start].offset
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
        cdecl = idaapi.asktext(0x10000, cdecl, "The following new type will be created")

        if cdecl:
            structure_name = idaapi.idc_parse_decl(idaapi.cvar.idati, cdecl, idaapi.PT_TYP)[0]
            ordinal = idaapi.idc_set_local_type(-1, cdecl, idaapi.PT_TYP)
            if ordinal:
                print "[Info] New type {0} was added to Local Types".format(structure_name)
                tid = idaapi.import_type(idaapi.cvar.idati, -1, structure_name)
                if tid:
                    tinfo = idaapi.create_typedef(structure_name)
                    ptr_tinfo = idaapi.tinfo_t()
                    ptr_tinfo.create_ptr(tinfo)
                    for scanned_var in self.get_scanned_variables(origin):
                        scanned_var.apply_type(ptr_tinfo)
                    return tinfo
            else:
                print "[ERROR] Structure {0} probably already exist".format(structure_name)
        return None

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

    def get_scanned_variables(self, origin=0):
        return set(
            map(lambda x: x.scanned_variable, filter(lambda x: x.scanned_variable and x.origin == origin, self.items))
        )

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
                    potential_members = self.get_fields_at_offset(tinfo, offset - base)
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

    def get_fields_at_offset(self, tinfo, offset):
        result = []
        if offset == 0:
            result.append(tinfo)
        udt_data = idaapi.udt_type_data_t()
        tinfo.get_udt_details(udt_data)
        udt_member = idaapi.udt_member_t()
        udt_member.offset = offset * 8
        idx = tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        if idx != -1:
            while idx < tinfo.get_udt_nmembers() and udt_data[idx].offset <= offset * 8:
                udt_member = udt_data[idx]
                if udt_member.offset == offset * 8:
                    if udt_member.type.is_ptr():
                        result.append(idaapi.get_unk_type(Const.EA_SIZE))
                        result.append(udt_member.type)
                        result.append(idaapi.dummy_ptrtype(Const.EA_SIZE, False))
                    elif not udt_member.type.is_udt():
                        result.append(udt_member.type)
                if udt_member.type.is_array():
                    if (offset - udt_member.offset / 8) % udt_member.type.get_array_element().get_size() == 0:
                        result.append(udt_member.type.get_array_element())
                elif udt_member.type.is_udt():
                    result.extend(self.get_fields_at_offset(udt_member.type, offset - udt_member.offset / 8))
                idx += 1
        return result

    @staticmethod
    def get_padding_member(offset, size):
        udt_member = idaapi.udt_member_t()
        if size == 1:
            udt_member.name = "gap_{0:X}".format(offset)
            udt_member.type = Const.BYTE_TINFO
            udt_member.size = Const.BYTE_TINFO.get_size()
            udt_member.offset = offset
            return udt_member

        array_data = idaapi.array_type_data_t()
        array_data.base = 0
        array_data.elem_type = Const.BYTE_TINFO
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
                self.items[idx.row()].enabled = False
                self.items[idx.row()].is_array = False
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
            self.dataChanged.emit(min_idx, max_idx)

        if min_idx == max_idx:
            tinfo = self.get_recognized_shape()
            if tinfo:
                tinfo.create_ptr(tinfo)
                for scanned_var in self.get_scanned_variables(0):
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
                for scanned_var in self.get_scanned_variables(base):
                    scanned_var.apply_type(ptr_tinfo)
                self.items = filter(lambda x: x.offset < base or x.offset >= base + tinfo.get_size(), self.items)
                self.add_row(Member(base, tinfo, None))

    def show_virtual_methods(self, index):
        self.dataChanged.emit(index, index)

        if index.column() == 1:
            self.items[index.row()].activate()
