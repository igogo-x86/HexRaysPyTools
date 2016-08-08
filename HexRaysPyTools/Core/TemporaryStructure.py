import bisect
import idc
import idaapi
import re
import PySide.QtCore as QtCore
import PySide.QtGui as QtGui

EA64 = idc.__EA64__
EA_SIZE = 8 if EA64 else 4
LEGAL_TYPES = ("_DWORD *", "int", "__int64", "signed __int64", "void *")


def parse_vtable_name(name):
    if name[0:3] == 'off':
        # off_XXXXXXXX case
        return "Vtable" + name[3:], False
    m = re.search(' (\w+)::', name)
    if m:
        # const class_name:`vftable' case
        return "Vtable_" + m.group(1), True
    return name, True


class AbstractField:
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
        self.scanned_variable = scanned_variable

    @property
    def type_name(self):
        pass

    __eq__ = lambda self, other: self.offset == other.offset and self.type_name == other.type_name
    __ne__ = lambda self, other: self.offset != other.offset or self.type_name != other.type_name
    __lt__ = lambda self, other: self.offset < other.offset or (self.offset == other.offset and self.type_name < other.type_name)
    __le__ = lambda self, other: self.offset <= other.offset
    __gt__ = lambda self, other: self.offset > other.offset or (self.offset == other.offset and self.type_name > other.type_name)
    __ge__ = lambda self, other: self.offset >= other.offset


class VirtualTable(AbstractField):
    def __init__(self, offset, address, scanned_variable, origin=0):
        AbstractField.__init__(self, offset + origin, scanned_variable, origin)
        self.address = address
        self.virtual_functions_ea = []
        self.name = "vtable"
        self.vtable_name, self.have_nice_name = parse_vtable_name(idaapi.get_short_name(address))
        self.populate()
        self.tinfo = self.create_tinfo()

    def populate(self):
        # TODO: Check if address of virtual function is in code section and then try to make function
        address = self.address
        while True:
            if EA64:
                func_address = idaapi.get_64bit(address)
            else:
                func_address = idaapi.get_32bit(address)
            flags = idaapi.getFlags(func_address)  # flags_t
            if idaapi.isCode(flags):
                self.virtual_functions_ea.append(func_address)
                address += EA_SIZE
            else:
                break

    def create_tinfo(self):
        print "(Virtual table) at address: {0:#010X} name: {1}".format(self.address, self.name)
        offset = 0
        udt_data = idaapi.udt_type_data_t()
        for address in self.virtual_functions_ea:
            decompiled_function = idaapi.decompile(address)
            print decompiled_function
            if decompiled_function:
                guessed_type = idaapi.tinfo_t()
                get_type = idaapi.tinfo_t()
                idaapi.guess_tinfo2(address, guessed_type)
                idaapi.get_tinfo2(address, get_type)
                print "\t(Virtual function) at address: {0:#010X} name: {1} type:".format(
                    address,
                    idaapi.get_short_name(address),
                    decompiled_function.type.dstr()
                )

                # continue

                udt_member = idaapi.udt_member_t()
                udt_member.type = idaapi.tinfo_t()
                tmp_tinfo = idaapi.tinfo_t(decompiled_function.type)
                tmp_tinfo.create_ptr(tmp_tinfo)
                udt_member.type = tmp_tinfo
                udt_member.offset = offset
                udt_member.name = idaapi.get_short_name(address)
                udt_member.size = EA_SIZE

                udt_data.push_back(udt_member)

            offset += EA_SIZE

        final_tinfo = idaapi.tinfo_t()
        if final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT):
            print "\n\t(Final structure)\n" + idaapi.print_tinfo('\t', 4, 5, 0x2F, final_tinfo, self.name, None)
            return final_tinfo
        else:
            print "[ERROR] Virtual table creation failed"

    def import_to_structures(self, ask=False):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x2F, self.tinfo, self.vtable_name, None)
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

    def get_udt_member(self):
        udt_member = idaapi.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name
            tmp_tinfo = idaapi.create_typedef(self.vtable_name)
            tmp_tinfo.create_ptr(tmp_tinfo)
            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset
            udt_member.size = EA_SIZE
        return udt_member

    @staticmethod
    def check_address(address):
        # Checks if given address contains virtual table. Returns True if more than 2 function pointers found
        functions_count = 0
        while True:
            if EA64:
                func_address = idaapi.get_64bit(address)
            else:
                func_address = idaapi.get_32bit(address)
            flags = idaapi.getFlags(func_address)  # flags_t
            if idaapi.isCode(flags):
                functions_count += 1
                address += EA_SIZE
            else:
                break
        return functions_count >= 2

    @staticmethod
    def is_vtable(): return True

    @property
    def type_name(self):
        return self.vtable_name + " *"

    @property
    def size(self):
        return EA_SIZE


class Field(AbstractField):
    def __init__(self, offset, tinfo, scanned_variable, origin=0):
        AbstractField.__init__(self, offset + origin, scanned_variable, origin)
        self.tinfo = tinfo
        self.name = "field_{0:X}".format(self.offset)

    def get_udt_member(self):
        udt_member = idaapi.udt_member_t()
        udt_member.name = self.name
        udt_member.type = self.tinfo
        udt_member.offset = self.offset
        udt_member.size = self.size
        return udt_member

    @staticmethod
    def is_vtable(): return False

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        return self.tinfo.get_size()


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
            lvar = filter(lambda x: x.name == self.lvar.name, hx_view.cfunc.get_lvars())[0]
            hx_view.set_lvar_type(lvar, tinfo)
            # idaapi.close_pseudocode(hx_view.form)
        else:
            print "[Warning] Failed to apply type"

    def __eq__(self, other):
        return self.function.entry_ea == other.function.entry_ea and self.lvar.name == other.lvar.name

    def __hash__(self):
        return hash((self.function.entry_ea, self.lvar.name))


class TemporaryStructureModel(QtCore.QAbstractTableModel):
    BYTE_TINFO = None

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
        self.structure_name = "CHANGE_MY_NAME"
        TemporaryStructureModel.BYTE_TINFO = idaapi.tinfo_t(idaapi.BTF_BYTE)

    # OVERLOADED METHODS #

    def rowCount(self, *args):
        return len(self.items)

    def columnCount(self, *args):
        return len(self.headers)

    def data(self, index, role):
        row, col = index.row(), index.column()
        if role == QtCore.Qt.DisplayRole:
            if col == 0:
                return "{0:#010X}".format(self.items[row].offset)
            elif col == 1:
                return self.items[row].type_name
            elif col == 2:
                return self.items[row].name
        elif role == QtCore.Qt.FontRole:
            if col == 1 and self.items[row].is_vtable():
                return QtGui.QFont("Consolas", 10, QtGui.QFont.Bold)
        elif role == QtCore.Qt.BackgroundColorRole:
            if not self.items[row].enabled:
                return QtGui.QColor(QtCore.Qt.gray)
            if self.items[row].offset == self.main_offset:
                if col == 0:
                    return QtGui.QBrush(QtGui.QColor("#ff8080"))
            if self.have_collision(row):
                return QtGui.QBrush(QtGui.QColor("#ffff99"))

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]

    # HELPER METHODS #

    def have_member(self, member):
        if self.items:
            idx = bisect.bisect_left(self.items, member)
            if idx < self.rowCount():
                return self.items[bisect.bisect_left(self.items, member)] == member
        return False

    def have_collision(self, row):
        if not self.items[row].enabled:
            return False
        left_neighbour = row - 1
        right_neighbour = row + 1
        while left_neighbour >= 0 and not self.items[left_neighbour].enabled:
            left_neighbour -= 1
        if left_neighbour >= 0:
            if self.items[row].offset < self.items[left_neighbour].offset + self.items[left_neighbour].size:
                return True
        while right_neighbour < self.rowCount() and not self.items[right_neighbour].enabled:
            right_neighbour += 1
        if right_neighbour != self.rowCount():
            if self.items[row].offset + self.items[row].size > self.items[right_neighbour].offset:
                return True
        return False

    def add_row(self, member):
        if not self.have_member(member):
            bisect.insort(self.items, member)
            self.modelReset.emit()

    def get_scanned_variables(self, ordinal=0):
        return set(map(lambda x: x.scanned_variable, self.items))

    @staticmethod
    def get_padding_member(offset, size):
        udt_member = idaapi.udt_member_t()
        if size == 1:
            udt_member.name = "gap_{0:X}".format(offset)
            udt_member.type = TemporaryStructureModel.BYTE_TINFO
            udt_member.size = TemporaryStructureModel.BYTE_TINFO.get_size()
            udt_member.offset = offset
            return udt_member

        array_data = idaapi.array_type_data_t()
        array_data.base = 0
        array_data.elem_type = TemporaryStructureModel.BYTE_TINFO
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
        for row in xrange(self.rowCount()):
            if self.have_collision(row):
                print "[Warning] Collisions detected"
                return

        final_tinfo = idaapi.tinfo_t()
        udt_data = idaapi.udt_type_data_t()
        offset = 0

        for item in filter(lambda x: x.enabled, self.items):    # Filter disabled members
            gap_size = item.offset - offset
            if gap_size:
                udt_data.push_back(TemporaryStructureModel.get_padding_member(offset, gap_size))
            udt_data.push_back(item.get_udt_member())
            offset = item.offset + item.size

        final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        cdecl = idaapi.print_tinfo(None, 4, 5, 0x2F, final_tinfo, self.structure_name, None)
        cdecl = idaapi.asktext(0x10000, cdecl, "The following new type will be created")

        if cdecl:
            structure_name = idaapi.idc_parse_decl(idaapi.cvar.idati, cdecl, idaapi.PT_TYP)[0]
            ordinal = idaapi.idc_set_local_type(-1, cdecl, idaapi.PT_TYP)
            if ordinal:
                print "[Info] New type {0} was added to Local Types".format(structure_name)
                tid = idaapi.import_type(idaapi.cvar.idati, -1, structure_name)
                if tid:
                    tinfo = idaapi.create_typedef(structure_name)
                    tinfo.create_ptr(tinfo)
                    for scanned_var in self.get_scanned_variables():
                        scanned_var.apply_type(tinfo)
                self.clear()
            else:
                print "[ERROR] Structure {0} probably already exist".format(structure_name)

    def disable_rows(self, indices):
        for idx in indices:
            if self.items[idx.row()].enabled:
                self.items[idx.row()].enabled = False
        self.modelReset.emit()

    def enable_rows(self, indices):
        for idx in indices:
            if not self.items[idx.row()].enabled:
                self.items[idx.row()].enabled = True
        self.modelReset.emit()

    def set_origin(self, indices):
        if indices:
            self.main_offset = self.items[indices[0].row()].offset
            self.modelReset.emit()

    def make_array(self, indices):
        pass

    def pack_substruct(self, indices):
        pass

    def remove_item(self, indices):
        rows = map(lambda x: x.row(), indices)
        if rows:
            self.items = [item for item in self.items if self.items.index(item) not in rows]
            self.modelReset.emit()

    def clear(self):
        self.items = []
        self.main_offset = 0
        self.modelReset.emit()
