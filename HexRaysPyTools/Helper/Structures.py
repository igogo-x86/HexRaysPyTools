import sys
import bisect
import idaapi
import re
import PySide.QtGui as QtGui
import PySide.QtCore as QtCore


EA64 = idaapi.cvar.inf.is_64bit()   # get_inf ...
EA_SIZE = 8 if EA64 else 4
LEGAL_TYPES = ("_DWORD *", "int", "void *")
BYTE_TINFO = idaapi.tinfo_t(idaapi.BTF_BYTE)


def parse_vtable_name(name):
    if name[0:3] == 'off':
        # off_XXXXXXXX case
        return "Vtable" + name[3:]
    m = re.search(' (\w+)::', name)
    if m:
        # const class_name:`vftable' case
        return "Vtable_" + m.group(1)
    return name


def get_padding_member(offset, size):
    array_data = idaapi.array_type_data_t()
    array_data.base = 0
    array_data.elem_type = BYTE_TINFO
    array_data.nelems = size
    tmp_tinfo = idaapi.tinfo_t()
    tmp_tinfo.create_array(array_data)

    udt_member = idaapi.udt_member_t()
    udt_member.name = "gap_{0:X}".format(offset)
    udt_member.type = tmp_tinfo
    udt_member.size = size
    udt_member.offset = offset
    return udt_member


class VirtualFunction:
    def __init__(self, address, type):
        self.address = address
        self.type = type


class VirtualTable:
    def __init__(self, address):
        self.address = address
        self.virtual_functions_ea = []
        self.name = parse_vtable_name(idaapi.get_short_name(address))
        self.populate()
        self.tinfo = self.create_tinfo()

    def populate(self):
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
        print "[Virtual table] at address: {0:#010X} name: {1}".format(self.address, self.name)
        offset = 0
        udt_data = idaapi.udt_type_data_t()
        for address in self.virtual_functions_ea:
            decompiled_function = idaapi.decompile(address)
            if decompiled_function:
                guessed_type = idaapi.tinfo_t()
                get_type = idaapi.tinfo_t()
                # if idaapi.guess_tinfo2(address, guessed_type) == idaapi.GUESS_FUNC_OK | idaapi.GUESS_FUNC_OK:
                idaapi.guess_tinfo2(address, guessed_type)
                idaapi.get_tinfo2(address, get_type)
                print "[Virtual function] at address: {0:#010X} name: {1} type: {2} guessed type: {3} get type: {4}".format(
                    address,
                    idaapi.get_short_name(address),
                    decompiled_function.type.dstr(),
                    guessed_type.dstr(),
                    get_type.dstr()
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

                print "[Member] name: {0} type: {1} offset: {2} size: {3}".format(
                    udt_member.name,
                    udt_member.type.dstr(),
                    udt_member.offset,
                    udt_member.size
                )

                udt_data.push_back(udt_member)

            offset += EA_SIZE

        final_tinfo = idaapi.tinfo_t()
        print "udt size = " + str(udt_data.size())
        print final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        # print final_tinfo.create_typedef(idaapi.cvar.idati, idaapi.get_short_name(self.address))
        print final_tinfo.get_size()
        print "[Final structure]\n" + idaapi.print_tinfo(None, 4, 5, 0x2F, final_tinfo, 'igogo_vtable', None)
        return final_tinfo

    def import_to_structures(self):
        """
        Imports virtual tables and returns tid_t of new structure

        :return: idaapi.tid_t
        """
        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, 0x2F, self.tinfo, self.name, None)
        # if idaapi.parse_decl2(idaapi.cvar.idati, cdecl_typedef, self.name)
        ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)
        if ordinal:
            print "[Info] Virtual table " + self.name + " added to Local Types"
            tid = idaapi.import_type(idaapi.cvar.idati, -1, self.name)
        else:
            print "[Warning] Virtual table " + self.name + " probably already exist"

    def __str__(self):
        pass


class Field:
    def __init__(self, offset, tinfo=None, virtual_table=None):
        self.offset = offset
        if virtual_table:
            tmp_tinfo = idaapi.tinfo_t()
            tmp_tinfo.create_ptr(virtual_table.tinfo)
            self.type = tmp_tinfo
            self.name = "vtable"
        else:
            self.type = tinfo
            self.name = "field_{0:x}".format(self.offset)
        self.virtual_table = virtual_table
        self.enabled = True

    def get_udt_member(self):
        udt_member = idaapi.udt_member_t()
        if self.virtual_table:
            tid = self.virtual_table.import_to_structures()
            if tid != idaapi.BADADDR:
                udt_member.name = self.name
                tmp_tinfo = idaapi.create_typedef(self.virtual_table.name)
                tmp_tinfo.create_ptr(tmp_tinfo)
                udt_member.type = tmp_tinfo
                udt_member.offset = self.offset
                udt_member.size = EA_SIZE
        else:
            udt_member.name = self.name
            udt_member.type = self.type
            udt_member.offset = self.offset
            udt_member.size = self.type.get_size()
        return udt_member

    @property
    def type_name(self):
        if self.virtual_table:
            return self.virtual_table.name + ' *'
        return self.type.dstr()

    __eq__ = lambda self, other: self.offset == other.offset and self.type_name == other.type_name
    __ne__ = lambda self, other: self.offset != other.offset or self.type_name != other.type_name
    __lt__ = lambda self, other: self.offset < other.offset or (self.offset == other.offset and self.type_name < other.type_name)
    __le__ = lambda self, other: self.offset <= other.offset
    __gt__ = lambda self, other: self.offset > other.offset or (self.offset == other.offset and self.type_name > other.type_name)
    __ge__ = lambda self, other: self.offset >= other.offset


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
        self.structure_name = "CHANGE_MY_NAME"

        # OVERLOADED METHODS #

    def rowCount(self, *args):
        return len(self.items)

    def columnCount(self, *args):
        return len(self.headers)

    def data(self, index, role):
        row, col = index.row(), index.column()
        if role == QtCore.Qt.DisplayRole:
            if index.column() == 0:
                return "{0:#010x}".format(self.items[row].offset)
            elif index.column() == 1:
                return self.items[row].type_name
            elif index.column() == 2:
                return self.items[row].name
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

    def add_row(self, member):
        if not self.have_member(member):
            bisect.insort(self.items, member)
            self.modelReset.emit()

    def have_collision(self, row):
        if not self.items[row].enabled:
            return False
        left_neighbour = row - 1
        right_neighbour = row + 1
        while left_neighbour >= 0 and not self.items[left_neighbour].enabled:
            left_neighbour -= 1
        while right_neighbour < self.rowCount() and not self.items[right_neighbour].enabled:
            right_neighbour += 1
        if left_neighbour >= 0:
            if self.items[row].offset < self.items[left_neighbour].offset + self.items[left_neighbour].type.get_size():
                return True
        if right_neighbour != self.rowCount():
            if self.items[row].offset + self.items[row].type.get_size() > self.items[right_neighbour].offset:
                return True
        return False

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
                udt_data.push_back(get_padding_member(offset, gap_size))
            udt_data.push_back(item.get_udt_member())
            offset = item.offset + item.type.get_size()

        final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        cdecl = idaapi.print_tinfo(None, 4, 5, 0x2F, final_tinfo, self.structure_name, None)
        cdecl = idaapi.asktext(idaapi.MAXSTR, cdecl, "The following new type will be created")

        if cdecl:
            structure_name = idaapi.idc_parse_decl(idaapi.cvar.idati, cdecl, idaapi.PT_TYP)[0]
            ordinal = idaapi.idc_set_local_type(-1, cdecl, idaapi.PT_TYP)
            if ordinal:
                print "[Info] New type {0} was added to Local Types".format(structure_name)
                tid = idaapi.import_type(idaapi.cvar.idati, -1, structure_name)
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
