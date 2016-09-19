import idc
import idaapi
import Helper

from PySide import QtGui, QtCore

all_virtual_functions = {}      # name    -> VirtualMethod
all_virtual_tables = {}         # ordinal -> VirtualTable


class VirtualMethod(object):
    def __init__(self, tinfo, name, parent):
        self.tinfo = tinfo
        self.tinfo_modified = False
        self.name = name
        self.name_modified = False
        self.parents = [parent]
        self.base_address = idc.LocByName(name)
        self.base_address = self.base_address - idaapi.get_imagebase() if self.base_address != idaapi.BADADDR else None

        self.rowcount = 0
        self.children = []

    @staticmethod
    def create(tinfo, name, parent):
        result = all_virtual_functions.get(name)
        if result:
            result.parents.append(parent)
            return result
        result = VirtualMethod(tinfo, name, parent)
        all_virtual_functions[name] = result
        return result

    def update(self, name, tinfo):
        self.name = name
        self.tinfo = tinfo
        self.name_modified = False
        self.tinfo_modified = False

        self.base_address = idc.LocByName(self.name)
        if self.base_address != idaapi.BADADDR:
            self.base_address -= idaapi.get_imagebase()

    def data(self, column):
        if column == 0:
            return self.name
        elif column == 1:
            return self.tinfo.dstr()
        elif column == 2:
            return "0x{0:08X}".format(self.address) if self.address else None

    def setData(self, column, value):
        if column == 0:
            if idaapi.isident(value) and self.name != value:
                self.name = value
                self.name_modified = True
                for parent in self.parents:
                    parent.modified = True
                return True
        elif column == 1:
            pass
        return False

    def font(self, column):
        if column == 0 and self.name_modified:
            return QtGui.QFont("Consolas", 10, italic=True)
        elif column == 1 and self.tinfo_modified:
            return QtGui.QFont("Consolas", 10, italic=True)
        return QtGui.QFont("Consolas", 10, 0)

    def flags(self, column):
        if column == 2:
            return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled
        else:
            return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsEditable

    @property
    def color(self):
        # return QtGui.QBrush(QtGui.QColor("#ffffb3"))
        return QtGui.QColor("#fefbd8")

    @property
    def tooltip(self):
        return None

    @property
    def address(self):
        return self.base_address + idaapi.get_imagebase() if self.base_address else None

    def set_first_argument_type(self):
        func_data = idaapi.func_type_data_t()
        if self.tinfo.get_func_details(func_data) and self.tinfo.get_nargs():
            if len(self.parents) > 1:
                print "[Info] Function {0} have more than one parent. Please set first argument manually".format(
                    self.name
                )
                return
            tinfo = self.parents[0].get_class_tinfo()
            tinfo.create_ptr(tinfo)
            func_data[0].type = tinfo
            self.tinfo.create_func(func_data)
            self.tinfo_modified = True

    def open_function(self):
        if self.address:
            if idaapi.decompile(self.address):
                idaapi.open_pseudocode(self.address, 0)
            else:
                idaapi.jumpto(self.address)

    def commit(self):
        if self.name_modified:
            self.name_modified = False
            if self.address:
                idaapi.set_name(self.address, self.name)
        if self.tinfo_modified:
            self.tinfo_modified = False
            if self.address:
                idaapi.set_tinfo2(self.address, self.tinfo)

    def __eq__(self, other):
        return self.address == other.address

    def __repr__(self):
        return self.name


class VirtualTable(object):
    def __init__(self, ordinal, tinfo, class_):
        self.ordinal = ordinal
        self.tinfo = tinfo
        self.class_ = [class_]
        self.virtual_functions = []
        self.name = self.tinfo.dstr()
        self._modified = False

    def update(self):
        if self.modified:
            vtable_tinfo = idaapi.tinfo_t()
            udt_data = idaapi.udt_type_data_t()
            vtable_tinfo.get_numbered_type(idaapi.cvar.idati, self.ordinal)
            vtable_tinfo.get_udt_details(udt_data)
            self.tinfo = vtable_tinfo
            self.name = vtable_tinfo.dstr()
            self.modified = False
            if len(self.virtual_functions) == len(udt_data):
                for current_function, other_function in zip(self.virtual_functions, udt_data):
                    current_function.update(other_function.name, other_function.type)
            else:
                print "[ERROR] Something have been modified in Local types. Please refresh this view"

    def update_local_type(self):
        if self.modified:
            final_tinfo = idaapi.tinfo_t()
            udt_data = idaapi.udt_type_data_t()
            self.tinfo.get_udt_details(udt_data)
            if len(udt_data) == len(self.virtual_functions):
                for udt_member, virtual_function in zip(udt_data, self.virtual_functions):
                    udt_member.name = virtual_function.name
                    udt_member.type = virtual_function.tinfo
                    virtual_function.commit()
                final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
                final_tinfo.set_numbered_type(idaapi.cvar.idati, self.ordinal, idaapi.NTF_REPLACE, self.name)
                self.modified = False
            else:
                print "[ERROR] Something have been modified in Local types. Please refresh this view"

    @property
    def modified(self):
        return self._modified

    @modified.setter
    def modified(self, value):
        self._modified = value
        if value:
            for class_ in self.class_:
                class_.modified = True

    @staticmethod
    def create(tinfo, class_):
        ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, tinfo.dstr())
        result = all_virtual_tables.get(ordinal)
        if result:
            result.class_.append(class_)
        else:
            udt_data = idaapi.udt_type_data_t()
            tinfo.get_udt_details(udt_data)
            result = VirtualTable(ordinal, tinfo, class_)
            virtual_functions = [VirtualMethod.create(func.type, func.name, result) for func in udt_data]
            result.virtual_functions = virtual_functions
            all_virtual_functions[ordinal] = result
        return result

    def get_class_tinfo(self):
        if len(self.class_) == 1:
            return self.class_.tinfo

    def setData(self, column, value):
        if column == 0:
            if idaapi.isident(value) and self.name != value:
                self.name = value
                self.modified = True
                return True
        return False

    def data(self, column):
        if column == 0:
            return self.name

    @property
    def color(self):
        return QtGui.QColor("#d5f4e6")

    @property
    def tooltip(self):
        pass

    def font(self, column):
        if self.modified:
            return QtGui.QFont("Consolas", 12, italic=True)
        return QtGui.QFont("Consolas", 12)

    def flags(self, column):
        if column == 0:
            return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEditable | QtCore.Qt.ItemIsEnabled
        return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled

    @property
    def children(self):
        return self.virtual_functions

    def __repr__(self):
        return str(self.virtual_functions)


class Class(object):
    def __init__(self, name, tinfo, ordinal):
        self.name = name
        self.ordinal = ordinal
        self.parent = None
        self.vtables = {}
        self.modified = False

    @staticmethod
    def create_class(ordinal):
        tinfo = idaapi.tinfo_t()
        tinfo.get_numbered_type(idaapi.cvar.idati, ordinal)
        vtables = {}
        if tinfo.is_struct():
            udt_data = idaapi.udt_type_data_t()
            tinfo.get_udt_details(udt_data)
            for field_udt in udt_data:
                if field_udt.type.is_ptr():
                    possible_vtable = field_udt.type.get_pointed_object()
                    if possible_vtable.is_struct():
                        v_udt_data = idaapi.udt_type_data_t()
                        possible_vtable.get_udt_details(v_udt_data)
                        for possible_func_udt in v_udt_data:
                            if not possible_func_udt.type.is_funcptr():
                                break
                        else:
                            vtables[field_udt.offset / 8] = possible_vtable
        if vtables:
            class_ = Class(tinfo.dstr(), tinfo, ordinal)
            for offset, vtable_tinfo in vtables.iteritems():
                vtables[offset] = VirtualTable.create(vtable_tinfo, class_)
            class_.vtables = vtables
            return class_

    def update_from_local_types(self):
        try:
            if self.modified:
                class_ = self.create_class(self.ordinal)
                if class_:
                    self.name = class_.name
                    self.modified = False
                    for offset, vtable in class_.vtables.iteritems():
                        self.vtables[offset].update()
                else:
                    # TODO: drop class
                    raise IndexError
        except IndexError:
            print "[ERROR] Something have been modified in Local types. Please refresh this view"

    def update_local_type(self):
        if self.modified:
            for vtable in self.vtables.values():
                vtable.update_local_type()
            udt_data = idaapi.udt_type_data_t()
            tinfo = idaapi.tinfo_t()
            self.tinfo.get_udt_details(udt_data)
            tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
            tinfo.set_numbered_type(idaapi.cvar.idati, self.ordinal, idaapi.NTF_REPLACE, self.name)
            self.modified = False

    def data(self, column):
        if column == 0:
            return self.name

    def setData(self, column, value):
        if column == 0:
            if idaapi.isident(value) and self.name != value:
                self.name = value
                self.modified = True
                return True
        return False

    def font(self, column):
        if self.modified:
            return QtGui.QFont("Consolas", 12, QtGui.QFont.Bold, italic=True)
        return QtGui.QFont("Consolas", 12, QtGui.QFont.Bold)

    @property
    def color(self):
        # return QtGui.QBrush(QtGui.QColor("#ffb3ff")):
        return QtGui.QColor("#80ced6")

    @property
    def tooltip(self):
        return None

    def flags(self, column):
        if column == 0:
            return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEditable | QtCore.Qt.ItemIsEnabled
        return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled

    @property
    def children(self):
        return self.vtables.values()

    @property
    def tinfo(self):
        tinfo = idaapi.tinfo_t()
        tinfo.get_numbered_type(idaapi.cvar.idati, self.ordinal)
        return tinfo

    def set_first_argument_type(self):
        for function in self.functions:
            function.set_first_argument_type()

    def open_function(self):
        pass

    def __repr__(self):
        return self.name + " ^_^ " + str(self.vtables)


class TreeItem:
    def __init__(self, item, row, parent):
        self.item = item
        self.parent = parent
        self.row = row
        self.children = []

    def __repr__(self):
        return str(self.item)


class TreeModel(QtCore.QAbstractItemModel):
    # TODO: Add higlighting if eip in function, consider setting breakpoints

    refreshed = QtCore.Signal()

    def __init__(self):
        super(TreeModel, self).__init__()
        self.tree_data = []
        self.headers = ["Name", "Declaration", "Address"]

        self.init()
        # import pydevd
        # pydevd.settrace("localhost", port=12345, stdoutToServer=True, stderrToServer=True)

    def init(self):
        idaapi.show_wait_box("Looking for classes...")
        all_virtual_functions.clear()
        all_virtual_tables.clear()

        classes = []
        for ordinal in xrange(1, idaapi.get_ordinal_qty(idaapi.cvar.idati)):
            result = Class.create_class(ordinal)
            if result:
                classes.append(result)

        for class_row, class_ in enumerate(classes):
            class_item = TreeItem(class_, class_row, None)
            for vtable_row, vtable in class_.vtables.iteritems():
                vtable_item = TreeItem(vtable, vtable_row, class_item)
                vtable_item.children = [TreeItem(function, 0, vtable_item) for function in vtable.virtual_functions]
                class_item.children.append(vtable_item)
            self.tree_data.append(class_item)
            print class_item

        idaapi.hide_wait_box()

    def flags(self, index):
        if index.isValid():
            return index.internalPointer().item.flags(index.column())

    def index(self, row, column, parent=QtCore.QModelIndex()):
        if parent.isValid():
            node = parent.internalPointer()
            return self.createIndex(row, column, node.children[row])
        else:
            return self.createIndex(row, column, self.tree_data[row])

    def parent(self, index):
        if index.isValid():
            node = index.internalPointer()
            if node.parent:
                return self.createIndex(node.parent.row, 0, node.parent)
        return QtCore.QModelIndex()

    def rowCount(self, index=QtCore.QModelIndex()):
        if index.isValid():
            node = index.internalPointer()
            if node:
                return len(node.children)
        return len(self.tree_data)

    def columnCount(self, index=QtCore.QModelIndex()):
        return 3

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            node = index.internalPointer()
            return node.item.data(index.column())
        elif role == QtCore.Qt.FontRole:
            return index.internalPointer().item.font(index.column())
        elif role == QtCore.Qt.ToolTipRole:
            return index.internalPointer().item.tooltip
        elif role == QtCore.Qt.BackgroundColorRole:
            return index.internalPointer().item.color
        return None

    def setData(self, index, value, role=QtCore.Qt.DisplayRole):
        result = False
        if role == QtCore.Qt.EditRole and value != "":
            node = index.internalPointer()
            result = node.item.setData(index.column(), str(value))
            # if result:
            #     index.parent().internalPointer().update_local_type()
        return result

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]

    def set_first_argument_type(self, indexes):
        class_indexes = filter(lambda x: x.internalPointer().children, indexes)
        for class_index in class_indexes:
            class_index.internalPointer().item.set_first_argument_type()

        handled_classes = map(lambda x: x.internalPointer(), class_indexes)
        for index in indexes:
            node = index.internalPointer()
            if index.column() == 1 and node.parent and node.parent not in handled_classes:
                index.internalPointer().set_first_argument_type()

    def refresh(self):
        self.tree_data = []
        self.modelReset.emit()
        self.init()
        self.refreshed.emit()

    def rollback(self):
        for class_item in self.tree_data:
            class_item.item.update_from_local_types()
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())

    def commit(self):
        for class_item in self.tree_data:
            if class_item.item.modified:
                class_item.item.update_local_type()

    def open_function(self, index):
        if index.column() == 2:
            index.internalPointer().item.open_function()
