from PyQt5 import QtCore, QtGui

import idaapi

import HexRaysPyTools.forms
import helper


all_virtual_functions = {}      # name    -> VirtualMethod
all_virtual_tables = {}         # ordinal -> VirtualTable


class VirtualMethod(object):
    def __init__(self, tinfo, name, parent):
        self.tinfo = tinfo
        self.tinfo_modified = False
        self.name = name
        self.class_name = None
        self.name_modified = False
        self.parents = [parent]
        image_base = idaapi.get_imagebase()
        self.ra_addresses = [ea - image_base for ea in helper.get_virtual_func_addresses(name)]

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

    def data(self, column):
        if column == 0:
            return self.name
        elif column == 1:
            return self.tinfo.get_pointed_object().dstr()
        elif column == 2:
            addresses = self.addresses
            if len(addresses) > 1:
                return "LIST"
            elif len(addresses) == 1:
                return helper.to_hex(addresses[0])

    def setData(self, column, value):
        if column == 0:
            if idaapi.isident(value) and self.name != value:
                self.name = value
                self.name_modified = True
                for parent in self.parents:
                    parent.modified = True
                return True
        elif column == 1:
            tinfo = idaapi.tinfo_t()
            split = value.split('(')
            if len(split) == 2:
                value = split[0] + ' ' + self.name + '(' + split[1] + ';'
                if idaapi.parse_decl(tinfo, idaapi.cvar.idati, value, idaapi.PT_TYP) is not None:
                    if tinfo.is_func():
                        tinfo.create_ptr(tinfo)
                        if tinfo.dstr() != self.tinfo.dstr():
                            self.tinfo = tinfo
                            self.tinfo_modified = True
                            for parent in self.parents:
                                parent.modified = True
                            return True
        return False

    def font(self, column):
        if column == 0 and self.name_modified:
            return QtGui.QFont("Consolas", 10, italic=True)
        elif column == 1 and self.tinfo_modified:
            return QtGui.QFont("Consolas", 10, italic=True)
        return QtGui.QFont("Consolas", 10, 0)

    def flags(self, column):
        if column != 2:
            if len(self.addresses) == 1:
                # Virtual function has only one address. Allow to modify its signature and name
                return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsEditable
        return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled


    @property
    def color(self):
        # return QtGui.QBrush(QtGui.QColor("#ffffb3"))
        return QtGui.QColor("#fefbd8")

    @property
    def tooltip(self):
        return None

    @property
    def addresses(self):
        image_base = idaapi.get_imagebase()
        return [ra + image_base for ra in self.ra_addresses]

    def set_first_argument_type(self, name):
        func_data = idaapi.func_type_data_t()
        func_tinfo = self.tinfo.get_pointed_object()
        class_tinfo = idaapi.tinfo_t()
        if func_tinfo.get_func_details(func_data) and func_tinfo.get_nargs() and \
                class_tinfo.get_named_type(idaapi.cvar.idati, name):
            class_tinfo.create_ptr(class_tinfo)
            first_arg_tinfo = func_data[0].type
            if (first_arg_tinfo.is_ptr() and first_arg_tinfo.get_pointed_object().is_udt()) or \
                    helper.is_legal_type(func_data[0].type):
                func_data[0].type = class_tinfo
                func_data[0].name = "this"
                func_tinfo.create_func(func_data)
                func_tinfo.create_ptr(func_tinfo)
                if func_tinfo.dstr() != self.tinfo.dstr():
                    self.tinfo = func_tinfo
                    self.tinfo_modified = True
                    for parent in self.parents:
                        parent.modified = True
            else:
                print "[Warning] function {0} probably have wrong type".format(self.name)

    def open_function(self):
        addresses = self.addresses
        if len(addresses) > 1:
            address = helper.choose_virtual_func_address(self.name)
            if not address:
                return
        elif len(addresses) == 1:
            address = addresses[0]
        else:
            return

        if helper.decompile_function(address):
            idaapi.open_pseudocode(address, 0)
        else:
            idaapi.jumpto(address)

    def commit(self):
        addresses = self.addresses
        if self.name_modified:
            self.name_modified = False
            if len(addresses) == 1:
                idaapi.set_name(addresses[0], self.name)
        if self.tinfo_modified:
            self.tinfo_modified = False
            if len(addresses) == 1:
                idaapi.apply_tinfo2(addresses[0], self.tinfo.get_pointed_object(), idaapi.TINFO_DEFINITE)

    def __eq__(self, other):
        return self.addresses == other.addresses

    def __repr__(self):
        return self.name


class VirtualTable(object):
    def __init__(self, ordinal, tinfo, class_):
        self.ordinal = ordinal
        self.tinfo = tinfo
        self.class_ = [class_]
        self.class_name = None
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

    def set_first_argument_type(self, class_name):
        for function in self.virtual_functions:
            function.set_first_argument_type(class_name)

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
        self.class_name = name
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

    def set_first_argument_type(self, class_name):
        if 0 in self.vtables:
            self.vtables[0].set_first_argument_type(class_name)

    def has_function(self, regexp):
        for vtable in self.vtables.values():
            if filter(lambda func: regexp.indexIn(func.name) >= 0, vtable.virtual_functions):
                return True
        return False

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

    refreshed = QtCore.pyqtSignal()

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
                return self.createIndex(0, 0, node.parent)
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
        elif role == QtCore.Qt.BackgroundRole:
            return index.internalPointer().item.color
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QBrush(QtGui.QColor("#191919"))
        return None

    def setData(self, index, value, role=QtCore.Qt.DisplayRole):
        result = False
        if role == QtCore.Qt.EditRole and value != "":
            node = index.internalPointer()
            result = node.item.setData(index.column(), str(value))
        return result

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]

    def set_first_argument_type(self, indexes):
        indexes = filter(lambda x: x.column() == 0, indexes)
        class_name = indexes[0].internalPointer().item.class_name
        if not class_name:
            classes = [[x.item.name] for x in self.tree_data]
            class_chooser = HexRaysPyTools.forms.MyChoose(classes, "Select Class", [["Name", 25]])
            idx = class_chooser.Show(True)
            if idx != -1:
                class_name = classes[idx][0]
        if class_name:
            for index in indexes:
                index.internalPointer().item.set_first_argument_type(class_name)

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


class ProxyModel(QtCore.QSortFilterProxyModel):
    def __init__(self):
        super(ProxyModel, self).__init__()
        self.filter_by_function = False

    def set_regexp_filter(self, regexp):
        if regexp and regexp[0] == '!':
            self.filter_by_function = True
            self.setFilterRegExp(regexp[1:])
        else:
            self.filter_by_function = False
            self.setFilterRegExp(regexp)

    def filterAcceptsRow(self, row, parent):
        if not parent.isValid() and self.filterRegExp():
            if self.filter_by_function:
                return self.sourceModel().tree_data[row].item.has_function(self.filterRegExp())
            return self.filterRegExp().indexIn(self.sourceModel().tree_data[row].item.class_name) >= 0
        return True
