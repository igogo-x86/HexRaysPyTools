from PyQt5 import QtCore, QtGui

import idaapi

import HexRaysPyTools.forms
from . import helper


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
            if idaapi.is_ident(value) and self.name != value:
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
                if idaapi.parse_decl(tinfo, idaapi.get_idati(), value, idaapi.PT_TYP) is not None:
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
                class_tinfo.get_named_type(idaapi.get_idati(), name):
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
                print("[Warning] function {0} probably have wrong type".format(self.name))

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
                idaapi.apply_tinfo(addresses[0], self.tinfo.get_pointed_object(), idaapi.TINFO_DEFINITE)

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
            vtable_tinfo.get_numbered_type(idaapi.get_idati(), self.ordinal)
            vtable_tinfo.get_udt_details(udt_data)
            self.tinfo = vtable_tinfo
            self.name = vtable_tinfo.dstr()
            self.modified = False
            if len(self.virtual_functions) == len(udt_data):
                for current_function, other_function in zip(self.virtual_functions, udt_data):
                    current_function.update(other_function.name, other_function.type)
            else:
                print("[ERROR] Something have been modified in Local types. Please refresh this view")

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
                final_tinfo.set_numbered_type(idaapi.get_idati(), self.ordinal, idaapi.NTF_REPLACE, self.name)
                self.modified = False
            else:
                print("[ERROR] Something have been modified in Local types. Please refresh this view")

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
        ordinal = idaapi.get_type_ordinal(idaapi.get_idati(), tinfo.dstr())
        if ordinal == 0:
            if idc.import_type(-1, tinfo.dstr()) == idaapi.BADNODE:
                raise ImportError("unable to import type to idb ({})".format(tinfo.dstr()))
            ordinal = idaapi.get_type_ordinal(idaapi.get_idati(), tinfo.dstr())

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
            if idaapi.is_ident(value) and self.name != value:
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
        tinfo.get_numbered_type(idaapi.get_idati(), ordinal)
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
                            vtables[field_udt.offset // 8] = possible_vtable
        if vtables:
            class_ = Class(tinfo.dstr(), tinfo, ordinal)
            for offset, vtable_tinfo in vtables.items():
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
                    for offset, vtable in class_.vtables.items():
                        self.vtables[offset].update()
                else:
                    # TODO: drop class
                    raise IndexError
        except IndexError:
            print("[ERROR] Something have been modified in Local types. Please refresh this view")

    def update_local_type(self):
        if self.modified:
            for vtable in list(self.vtables.values()):
                vtable.update_local_type()
            udt_data = idaapi.udt_type_data_t()
            tinfo = idaapi.tinfo_t()
            self.tinfo.get_udt_details(udt_data)
            tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
            tinfo.set_numbered_type(idaapi.get_idati(), self.ordinal, idaapi.NTF_REPLACE, self.name)
            self.modified = False

    def set_first_argument_type(self, class_name):
        if 0 in self.vtables:
            self.vtables[0].set_first_argument_type(class_name)

    def has_function(self, regexp):
        for vtable in list(self.vtables.values()):
            if [func for func in vtable.virtual_functions if regexp.indexIn(func.name) >= 0]:
                return True
        return False

    def data(self, column):
        if column == 0:
            return self.name

    def setData(self, column, value):
        if column == 0:
            if idaapi.is_ident(value) and self.name != value:
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
        return list(self.vtables.values())

    @property
    def tinfo(self):
        tinfo = idaapi.tinfo_t()
        tinfo.get_numbered_type(idaapi.get_idati(), self.ordinal)
        return tinfo

    def open_function(self):
        pass

    def __repr__(self):
        return self.name + " ^_^ " + str(self.vtables)


class TreeItem(object):
    def __init__(self, item, parent=None):
        self.item = item
        self.parent = parent
        self.children = []

    def __repr__(self):
        return str(self.item)

    def appendChild(self, item):
        self.children.append(item)

    def child(self, row):
        return self.children[row]

    def childCount(self):
        return len(self.children)

    def columnCount(self):
        return len(self.item)

    def data(self, column):
        try:
            return self.item[column]
        except IndexError:
            return None

    def row(self):
        if self.parent:
            return self.parent.children.index(self)

        return 0


class TreeModel(QtCore.QAbstractItemModel):
    # TODO: Add higlighting if eip in function, consider setting breakpoints

    refreshed = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(TreeModel, self).__init__(parent)

        self.rootItem = TreeItem(("Name", "Declaration", "Address"))
        self.setupModelData(self.rootItem)

    def setupModelData(self, root):
        idaapi.show_wait_box("Looking for classes...")

        all_virtual_functions.clear()
        all_virtual_tables.clear()

        classes = []
        for ordinal in range(1, idaapi.get_ordinal_qty(idaapi.get_idati())):
            result = Class.create_class(ordinal)
            if result:
                classes.append(result)

        for class_ in classes:
            class_item = TreeItem(class_, root)
            for vtable in class_.vtables.values():
                vtable_item = TreeItem(vtable, class_item)
                vtable_item.children = [TreeItem(function, vtable_item) for function in vtable.virtual_functions]
                class_item.appendChild(vtable_item)
            root.appendChild(class_item)

        idaapi.hide_wait_box()

    def flags(self, index):
        if index.isValid():
            return index.internalPointer().item.flags(index.column())
        else:
            return QtCore.Qt.NoItemFlags

    def index(self, row, column, parent):
        if not self.hasIndex(row, column, parent):
            return QtCore.QModelIndex()

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        childItem = parentItem.child(row)
        if childItem:
            return self.createIndex(row, column, childItem)
        else:
            return QtCore.QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QtCore.QModelIndex()

        childItem = index.internalPointer()
        parentItem = childItem.parent

        if parentItem == self.rootItem:
            return QtCore.QModelIndex()

        return self.createIndex(parentItem.row(), 0, parentItem)

    def rowCount(self, parent):
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()

        return parentItem.childCount()

    def columnCount(self, parent):
        return self.rootItem.columnCount()

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None

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

    def setData(self, index, value, role=QtCore.Qt.EditRole):
        result = False
        value = str(value)
        if role == QtCore.Qt.EditRole and value:
            node = index.internalPointer()
            result = node.item.setData(index.column(), value)

        return result

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.rootItem.data(section)

        return None

    def set_first_argument_type(self, indexes):
        indexes = [x for x in indexes if x.column() == 0]
        class_name = indexes[0].internalPointer().item.class_name
        if not class_name:
            classes = [[x.item.name] for x in self.rootItem.children]
            class_chooser = HexRaysPyTools.forms.MyChoose(classes, "Select Class", [["Name", 25]])
            idx = class_chooser.Show(True)
            if idx != -1:
                class_name = classes[idx][0]
        if class_name:
            for index in indexes:
                index.internalPointer().item.set_first_argument_type(class_name)

    def refresh(self):
        self.beginResetModel()
        self.rootItem.children = []
        self.endResetModel()

        self.layoutAboutToBeChanged.emit()
        self.setupModelData(self.rootItem)
        self.layoutChanged.emit()

        self.refreshed.emit()

    def rollback(self):
        self.layoutAboutToBeChanged.emit()
        for class_item in self.rootItem.children:
            class_item.item.update_from_local_types()
        self.layoutChanged.emit()

    def commit(self):
        for class_item in self.rootItem.children:
            if class_item.item.modified:
                class_item.item.update_local_type()

    def open_function(self, index):
        item = index.internalPointer().item
        if isinstance(item, VirtualMethod):
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
        filter_regexp = self.filterRegExp()
        if filter_regexp:
            index = self.sourceModel().index(row, 0, parent)
            item = index.internalPointer().item

            if self.filter_by_function and isinstance(item, Class):
                return item.has_function(filter_regexp)
            else:
                return filter_regexp.indexIn(item.class_name) >= 0

        return True
