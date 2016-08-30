import sys
import idaapi
import HexRaysPyTools.Core.Helper as Helper

from PySide import QtGui, QtCore


class VirtualMethod:
    def __init__(self, tinfo, name, parent):
        self.tinfo = tinfo
        self.tinfo_modified = False
        self.name = name
        self.name_modified = False
        self.parent = parent
        self.base_address = Helper.get_func_address_by_name(name)
        if not self.base_address:
            self.base_address = Helper.get_func_address_by_name(parent.name + '::' + name)
        if self.base_address:
            self.base_address -= idaapi.get_imagebase()
        self.rowcount = 0

    def update_from_local_type(self, new_function):
        self.name = new_function.name
        self.tinfo = new_function.tinfo
        self.name_modified = False
        self.tinfo_modified = False
        self.base_address = Helper.get_func_address_by_name(self.name)
        if not self.base_address:
            self.base_address = Helper.get_func_address_by_name(self.parent.name + '::' + self.name)
        if self.base_address:
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
            if not set('`()"[];').intersection(value) and self.name != value:
                self.name = value
                self.name_modified = True
                self.parent.modified = True
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

    def flags(self, index):
        if index.column() == 2:
            return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled
        else:
            return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsEditable

    @property
    def color(self):
        # return QtGui.QBrush(QtGui.QColor("#ffffb3"))
        return QtGui.QColor("#ffffb3")

    @property
    def tooltip(self):
        return None

    @property
    def address(self):
        return self.base_address + idaapi.get_imagebase() if self.base_address else None

    @property
    def children(self):
        return []

    def set_first_argument_type(self):
        func_data = idaapi.func_type_data_t()
        if self.tinfo.get_func_details(func_data) and self.tinfo.get_nargs():
            tinfo = idaapi.tinfo_t()
            tinfo.get_numbered_type(idaapi.cvar.idati, self.parent.ordinal)
            tinfo.create_ptr(tinfo)
            func_data[0].type = tinfo
            self.tinfo.create_func(func_data)
            self.tinfo_modified = True
            self.parent.modified = True

    def open_function(self):
        if self.address:
            idaapi.open_pseudocode(self.address, 1)

    def commit(self):
        if self.name_modified:
            self.name_modified = False
            if self.address:
                idaapi.set_name(self.address, self.name)
        if self.tinfo_modified:
            self.tinfo_modified = False
            if self.address:
                idaapi.set_tinfo2(self.address, self.tinfo)


class Class:
    def __init__(self, name, full_name, ordinal, vtable_ordinal, vtable_tinfo):
        self.full_name = full_name
        self.name = name
        self.ordinal = ordinal
        self.vtable_ordinal = vtable_ordinal
        self.vtable_tinfo = vtable_tinfo
        self.functions = None
        self.parent = None
        self.modified = False

    @staticmethod
    def create_class(ordinal):
        tinfo = idaapi.tinfo_t()
        tinfo.get_numbered_type(idaapi.cvar.idati, ordinal)
        if tinfo.is_struct():
            name = tinfo.dstr()
            full_name = name
            udt_data = idaapi.udt_type_data_t()
            tmp_tinfo = tinfo
            while tmp_tinfo.is_struct() and tmp_tinfo.get_udt_nmembers():
                tmp_tinfo.get_udt_details(udt_data)
                tmp_tinfo = udt_data[0].type
                if tmp_tinfo.is_ptr():
                    tmp_tinfo = tmp_tinfo.get_pointed_object()
                    if tmp_tinfo.get_udt_details(udt_data):
                        virtual_functions = []
                        for udt_member in udt_data:
                            if udt_member.type.is_funcptr():
                                virtual_functions.append(udt_member)
                            else:
                                return None
                        vtable_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, tmp_tinfo.dstr())
                        if vtable_ordinal:
                            result_class = Class(name, full_name, ordinal, vtable_ordinal, tmp_tinfo)
                            result_class.functions = [
                                VirtualMethod(udt_member.type.get_pointed_object(), udt_member.name, result_class)
                                for udt_member in virtual_functions
                            ]
                            return result_class
                full_name += '::' + tmp_tinfo.dstr()
                tmp_tinfo.get_udt_details(udt_data)
        return None

    def update_from_local_type(self):

        class_ = self.create_class(self.ordinal)
        if class_:
            self.name = class_.name
            self.ordinal = class_.ordinal
            self.vtable_ordinal = class_.vtable_ordinal
            self.vtable_tinfo = class_.vtable_tinfo
            self.modified = False
            for function, new_function in zip(self.functions, class_.functions):
                function.update_from_local_type(new_function)

    def update_local_type(self):
        vtable_name = self.vtable_tinfo.dstr()
        udt_data = idaapi.udt_type_data_t()
        self.vtable_tinfo.get_udt_details(udt_data)
        for idx in xrange(len(udt_data)):
            udt_data[idx].name = self.functions[idx].name
            ptr_tinfo = idaapi.tinfo_t()
            ptr_tinfo.create_ptr(self.functions[idx].tinfo)
            udt_data[idx].type = ptr_tinfo
        self.vtable_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        self.vtable_tinfo.set_numbered_type(idaapi.cvar.idati, self.vtable_ordinal, idaapi.NTF_REPLACE, vtable_name)
        self.modified = False
        for function in self.functions:
            function.commit()

    def data(self, column):
        if column == 0:
            return self.name

    def font(self, column):
        if self.modified:
            return QtGui.QFont("Consolas", 12, QtGui.QFont.Bold, italic=True)
        else:
            return QtGui.QFont("Consolas", 12, QtGui.QFont.Bold)

    @property
    def color(self):
        # return QtGui.QBrush(QtGui.QColor("#ffb3ff")):
        return QtGui.QColor("#ffb3ff")

    @property
    def tooltip(self):
        return self.full_name

    def flags(self, index):
        return QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled

    @property
    def children(self):
        return self.functions

    def set_first_argument_type(self):
        for function in self.functions:
            function.set_first_argument_type()

    def open_function(self):
        pass

    def __repr__(self):
        return self.full_name


class TreeModel(QtCore.QAbstractItemModel):

    def __init__(self):
        super(TreeModel, self).__init__()
        self.classes = []
        self.headers = ["Name", "Declaration", "Address"]

        # import pydevd
        # pydevd.settrace("localhost", port=12345, stdoutToServer=True, stderrToServer=True)
        self.init()

    def init(self):
        for ordinal in xrange(1, idaapi.get_ordinal_qty(idaapi.cvar.idati)):
            result = Class.create_class(ordinal)
            if result:
                self.classes.append(result)

    def flags(self, index):
        if index.isValid():
            return index.internalPointer().flags(index)

    def index(self, row, column, parent=QtCore.QModelIndex()):
        if parent.isValid():
            node = parent.internalPointer()
            return self.createIndex(row, column, node.functions[row])
        else:
            return self.createIndex(row, column, self.classes[row])

    def parent(self, index):
        if index.isValid():
            node = index.internalPointer()
            parent = node.parent
            if parent:
                return self.createIndex(0, 0, parent)
        return QtCore.QModelIndex()

    def rowCount(self, index=QtCore.QModelIndex()):
        if index.isValid():
            node = index.internalPointer()
            if node:
                return len(node.children)
        return len(self.classes)

    def columnCount(self, index=QtCore.QModelIndex()):
        return 3

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            node = index.internalPointer()
            return node.data(index.column())
        elif role == QtCore.Qt.FontRole:
            return index.internalPointer().font(index.column())
        elif role == QtCore.Qt.ToolTipRole:
            return index.internalPointer().tooltip
        elif role == QtCore.Qt.BackgroundColorRole:
            return index.internalPointer().color
        return None

    def setData(self, index, value, role=QtCore.Qt.DisplayRole):
        result = False
        if role == QtCore.Qt.EditRole and value != "":
            node = index.internalPointer()
            result = node.setData(index.column(), str(value))
            # if result:
            #     index.parent().internalPointer().update_local_type()
        return result

    def headerData(self, section, orientation, role):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            return self.headers[section]

    def set_first_argument_type(self, indexes):
        class_indexes = filter(lambda x: x.internalPointer().children, indexes)
        for class_index in class_indexes:
            class_index.internalPointer().set_first_argument_type()

        handled_classes = map(lambda x: x.internalPointer(), class_indexes)
        for index in indexes:
            node = index.internalPointer()
            if index.column() == 1 and node.parent and node.parent not in handled_classes:
                index.internalPointer().set_first_argument_type()

    def rollback(self):
        for class_ in self.classes:
            class_.update_from_local_type()
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())
        #
        # self.modelReset.emit()
        # self.init()
        # self.modelReset.emit()

    def commit(self):
        for class_ in self.classes:
            class_.update_local_type()

    def open_function(self, index):
        if index.column() == 2:
            index.internalPointer().open_function()
