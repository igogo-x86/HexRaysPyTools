from PyQt5 import QtCore, QtWidgets

import idaapi


class MyChoose(idaapi.Choose2):
    def __init__(self, items, title, cols, icon=-1):
        idaapi.Choose2.__init__(self, title, cols, flags=idaapi.Choose2.CH_MODAL, icon=icon)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class StructureBuilder(idaapi.PluginForm):
    def __init__(self, structure_model):
        super(StructureBuilder, self).__init__()
        self.structure_model = structure_model
        self.parent = None

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent; selection-background-color: #87bdd8;}"
            "QHeaderView::section {background-color: transparent; border: 0.5px solid;}"
            "QPushButton {width: 50px; height: 20px;}"
            # "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('Structure Builder')

        btn_finalize = QtWidgets.QPushButton("&Finalize")
        btn_disable = QtWidgets.QPushButton("&Disable")
        btn_enable = QtWidgets.QPushButton("&Enable")
        btn_origin = QtWidgets.QPushButton("&Origin")
        btn_array = QtWidgets.QPushButton("&Array")
        btn_pack = QtWidgets.QPushButton("&Pack")
        btn_unpack = QtWidgets.QPushButton("&Unpack")
        btn_remove = QtWidgets.QPushButton("&Remove")
        btn_resolve = QtWidgets.QPushButton("Resolve")
        btn_clear = QtWidgets.QPushButton("Clear")  # Clear button doesn't have shortcut because it can fuck up all work
        btn_recognize = QtWidgets.QPushButton("Recognize Shape")
        btn_recognize.setStyleSheet("QPushButton {width: 100px; height: 20px;}")

        btn_finalize.setShortcut("f")
        btn_disable.setShortcut("d")
        btn_enable.setShortcut("e")
        btn_origin.setShortcut("o")
        btn_array.setShortcut("a")
        btn_pack.setShortcut("p")
        btn_unpack.setShortcut("u")
        btn_remove.setShortcut("r")

        struct_view = QtWidgets.QTableView()
        struct_view.setModel(self.structure_model)
        # struct_view.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        struct_view.verticalHeader().setVisible(False)
        struct_view.verticalHeader().setDefaultSectionSize(24)
        struct_view.horizontalHeader().setStretchLastSection(True)
        struct_view.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        grid_box = QtWidgets.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(btn_finalize, 0, 0)
        grid_box.addWidget(btn_enable, 0, 1)
        grid_box.addWidget(btn_disable, 0, 2)
        grid_box.addWidget(btn_origin, 0, 3)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 0, 5)
        grid_box.addWidget(btn_array, 1, 0)
        grid_box.addWidget(btn_pack, 1, 1)
        grid_box.addWidget(btn_unpack, 1, 2)
        grid_box.addWidget(btn_remove, 1, 3)
        grid_box.addWidget(btn_resolve, 0, 4)
        grid_box.addItem(QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Expanding), 1, 5)
        grid_box.addWidget(btn_recognize, 0, 6)
        grid_box.addWidget(btn_clear, 1, 6)

        vertical_box = QtWidgets.QVBoxLayout()
        vertical_box.addWidget(struct_view)
        vertical_box.addLayout(grid_box)
        self.parent.setLayout(vertical_box)

        btn_finalize.clicked.connect(lambda: self.structure_model.finalize())
        btn_disable.clicked.connect(lambda: self.structure_model.disable_rows(struct_view.selectedIndexes()))
        btn_enable.clicked.connect(lambda: self.structure_model.enable_rows(struct_view.selectedIndexes()))
        btn_origin.clicked.connect(lambda: self.structure_model.set_origin(struct_view.selectedIndexes()))
        btn_array.clicked.connect(lambda: self.structure_model.make_array(struct_view.selectedIndexes()))
        btn_pack.clicked.connect(lambda: self.structure_model.pack_substructure(struct_view.selectedIndexes()))
        btn_unpack.clicked.connect(lambda: self.structure_model.unpack_substructure(struct_view.selectedIndexes()))
        btn_remove.clicked.connect(lambda: self.structure_model.remove_items(struct_view.selectedIndexes()))
        btn_resolve.clicked.connect(lambda: self.structure_model.resolve_types())
        btn_clear.clicked.connect(lambda: self.structure_model.clear())
        btn_recognize.clicked.connect(lambda: self.structure_model.recognize_shape(struct_view.selectedIndexes()))
        struct_view.activated[QtCore.QModelIndex].connect(self.structure_model.activated)
        self.structure_model.dataChanged.connect(struct_view.clearSelection)

    def OnClose(self, form):
        pass

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)


class StructureGraphViewer(idaapi.GraphViewer):
    def __init__(self, title, graph):
        idaapi.GraphViewer.__init__(self, title)
        self.graph = graph
        self.nodes_id = {}

    def OnRefresh(self):
        self.Clear()
        self.nodes_id.clear()
        for node in self.graph.get_nodes():
            self.nodes_id[node] = self.AddNode(node)
        for first, second in self.graph.get_edges():
            self.AddEdge(self.nodes_id[first], self.nodes_id[second])
        return True

    def OnGetText(self, node_id):
        return self.graph.local_types[self[node_id]].name_and_color

    def OnHint(self, node_id):
        """ Try-catch clause because IDA sometimes attempts to use old information to get hint """
        try:
            ordinal = self[node_id]
            return self.graph.local_types[ordinal].hint
        except KeyError:
            return

    def OnDblClick(self, node_id):
        self.change_selected([self[node_id]])

    def change_selected(self, ordinals):
        self.graph.change_selected(ordinals)
        self.Refresh()
        self.Select(self.nodes_id[ordinals[0]])


class ClassViewer(idaapi.PluginForm):
    def __init__(self, proxy_model, class_model):
        super(ClassViewer, self).__init__()
        self.parent = None
        self.class_tree = QtWidgets.QTreeView()
        self.line_edit_filter = QtWidgets.QLineEdit()

        self.action_collapse = QtWidgets.QAction("Collapse all", self.class_tree)
        self.action_expand = QtWidgets.QAction("Expand all", self.class_tree)
        self.action_set_arg = QtWidgets.QAction("Set First Argument Type", self.class_tree)
        self.action_rollback = QtWidgets.QAction("Rollback", self.class_tree)
        self.action_refresh = QtWidgets.QAction("Refresh", self.class_tree)
        self.action_commit = QtWidgets.QAction("Commit", self.class_tree)

        self.menu = QtWidgets.QMenu(self.parent)

        self.proxy_model = proxy_model
        self.class_model = class_model

    def OnCreate(self, form):
        # self.parent = self.FormToPySideWidget(form)
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setWindowTitle('Classes')
        self.parent.setStyleSheet(
            # "QTreeView::item:!has-children { background-color: #fefbd8; border: 0.5px solid lightgray ;}"
            # "QTreeView::item:has-children { background-color: #80ced6; border-top: 1px solid black ;}"
            # "QTreeView::item:selected { background-color: #618685; show-decoration-selected: 1;}"
            "QTreeView {background-color: transparent; }"
            "QHeaderView::section {background-color: transparent; border: 1px solid;}"
        )

        hbox_layout = QtWidgets.QHBoxLayout()
        label_filter = QtWidgets.QLabel("&Filter:")
        label_filter.setBuddy(self.line_edit_filter)
        hbox_layout.addWidget(label_filter)
        hbox_layout.addWidget(self.line_edit_filter)

        self.proxy_model.setSourceModel(self.class_model)
        self.proxy_model.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.class_tree.setModel(self.proxy_model)
        self.class_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.class_tree.expandAll()
        self.class_tree.header().setStretchLastSection(True)
        self.class_tree.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.class_tree.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        self.action_collapse.triggered.connect(self.class_tree.collapseAll)
        self.action_expand.triggered.connect(self.class_tree.expandAll)
        self.action_set_arg.triggered.connect(
            lambda: self.class_model.set_first_argument_type(
                map(self.proxy_model.mapToSource, self.class_tree.selectedIndexes())
            )
        )
        self.action_rollback.triggered.connect(lambda: self.class_model.rollback())
        self.action_refresh.triggered.connect(lambda: self.class_model.refresh())
        self.action_commit.triggered.connect(lambda: self.class_model.commit())
        self.class_model.refreshed.connect(self.class_tree.expandAll)

        self.menu.addAction(self.action_collapse)
        self.menu.addAction(self.action_expand)
        self.menu.addAction(self.action_refresh)
        self.menu.addAction(self.action_set_arg)
        self.menu.addAction(self.action_rollback)
        self.menu.addAction(self.action_commit)

        vertical_box = QtWidgets.QVBoxLayout()
        vertical_box.addWidget(self.class_tree)
        vertical_box.addLayout(hbox_layout)
        self.parent.setLayout(vertical_box)

        self.class_tree.activated[QtCore.QModelIndex].connect(
            lambda x: self.class_model.open_function(self.proxy_model.mapToSource(x))
        )
        self.class_tree.customContextMenuRequested[QtCore.QPoint].connect(self.show_menu)
        self.line_edit_filter.textChanged[str].connect(self.proxy_model.set_regexp_filter)
        # proxy_model.rowsInserted[object].connect(lambda: self.class_tree.setExpanded(object, True))

    def OnClose(self, form):
        pass

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=options)

    def show_menu(self, point):
        self.action_set_arg.setEnabled(True)
        indexes = map(
            self.proxy_model.mapToSource,
            filter(lambda x: x.column() == 0, self.class_tree.selectedIndexes())
        )
        if len(indexes) > 1:
            if filter(lambda x: len(x.internalPointer().children) > 0, indexes):
                self.action_set_arg.setEnabled(False)
        self.menu.exec_(self.class_tree.mapToGlobal(point))
