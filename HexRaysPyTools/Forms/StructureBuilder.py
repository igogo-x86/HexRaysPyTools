import PySide.QtGui as QtGui
import idaapi

from HexRaysPyTools.Helper.Structures import *


class StructureBuilder(idaapi.PluginForm):
    def __init__(self, structure_model):
        super(StructureBuilder, self).__init__()
        self.structure_model = structure_model
        self.parent = None

    def OnCreate(self, form):
        self.parent = self.FormToPySideWidget(form)
        self.init_ui()

    def init_ui(self):
        self.parent.setStyleSheet(
            "QTableView {background-color: transparent;}"
            "QHeaderView::section {background-color: transparent; border: 1px solid;}"
            "QPushButton {width: 80px; height: 20px;}"
            # "QPushButton::pressed {background-color: #ccccff}"
        )
        self.parent.resize(400, 600)
        self.parent.setWindowTitle('Structure Builder')

        btn_finalize = QtGui.QPushButton("&Finalize")
        btn_disable = QtGui.QPushButton("&Disable")
        btn_enable = QtGui.QPushButton("&Enable")
        btn_origin = QtGui.QPushButton("&Origin")
        btn_array = QtGui.QPushButton("&Array")
        btn_pack = QtGui.QPushButton("&Pack")
        btn_remove = QtGui.QPushButton("&Remove")
        btn_clear = QtGui.QPushButton("Clear")  # Clear button doesn't have shortcut because it can fuck up all work

        btn_finalize.setShortcut("f")
        btn_disable.setShortcut("d")
        btn_enable.setShortcut("e")
        btn_origin.setShortcut("o")
        btn_array.setShortcut("a")
        btn_pack.setShortcut("p")
        btn_remove.setShortcut("r")

        struct_view = QtGui.QTableView()
        struct_view.setModel(self.structure_model)

        struct_view.verticalHeader().setVisible(False)
        struct_view.horizontalHeader().setStretchLastSection(True)
        struct_view.horizontalHeader().setResizeMode(QtGui.QHeaderView.ResizeToContents)

        grid_box = QtGui.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(btn_finalize, 0, 0)
        grid_box.addWidget(btn_disable, 0, 1)
        grid_box.addWidget(btn_enable, 0, 2)
        grid_box.addWidget(btn_origin, 0, 3)
        grid_box.addWidget(btn_array, 1, 0)
        grid_box.addWidget(btn_pack, 1, 1)
        grid_box.addWidget(btn_remove, 1, 2)
        grid_box.addWidget(btn_clear, 1, 3)

        horizontal_box = QtGui.QHBoxLayout()
        horizontal_box.addLayout(grid_box)
        horizontal_box.addStretch(1)

        vertical_box = QtGui.QVBoxLayout()
        vertical_box.addWidget(struct_view)
        vertical_box.addLayout(horizontal_box)
        self.parent.setLayout(vertical_box)

        btn_finalize.clicked.connect(lambda: self.structure_model.finalize())
        btn_disable.clicked.connect(lambda: self.structure_model.disable_rows(struct_view.selectedIndexes()))
        btn_enable.clicked.connect(lambda: self.structure_model.enable_rows(struct_view.selectedIndexes()))
        btn_origin.clicked.connect(lambda: self.structure_model.set_origin(struct_view.selectedIndexes()))
        btn_origin.clicked.connect(lambda: self.structure_model.make_array(struct_view.selectedIndexes()))
        btn_origin.clicked.connect(lambda: self.structure_model.pack_substruct(struct_view.selectedIndexes()))
        btn_remove.clicked.connect(lambda: self.structure_model.remove_item(struct_view.selectedIndexes()))
        btn_clear.clicked.connect(lambda: self.structure_model.clear())

    def OnClose(self, form):
        pass

    def Show(self, caption=None, options=0):
        return idaapi.PluginForm.Show(self, caption, options=0)
