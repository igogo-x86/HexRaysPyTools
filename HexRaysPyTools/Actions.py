import ctypes
import sys

import idaapi

import HexRaysPyTools.Forms as Forms
# from HexRaysPyTools.Forms import StructureGraphViewer, MyChoose
from HexRaysPyTools.Core.StructureGraph import StructureGraph
from HexRaysPyTools.Core.TemporaryStructure import VirtualTable, EA64, LEGAL_TYPES, ScannedVariable
from HexRaysPyTools.Core.VariableScanner import CtreeVisitor


def register(action, *args):
    idaapi.register_action(
        idaapi.action_desc_t(
            action.name,
            action.description,
            action(*args),
            action.hotkey
        )
    )


def unregister(action):
    idaapi.unregister_action(action.name)


class RemoveArgument(idaapi.action_handler_t):

    name = "my:RemoveArgument"
    description = "Remove Argument"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        vu = idaapi.get_tform_vdui(ctx.form)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        del_arg = vu.item.get_lvar()  # lvar_t

        function_details.erase(filter(lambda x: x.name == del_arg.name, function_details)[0])

        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class RemoveReturn(idaapi.action_handler_t):

    name = "my:RemoveReturn"
    description = "Remove Return"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # ctx - action_activation_ctx_t
        vu = idaapi.get_tform_vdui(ctx.form)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        function_details.rettype = idaapi.tinfo_t(idaapi.BT_VOID)
        function_tinfo.create_func(function_details)
        idaapi.set_tinfo2(vu.cfunc.entry_ea, function_tinfo)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GetStructureBySize(idaapi.action_handler_t):
    # TODO: apply type automatically if expression like `var = new(size)`

    name = "my:WhichStructHaveThisSize"
    description = "Structures with this size"
    hotkey = "W"

    class til_t(ctypes.Structure):
        pass

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

        GetStructureBySize.til_t._fields_ = [
            ("name", ctypes.c_char_p),
            ("desc", ctypes.c_char_p),
            ("nbases", ctypes.c_int),
            ("base", ctypes.POINTER(ctypes.POINTER(GetStructureBySize.til_t)))
        ]

    @staticmethod
    def enable_library_ordinals(library_num):
        idaname = "ida64" if EA64 else "ida"
        if sys.platform == "win32":
            dll = ctypes.windll[idaname + ".wll"]
        elif sys.platform == "linux2":
            dll = ctypes.cdll["lib" + idaname + ".so"]
        elif sys.platform == "darwin":
            dll = ctypes.cdll["lib" + idaname + ".dylib"]

        idati = ctypes.POINTER(GetStructureBySize.til_t).in_dll(dll, "idati")
        dll.enable_numbered_types(idati.contents.base[library_num], True)

    @staticmethod
    def select_structure_by_size(size):
        idati = idaapi.cvar.idati
        list_type_library = [(idati, idati.name, idati.desc)]
        for idx in xrange(idaapi.cvar.idati.nbases):
            type_library = idaapi.cvar.idati.base(idx)          # idaapi.til_t type
            list_type_library.append((type_library, type_library.name, type_library.desc))

        library_chooser = Forms.MyChoose(
            list(map(lambda x: [x[1], x[2]], list_type_library)),
            "Select Library",
            [["Library", 10 | idaapi.Choose2.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose2.CHCOL_PLAIN]]
        )
        library_num = library_chooser.Show(True)
        if library_num != -1:
            selected_library = list_type_library[library_num][0]
            max_ordinal = idaapi.get_ordinal_qty(selected_library)
            if max_ordinal == idaapi.BADNODE:
                GetStructureBySize.enable_library_ordinals(library_num - 1)
                max_ordinal = idaapi.get_ordinal_qty(selected_library)

            print "[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal)

            matched_types = []
            tinfo = idaapi.tinfo_t()
            for ordinal in xrange(1, max_ordinal):
                tinfo.create_typedef(selected_library, ordinal)
                if tinfo.get_size() == size:
                    name = tinfo.dstr()
                    description = idaapi.print_tinfo(None, 0, 0, idaapi.PRTYPE_DEF, tinfo, None, None)
                    matched_types.append([str(ordinal), name, description])

            type_chooser = Forms.MyChoose(
                matched_types,
                "Select Type",
                [["Ordinal", 5 | idaapi.Choose2.CHCOL_HEX], ["Type Name", 25], ["Declaration", 50]]
            )
            selected_type = type_chooser.Show(True)
            if selected_type != -1:
                if library_num:
                    print "[Info] Importing type: {0}".format(matched_types[selected_type][1])
                    last_ordinal = idaapi.get_ordinal_qty(idaapi.cvar.idati)
                    type_id = idaapi.import_type(selected_library, -1, matched_types[selected_type][1]) # tid_t
                    if type_id != idaapi.BADNODE:
                        return last_ordinal
                    else:
                        return None
                else:
                    return int(matched_types[selected_type][0])
            return None

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        if hx_view.item.citype != idaapi.VDI_EXPR or hx_view.item.e.op != idaapi.cot_num:
            return
        ea = ctx.cur_ea
        c_number = hx_view.item.e.n
        number_value = c_number._value
        ordinal = GetStructureBySize.select_structure_by_size(number_value)
        if ordinal:
            number_format_old = c_number.nf
            number_format_new = idaapi.number_format_t()
            number_format_new.flags = idaapi.FF_1STRO | idaapi.FF_0STRO
            operand_number = number_format_old.opnum
            number_format_new.opnum = operand_number
            number_format_new.props = number_format_old.props
            number_format_new.type_name = idaapi.create_numbered_type_name(ordinal)

            c_function = hx_view.cfunc
            number_formats = c_function.numforms    # idaapi.user_numforms_t
            operand_locator = idaapi.operand_locator_t(ea, ord(operand_number) if operand_number else 0)
            if operand_locator in number_formats:
                del number_formats[operand_locator]

            number_formats[operand_locator] = number_format_new
            c_function.save_user_numforms()
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM


class ScanVariable(idaapi.action_handler_t):

    name = "my:ScanVariable"
    description = "Scan Variable"
    hotkey = None

    def __init__(self, temporary_structure):
        self.temporary_structure = temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, item):
        """
        Checks if variable belongs to cfunc and have a type that is supportable for scanning

        :param cfunc: idaapi.cfunct_t
        :param item: idaapi.ctree_item_t
        :return: bool
        """
        if item.citype == idaapi.VDI_EXPR:
            if item.e.op == idaapi.cot_var:
                local_variable = cfunc.get_lvars()[item.e.v.idx]
                if local_variable.type().dstr() in LEGAL_TYPES:
                    return True
        elif item.citype == idaapi.VDI_LVAR:
            local_variable = item.get_lvar()
            if local_variable.type().dstr() in LEGAL_TYPES:
                return True
        else:
            return False

    def activate(self, ctx):
        vu = idaapi.get_tform_vdui(ctx.form)
        variable = vu.item.get_lvar()  # lvar_t
        print "Local variable type: %s" % variable.tif.dstr()
        if variable.tif.dstr() in LEGAL_TYPES:
            scanner = CtreeVisitor(vu.cfunc, variable, self.temporary_structure.main_offset)
            scanner.apply_to(vu.cfunc.body, None)
            for field in scanner.candidates:
                self.temporary_structure.add_row(field)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM


class ShowGraph(idaapi.action_handler_t):

    name = "my:ShowGraph"
    description = "Show graph"
    hotkey = "G"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.graph = None
        self.graph_view = None

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        form = self.graph_view.GetTForm() if self.graph_view else None
        if form:
            self.graph.change_selected(list(ctx.chooser_selection))
            self.graph_view.Refresh()
        else:
            self.graph = StructureGraph(list(ctx.chooser_selection))
            self.graph_view = Forms.StructureGraphViewer("Structure Graph", self.graph)
            self.graph_view.Show()

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_LOCTYPS:
            idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM


class CreateVtable(idaapi.action_handler_t):

    name = "my:CreateVtable"
    description = "Create Virtual Table"
    hotkey = "V"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ctx.cur_ea
        if ea != idaapi.BADADDR and VirtualTable.check_address(ea):
            vtable = VirtualTable(0, ea)
            vtable.import_to_structures(True)

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM

