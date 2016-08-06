import sys
import idaapi
import ctypes

from HexRaysPyTools.Forms.StructureBuilder import *
from HexRaysPyTools.Forms.StructureGraphForm import *
from HexRaysPyTools.Helper.Scanner import *

# import Helper.QtShim as QtShim


def is_scan_variable(cfunc, item):
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


def hexrays_events_callback(*args):
    hexrays_event = args[0]
    if hexrays_event == idaapi.hxe_keyboard:
        hx_view, key, shift = args[1:]
        if key == ord('F'):
            if is_scan_variable(hx_view.cfunc, hx_view.item):
                idaapi.process_ui_action("my:ScanVariable")

    elif hexrays_event == idaapi.hxe_populating_popup:
        form, popup, hx_view = args[1:]
        item = hx_view.item  # current ctree_item_t

        if is_scan_variable(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, "my:ScanVariable", None)

        elif item.citype == idaapi.VDI_FUNC:
            # If we clicked on function
            if not hx_view.cfunc.entry_ea == idaapi.BADADDR:  # Probably never happen
                idaapi.attach_action_to_popup(form, popup, "my:RemoveReturn", None)

        elif item.citype == idaapi.VDI_LVAR:
            # If we clicked on argument
            local_variable = hx_view.item.get_lvar()          # idaapi.lvar_t
            if local_variable.is_arg_var:
                idaapi.attach_action_to_popup(form, popup, "my:RemoveArgument", None)

        elif item.citype == idaapi.VDI_EXPR and item.e.op == idaapi.cot_num:
            num = item.e.n.nf
            print "(number) flags:", hex(num.flags), "type_name:", num.type_name, "props:", num.props, "serial:", num.serial, "org_nbytes:", num.org_nbytes, "opnum:", num.opnum
            idaapi.attach_action_to_popup(form, popup, ActionGetStructureBySize.name, None)

    elif hexrays_event == idaapi.hxe_double_click:
        hx_view = args[1]
        item = hx_view.item
        if item.citype == idaapi.VDI_EXPR and item.e.op == idaapi.cot_memptr:
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset
            structure_tinfo = item.e.x.type
            member_offset = item.e.m
            if structure_tinfo.is_ptr():
                structure_tinfo.remove_ptr_or_array()
                if structure_tinfo.is_udt():
                    udt_data = idaapi.udt_type_data_t()
                    structure_tinfo.get_udt_details(udt_data)
                    member_name = filter(lambda x: x.offset == member_offset * 8, udt_data)[0].name

                    # And finally look through all functions and find the same name. Sigh...
                    for idx in xrange(idaapi.get_func_qty()):
                        function = idaapi.getn_func(idx)
                        if idaapi.get_func_name2(function.startEA) == member_name:
                            idaapi.open_pseudocode(function.startEA, 0)
                            return 1
    return 0


class ActionRemoveArgument(idaapi.action_handler_t):
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


class ActionRemoveReturn(idaapi.action_handler_t):
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


class ActionCreateVtable(idaapi.action_handler_t):
    name = "my:CreateVtable"
    description = "Create Virtual Table"
    hotkey = "V"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def generate():
        return idaapi.action_desc_t(
            ActionCreateVtable.name,
            ActionCreateVtable.description,
            ActionCreateVtable(),
            ActionCreateVtable.hotkey
        )

    def activate(self, ctx):
        ea = ctx.cur_ea
        if ea != idaapi.BADADDR and check_virtual_table(ea):
            vtable = VirtualTable(0, ea)
            vtable.import_to_structures(True)

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM


class MyChoose(idaapi.Choose2):
    def __init__(self, items, title, cols):
        idaapi.Choose2.__init__(self, title, cols, flags=idaapi.Choose2.CH_MODAL)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class ActionGetStructureBySize(idaapi.action_handler_t):
    name = "my:WhichStructHaveThisSize"
    description = "Structures with this size"
    hotkey = "W"

    class til_t(ctypes.Structure):
        pass

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

        ActionGetStructureBySize.til_t._fields_ = [
            ("name", ctypes.c_char_p),
            ("desc", ctypes.c_char_p),
            ("nbases", ctypes.c_int),
            ("base", ctypes.POINTER(ctypes.POINTER(ActionGetStructureBySize.til_t)))
        ]

    @staticmethod
    def generate():
        return idaapi.action_desc_t(
            ActionGetStructureBySize.name,
            ActionGetStructureBySize.description,
            ActionGetStructureBySize(),
            ActionGetStructureBySize.hotkey
        )

    @staticmethod
    def enable_library_ordinals(library_num):
        idaname = "ida64" if EA64 else "ida"
        if sys.platform == "win32":
            dll = ctypes.windll[idaname + ".wll"]
        elif sys.platform == "linux2":
            dll = ctypes.cdll["lib" + idaname + ".so"]
        elif sys.platform == "darwin":
            dll = ctypes.cdll["lib" + idaname + ".dylib"]

        idati = ctypes.POINTER(ActionGetStructureBySize.til_t).in_dll(dll, "idati")
        dll.enable_numbered_types(idati.contents.base[library_num], True)

    @staticmethod
    def select_structure_by_size(size):
        idati = idaapi.cvar.idati
        list_type_library = [(idati, idati.name, idati.desc)]
        for idx in xrange(idaapi.cvar.idati.nbases):
            type_library = idaapi.cvar.idati.base(idx)          # idaapi.til_t type
            list_type_library.append((type_library, type_library.name, type_library.desc))

        library_chooser = MyChoose(
            list(map(lambda x: [x[1], x[2]], list_type_library)),
            "Select Library",
            [["Library", 10 | idaapi.Choose2.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose2.CHCOL_PLAIN]]
        )
        library_num = library_chooser.Show(True)
        if library_num != -1:
            selected_library = list_type_library[library_num][0]
            max_ordinal = idaapi.get_ordinal_qty(selected_library)
            if max_ordinal == idaapi.BADNODE:
                ActionGetStructureBySize.enable_library_ordinals(library_num - 1)
                max_ordinal = idaapi.get_ordinal_qty(selected_library)

            print "[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal)

            matched_types = []
            tinfo = idaapi.tinfo_t()
            for ordinal in xrange(1, max_ordinal):
                tinfo.create_typedef(selected_library, ordinal)
                if tinfo.get_size() == size:
                    name = tinfo.dstr()
                    udt_data = idaapi.udt_type_data_t()
                    tinfo.get_udt_details(udt_data)
                    tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
                    matched_types.append([str(ordinal), name, tinfo.dstr()])

            type_chooser = MyChoose(
                matched_types,
                "Select Type",
                [["Ordinal", 3 | idaapi.Choose2.CHCOL_HEX], ["Type Name", 10], ["Declaration", 40]]
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
        ea = ctx.cur_ea
        c_number = hx_view.item.e.n
        number_value = c_number._value
        ordinal = ActionGetStructureBySize.select_structure_by_size(number_value)
        if ordinal:
            number_format_old = c_number.nf
            number_format_new = idaapi.number_format_t()
            number_format_new.flags = idaapi.FF_1STRO | idaapi.FF_0STRO
            operand_number = number_format_old.opnum
            number_format_new.opnum = operand_number
            number_format_new.props = number_format_old.props
            number_format_new.type_name = idaapi.create_numbered_type_name(ordinal)

            c_function = hx_view.cfunc
            number_formats = idaapi.restore_user_numforms(c_function.entry_ea)
            if not number_formats:
                number_formats = c_function.numforms    # idaapi.user_numforms_t

            operand_locator = idaapi.operand_locator_t(ea, ord(operand_number) if operand_number else 0)
            number_formats[operand_locator] = number_format_new

            idaapi.save_user_numforms(c_function.entry_ea, number_formats)
            # idaapi.user_numforms_free(number_formats)

            hx_view.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"
    structure_builder = None
    temporary_structure = None

    def init(self):
        idaapi.msg("init() called\n")
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        MyPlugin.temporary_structure = TemporaryStructureModel()
        idaapi.register_action(ActionCreateVtable.generate())
        idaapi.register_action(ActionShowGraph.generate())
        idaapi.register_action(ActionGetStructureBySize.generate())
        idaapi.register_action(idaapi.action_desc_t("my:RemoveReturn", "Remove Return", ActionRemoveReturn()))
        idaapi.register_action(idaapi.action_desc_t("my:RemoveArgument", "Remove Argument", ActionRemoveArgument()))
        idaapi.register_action(idaapi.action_desc_t("my:ScanVariable", "Scan Variable", ActionScanVariable(MyPlugin.temporary_structure)))
        idaapi.install_hexrays_callback(hexrays_events_callback)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run() called!\n")

        if not MyPlugin.structure_builder:
            MyPlugin.structure_builder = StructureBuilder(MyPlugin.temporary_structure)
        MyPlugin.structure_builder.Show()

    def term(self):
        MyPlugin.temporary_structure.clear()
        idaapi.msg("term() called!\n")
        idaapi.remove_hexrays_callback(hexrays_events_callback)
        idaapi.unregister_action(ActionShowGraph.name)
        idaapi.unregister_action(ActionGetStructureBySize.name)
        idaapi.unregister_action("my:RemoveReturn")
        idaapi.unregister_action("my:RemoveArgument")
        idaapi.unregister_action("my:ScanVariable")
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return MyPlugin()
