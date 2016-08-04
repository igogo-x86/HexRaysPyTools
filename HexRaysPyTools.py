import sys
import idaapi
from HexRaysPyTools.Forms.StructureBuilder import *
from HexRaysPyTools.Forms.StructureGraphForm import *
from HexRaysPyTools.Helper.Scanner import *

# import Helper.QtShim as QtShim

temporary_structure = TemporaryStructureModel()


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


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"

    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"
    structure_builder = None

    def init(self):
        idaapi.msg("init() called\n")
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        idaapi.register_action(ActionShowGraph.generate())
        idaapi.register_action(idaapi.action_desc_t("my:RemoveReturn", "Remove Return", ActionRemoveReturn()))
        idaapi.register_action(idaapi.action_desc_t("my:RemoveArgument", "Remove Argument", ActionRemoveArgument()))
        idaapi.register_action(idaapi.action_desc_t("my:ScanVariable", "Scan Variable", ActionScanVariable(temporary_structure)))
        idaapi.install_hexrays_callback(hexrays_events_callback)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run() called!\n")

        if not MyPlugin.structure_builder:
           MyPlugin.structure_builder = StructureBuilder(temporary_structure)
        MyPlugin.structure_builder.Show()

    def term(self):
        idaapi.msg("term() called!\n")
        idaapi.remove_hexrays_callback(hexrays_events_callback)
        idaapi.unregister_action(ActionShowGraph.name)
        idaapi.unregister_action("my:RemoveReturn")
        idaapi.unregister_action("my:RemoveArgument")
        idaapi.unregister_action("my:ScanVariable")
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return MyPlugin()
