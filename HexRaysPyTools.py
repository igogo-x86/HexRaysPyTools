import sys
import idaapi
from HexRaysPyTools.Forms.StructureBuilder import *
from HexRaysPyTools.Helper.Scanner import *

# import Helper.QtShim as QtShim

temporary_structure = TemporaryStructureModel()


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


class Hooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
        if "Pseudocode" in idaapi.get_tform_title(form):
            hexrays_view = idaapi.get_tform_vdui(form)  # vdui_t structure type
            item = hexrays_view.item  # current ctree_item_t
            print item.citype

            if item.citype == idaapi.VDI_EXPR:
                pass

            elif item.citype == idaapi.VDI_FUNC:
                if not hexrays_view.cfunc.entry_ea == idaapi.BADADDR:  # Probably never happen
                    idaapi.attach_action_to_popup(form, popup, "my:RemoveReturn", None)

            elif item.citype == idaapi.VDI_LVAR:
                lvar = hexrays_view.item.get_lvar()
                if lvar.is_arg_var:
                    idaapi.attach_action_to_popup(form, popup, "my:RemoveArgument", None)
                else:
                    idaapi.attach_action_to_popup(form, popup, "my:ScanVariable", None)


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"

    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"
    hooks = Hooks()
    structure_builder = None

    def init(self):
        idaapi.msg("init() called\n")
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        idaapi.register_action(idaapi.action_desc_t("my:RemoveReturn", "Remove Return", ActionRemoveReturn()))
        idaapi.register_action(idaapi.action_desc_t("my:RemoveArgument", "Remove Argument", ActionRemoveArgument()))
        idaapi.register_action(idaapi.action_desc_t("my:ScanVariable", "Scan Variable", ActionScanVariable(temporary_structure)))
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run() called!\n")
        self.structure_builder = self.structure_builder or StructureBuilder(temporary_structure)
        self.structure_builder.Show()

    def term(self):
        idaapi.msg("term() called!\n")
        self.hooks.unhook()
        idaapi.unregister_action("my:RemoveReturn")
        idaapi.unregister_action("my:RemoveArgument")
        idaapi.unregister_action("my:ScanVariable")
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return MyPlugin()