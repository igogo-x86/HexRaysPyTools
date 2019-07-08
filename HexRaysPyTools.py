import logging
import HexRaysPyTools.actions as actions
from HexRaysPyTools.callbacks import callback_manager, action_manager
from HexRaysPyTools.core.temporary_structure import *
import HexRaysPyTools.forms as forms
import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
import HexRaysPyTools.settings as settings
from HexRaysPyTools.core.struct_xrefs import XrefStorage


def hexrays_events_callback(*args):
    hexrays_event = args[0]
    if hexrays_event == idaapi.hxe_double_click:
        hx_view = args[1]
        item = hx_view.item
        if item.citype == idaapi.VDI_EXPR and item.e.op == idaapi.cot_memptr:
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset
            if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.x.m
            elif item.e.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m
            else:
                func_offset = item.e.m
                struct_tinfo = item.e.x.type.get_pointed_object()
                func_ea = helper.choose_virtual_func_address(helper.get_member_name(struct_tinfo, func_offset))
                if func_ea:
                    idaapi.jumpto(func_ea)
                return 0

            func_name = helper.get_member_name(vtable_tinfo, method_offset)
            func_ea = helper.choose_virtual_func_address(func_name, class_tinfo, vtable_offset)
            if func_ea:
                idaapi.open_pseudocode(func_ea, 0)
                return 1
    return 0


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "This is help"
    wanted_name = "HexRaysPyTools"
    wanted_hotkey = "Alt-F8"

    @staticmethod
    def init():
        if not idaapi.init_hexrays_plugin():
            print "[ERROR] Failed to initialize Hex-Rays SDK"
            return idaapi.PLUGIN_SKIP

        cache.temporary_structure = TemporaryStructureModel()
        action_manager.initialize()
        callback_manager.initialize()
        actions.register(actions.CreateVtable)
        actions.register(actions.ShowGraph)
        actions.register(actions.ShowClasses)

        idaapi.attach_action_to_menu('View/Open subviews/Local types', actions.ShowClasses.name, idaapi.SETMENU_APP)
        idaapi.install_hexrays_callback(hexrays_events_callback)

        const.init()
        XrefStorage().open()

        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(arg):
        tform = idaapi.find_tform("Structure Builder")
        if tform:
            idaapi.switchto_tform(tform, True)
        else:
            forms.StructureBuilder(cache.temporary_structure).Show()

    @staticmethod
    def term():
        if cache.temporary_structure:
            cache.temporary_structure.clear()

        action_manager.finalize()
        callback_manager.finalize()
        actions.unregister(actions.CreateVtable)
        actions.unregister(actions.ShowGraph)
        actions.unregister(actions.ShowClasses)
        idaapi.term_hexrays_plugin()
        XrefStorage().close()


def PLUGIN_ENTRY():
    settings.load_settings()
    logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    logging.root.setLevel(settings.DEBUG_MESSAGE_LEVEL)
    idaapi.notify_when(idaapi.NW_OPENIDB, cache.init_demangled_names)
    idaapi.notify_when(idaapi.NW_OPENIDB, cache.init_imported_ea)
    idaapi.notify_when(idaapi.NW_OPENIDB, cache.reset_touched_functions)
    helper.extend_ida()
    return MyPlugin()
