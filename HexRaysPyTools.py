import logging
from HexRaysPyTools.callbacks import callback_manager, action_manager
from HexRaysPyTools.core.temporary_structure import *
import HexRaysPyTools.forms as forms
import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
import HexRaysPyTools.settings as settings
from HexRaysPyTools.core.struct_xrefs import XrefStorage


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "See https://github.com/igogo-x86/HexRaysPyTools/blob/master/readme.md"
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
