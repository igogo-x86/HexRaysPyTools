import logging
import idaapi

import HexRaysPyTools.actions as actions
from HexRaysPyTools.core.temporary_structure import *
import HexRaysPyTools.forms as forms
import HexRaysPyTools.core.negative_offsets as negative_offsets
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
from HexRaysPyTools.core.spaghetti_code import SpaghettiVisitor, SwapThenElseVisitor
from HexRaysPyTools.core.struct_xrefs import *

potential_negatives = {}


def hexrays_events_callback(*args):
    global potential_negatives

    hexrays_event = args[0]

    if hexrays_event == idaapi.hxe_populating_popup:
        form, popup, hx_view = args[1:]
        item = hx_view.item  # current ctree_item_t

        if actions.GuessAllocation.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.GuessAllocation.name, None)

        if actions.RecastItemRight.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.RecastItemRight.name, None)

        if actions.RecastItemLeft.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.RecastItemLeft.name, None)

        if actions.RenameOther.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.RenameOther.name, None)

        if actions.RenameInside.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.RenameInside.name, None)

        if actions.RenameOutside.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.RenameOutside.name, None)

        if actions.RenameUsingAssert.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.RenameUsingAssert.name, None)

        if actions.SwapThenElse.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.SwapThenElse.name, None)

        if actions.ShallowScanVariable.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.ShallowScanVariable.name, None)
            idaapi.attach_action_to_popup(form, popup, actions.DeepScanVariable.name, None)
            idaapi.attach_action_to_popup(form, popup, actions.RecognizeShape.name, None)

        if actions.CreateNewField.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.CreateNewField.name, None)

        if actions.FindFieldXrefs.check(item):
            idaapi.attach_action_to_popup(form, popup, actions.FindFieldXrefs.name, None)

        if actions.PropagateName.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, actions.PropagateName.name, None)

        if item.citype == idaapi.VDI_FUNC:
            # If we clicked on function
            if not hx_view.cfunc.entry_ea == idaapi.BADADDR:  # Probably never happen
                idaapi.attach_action_to_popup(form, popup, actions.AddRemoveReturn.name, None)
                idaapi.attach_action_to_popup(form, popup, actions.ConvertToUsercall.name, None)
                if actions.DeepScanReturn.check(hx_view):
                    idaapi.attach_action_to_popup(form, popup, actions.DeepScanReturn.name, None)

        elif item.citype == idaapi.VDI_LVAR:
            # If we clicked on argument
            local_variable = hx_view.item.get_lvar()          # idaapi.lvar_t
            if local_variable.is_arg_var:
                idaapi.attach_action_to_popup(form, popup, actions.RemoveArgument.name, None)

        elif item.citype == idaapi.VDI_EXPR:
            if item.e.op == idaapi.cot_num:
                # number_format = item.e.n.nf                       # idaapi.number_format_t
                # print "(number) flags: {0:#010X}, type_name: {1}, opnum: {2}".format(
                #     number_format.flags,
                #     number_format.type_name,
                #     number_format.opnum
                # )
                idaapi.attach_action_to_popup(form, popup, actions.GetStructureBySize.name, None)
            elif item.e.op == idaapi.cot_var:
                # Check if we clicked on variable that is a pointer to a structure that is potentially part of
                # containing structure
                if item.e.v.idx in potential_negatives:
                    idaapi.attach_action_to_popup(form, popup, actions.SelectContainingStructure.name, None)
                if actions.ResetContainingStructure.check(hx_view.cfunc.get_lvars()[item.e.v.idx]):
                    idaapi.attach_action_to_popup(form, popup, actions.ResetContainingStructure.name, None)

    elif hexrays_event == idaapi.hxe_double_click:
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

    elif hexrays_event == idaapi.hxe_maturity:
        cfunc, level_of_maturity = args[1:]

        if level_of_maturity == idaapi.CMAT_BUILT:
            # print '=' * 40
            # print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            # print '=' * 40
            # print cfunc

            # First search for CONTAINING_RECORD made by Ida
            visitor = negative_offsets.SearchVisitor(cfunc)
            visitor.apply_to(cfunc.body, None)
            negative_lvars = visitor.result

            # Second get saved information from comments
            lvars = cfunc.get_lvars()
            for idx in xrange(len(lvars)):
                result = negative_offsets.parse_lvar_comment(lvars[idx])
                if result and result.tinfo.equals_to(lvars[idx].type().get_pointed_object()):
                    negative_lvars[idx] = result

            # Third make an analysis of local variables that a structure pointers and have reference that pass
            # through structure boundaries. This variables will be considered as potential pointers to substructure
            # and will get a menu on right click that helps to select Containing Structure from different libraries

            structure_pointer_variables = {}
            for idx in set(range(len(lvars))) - set(negative_lvars.keys()):
                if lvars[idx].type().is_ptr():
                    pointed_tinfo = lvars[idx].type().get_pointed_object()
                    if pointed_tinfo.is_udt():
                        structure_pointer_variables[idx] = pointed_tinfo

            if structure_pointer_variables:
                visitor = negative_offsets.AnalyseVisitor(structure_pointer_variables, potential_negatives)
                visitor.apply_to(cfunc.body, None)

            if negative_lvars:
                visitor = negative_offsets.ReplaceVisitor(negative_lvars)
                visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_TRANS1:

            visitor = SwapThenElseVisitor(cfunc.entry_ea)
            visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_TRANS2:
            # print '=' * 40
            # print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            # print '=' * 40
            # print cfunc
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_FINAL:
            StructXrefVisitor(cfunc).process()

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
        # Actions.register(Actions.CreateVtable)
        actions.register(actions.ShowGraph)
        actions.register(actions.ShowClasses)
        actions.register(actions.GetStructureBySize)
        actions.register(actions.RemoveArgument)
        actions.register(actions.AddRemoveReturn)
        actions.register(actions.ConvertToUsercall)
        actions.register(actions.ShallowScanVariable, cache.temporary_structure)
        actions.register(actions.DeepScanVariable, cache.temporary_structure)
        actions.register(actions.DeepScanReturn, cache.temporary_structure)
        actions.register(actions.DeepScanFunctions, cache.temporary_structure)
        actions.register(actions.RecognizeShape)
        actions.register(actions.CreateNewField)
        actions.register(actions.SelectContainingStructure, potential_negatives)
        actions.register(actions.ResetContainingStructure)
        actions.register(actions.RecastItemRight)
        actions.register(actions.RecastItemLeft)
        actions.register(actions.RenameOther)
        actions.register(actions.RenameInside)
        actions.register(actions.RenameOutside)
        actions.register(actions.RenameUsingAssert)
        actions.register(actions.SwapThenElse)
        actions.register(actions.FindFieldXrefs)
        actions.register(actions.PropagateName)
        actions.register(actions.GuessAllocation)

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
        # Actions.unregister(Actions.CreateVtable)
        actions.unregister(actions.ShowGraph)
        actions.unregister(actions.ShowClasses)
        actions.unregister(actions.GetStructureBySize)
        actions.unregister(actions.RemoveArgument)
        actions.unregister(actions.AddRemoveReturn)
        actions.unregister(actions.ConvertToUsercall)
        actions.unregister(actions.ShallowScanVariable)
        actions.unregister(actions.DeepScanVariable)
        actions.unregister(actions.DeepScanReturn)
        actions.unregister(actions.DeepScanFunctions)
        actions.unregister(actions.RecognizeShape)
        actions.unregister(actions.CreateNewField)
        actions.unregister(actions.SelectContainingStructure)
        actions.unregister(actions.ResetContainingStructure)
        actions.unregister(actions.RecastItemRight)
        actions.unregister(actions.RecastItemLeft)
        actions.unregister(actions.RenameOther)
        actions.unregister(actions.RenameInside)
        actions.unregister(actions.RenameOutside)
        actions.unregister(actions.RenameUsingAssert)
        actions.unregister(actions.SwapThenElse)
        actions.unregister(actions.FindFieldXrefs)
        actions.unregister(actions.PropagateName)
        actions.unregister(actions.GuessAllocation)
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
