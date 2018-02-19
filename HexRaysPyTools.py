import HexRaysPyTools.Actions as Actions
from HexRaysPyTools.Core.TemporaryStructure import *
from HexRaysPyTools.Config import *
import HexRaysPyTools.Forms as Forms
import idaapi
import HexRaysPyTools.Core.NegativeOffsets as NegativeOffsets
import HexRaysPyTools.Core.Helper as Helper
import HexRaysPyTools.Core.Const as Const
from HexRaysPyTools.Core.SpaghettiCode import SpaghettiVisitor, SwapThenElseVisitor
from HexRaysPyTools.Config import hex_pytools_config, Config
from HexRaysPyTools.Core.Helper import potential_negatives

#If I forget to add kudos in README
#Big thanks williballenthin for plugin. https://github.com/williballenthin/ida-netnode
from HexRaysPyTools.netnode import Netnode

fDebug = False
if fDebug:
    import pydevd


def hexrays_events_callback(*args):
    if fDebug:
        pydevd.settrace('localhost', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
    hexrays_event = args[0]
    from HexRaysPyTools.Config import hex_pytools_config
    if hexrays_event == idaapi.hxe_populating_popup:
        form, popup, hx_view = args[1:]
        item = hx_view.item  # current ctree_item_t

        for ac in hex_pytools_config.actions_refs.values():
            if ac.ForPopup and hex_pytools_config[ac.name] and ac.check(hx_view.cfunc,item):
                idaapi.attach_action_to_popup(form, popup, ac.name, None)

        # if Actions.RecastStructMember.check(hx_view.cfunc,item):
        #     if hex_pytools_config[Actions.RecastStructMember.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RecastStructMember.name, None)
        #
        # if Actions.SimpleCreateStruct.check(hx_view.cfunc,item):
        #     if hex_pytools_config[Actions.SimpleCreateStruct.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.SimpleCreateStruct.name, None)
        #
        # if Actions.RecastItemRight.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.RecastItemRight.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RecastItemRight.name, None)
        #
        # if Actions.RecastItemLeft.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.RecastItemLeft.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RecastItemLeft.name, None)
        #
        # if Actions.RenameOther.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.RenameOther.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RenameOther.name, None)
        #
        # if Actions.RenameInside.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.RenameInside.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RenameInside.name, None)
        #
        # if Actions.RenameOutside.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.RenameOutside.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RenameOutside.name, None)
        #
        # if Actions.SwapThenElse.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.SwapThenElse.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.SwapThenElse.name, None)
        #
        # if Actions.ShallowScanVariable.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.ShallowScanVariable.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.ShallowScanVariable.name, None)
        #     if hex_pytools_config[Actions.DeepScanVariable.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.DeepScanVariable.name, None)
        #     if hex_pytools_config[Actions.RecognizeShape.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.RecognizeShape.name, None)
        #
        # if Actions.CreateNewField.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.CreateNewField.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.CreateNewField.name, None)
        #
        # if Actions.CreateVtable.check(hx_view.cfunc, item):
        #     if hex_pytools_config[Actions.CreateVtable.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.CreateVtable.name, None)
        #
        # if Actions.AddRemoveReturn.check(hx_view.cfunc, item) and hex_pytools_config[Actions.AddRemoveReturn.name]:
        #     idaapi.attach_action_to_popup(form, popup, Actions.AddRemoveReturn.name, None)
        # if Actions.ConvertToUsercall.check(hx_view.cfunc, item) and hex_pytools_config[Actions.ConvertToUsercall.name]:
        #     idaapi.attach_action_to_popup(form, popup, Actions.ConvertToUsercall.name, None)
        # if Actions.DeepScanReturn.check(hx_view.cfunc, item) and hex_pytools_config[Actions.DeepScanReturn.name]:
        #     idaapi.attach_action_to_popup(form, popup, Actions.DeepScanReturn.name, None)
        #
        # if Actions.RemoveArgument.check(hx_view.cfunc,item) and hex_pytools_config[Actions.RemoveArgument.name]:
        #     idaapi.attach_action_to_popup(form, popup, Actions.RemoveArgument.name, None)
        #
        # if Actions.GetStructureBySize.check(hx_view.cfunc,item) and hex_pytools_config[Actions.GetStructureBySize.name]:
        #     idaapi.attach_action_to_popup(form, popup, Actions.GetStructureBySize.name, None)
        #
        # if Actions.SelectContainingStructure.check(hx_view.cfunc,item) and hex_pytools_config[Actions.SelectContainingStructure.name]:
        #     idaapi.attach_action_to_popup(form, popup, Actions.SelectContainingStructure.name, None)
        #
        # if Actions.ResetContainingStructure.check(hx_view.cfunc,item):
        #     if hex_pytools_config[Actions.ResetContainingStructure.name]:
        #         idaapi.attach_action_to_popup(form, popup, Actions.ResetContainingStructure.name, None)

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
                return 0
            #print vtable_tinfo.get_type_name()
            #print method_offset
            udt_member = idaapi.udt_member_t()
            udt_member.offset = method_offset * 8
            vtable_tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)

            func_ea = Helper.get_virtual_func_address(udt_member.name, class_tinfo, vtable_offset)
            if func_ea:
                idaapi.open_pseudocode(func_ea, 0)
                return 1
            n = Netnode("$ VTables")
            vt_name = vtable_tinfo.get_type_name()
            if vt_name in n:
                l = n[vt_name]
                #print l
                info = idaapi.get_inf_structure()
                if info.is_32bit():
                    ptr_size = 4
                elif info.is_64bit():
                    ptr_size = 8
                else:
                    ptr_size = 2
                if method_offset%ptr_size == 0 and method_offset/ptr_size < len(l):
                    idaapi.open_pseudocode(l[method_offset/ptr_size] + idaapi.get_imagebase(), 0)


    elif hexrays_event == idaapi.hxe_maturity:
        cfunc, level_of_maturity = args[1:]

        if level_of_maturity == idaapi.CMAT_BUILT:
            # print '=' * 40
            # print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            # print '=' * 40
            # print cfunc

            # First search for CONTAINING_RECORD made by Ida
            visitor = NegativeOffsets.SearchVisitor(cfunc)
            visitor.apply_to(cfunc.body, None)
            negative_lvars = visitor.result

            # Second get saved information from comments
            lvars = cfunc.get_lvars()
            for idx in xrange(len(lvars)):
                result = NegativeOffsets.parse_lvar_comment(lvars[idx])
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
                visitor = NegativeOffsets.AnalyseVisitor(structure_pointer_variables, potential_negatives)
                visitor.apply_to(cfunc.body, None)

            if negative_lvars:
                visitor = NegativeOffsets.ReplaceVisitor(negative_lvars)
                visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_TRANS1:

            visitor = SwapThenElseVisitor(cfunc.entry_ea)
            visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_TRANS2:
            return 0
            # print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            # print '=' * 40
            # print cfunc
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)
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
        if fDebug:
            pydevd.settrace('localhost', port=31337, stdoutToServer=True, stderrToServer=True,suspend=False)
        if not idaapi.init_hexrays_plugin():
            print "[ERROR] Failed to initialize Hex-Rays SDK"
            return idaapi.PLUGIN_SKIP

        Helper.temporary_structure = TemporaryStructureModel()
        hex_pytools_config = Config()
        for ac in hex_pytools_config.actions:
            if hex_pytools_config.actions[ac]:
                Actions.register(hex_pytools_config.actions_refs[ac])
        # Actions.register(Actions.CreateVtable)
        # Actions.register(Actions.ShowGraph)
        # Actions.register(Actions.ShowClasses)
        # Actions.register(Actions.GetStructureBySize)
        # Actions.register(Actions.RemoveArgument)
        # Actions.register(Actions.AddRemoveReturn)
        # Actions.register(Actions.ConvertToUsercall)
        # Actions.register(Actions.ShallowScanVariable, Helper.temporary_structure)
        # Actions.register(Actions.DeepScanVariable, Helper.temporary_structure)
        # Actions.register(Actions.RecognizeShape)
        # Actions.register(Actions.SelectContainingStructure, potential_negatives)
        # Actions.register(Actions.ResetContainingStructure)
        # Actions.register(Actions.RecastItemRight)
        # Actions.register(Actions.RecastItemLeft)
        # Actions.register(Actions.RenameInside)
        # Actions.register(Actions.RenameOutside)

        idaapi.attach_action_to_menu('View/Open subviews/Local types', Actions.ShowClasses.name, idaapi.SETMENU_APP)
        idaapi.install_hexrays_callback(hexrays_events_callback)

        Helper.touched_functions.clear()
        Const.init()

        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(arg):
        tform = idaapi.find_tform("Structure Builder")
        if tform:
            idaapi.switchto_tform(tform, True)
        else:
            Forms.StructureBuilder(Helper.temporary_structure).Show()

    @staticmethod
    def term():
        if Helper.temporary_structure:
            Helper.temporary_structure.clear()
        # Actions.unregister(Actions.CreateVtable)
        if hex_pytools_config:
            for ac in hex_pytools_config.actions:
                if hex_pytools_config.actions[ac]:
                    Actions.unregister(hex_pytools_config.actions_refs[ac])
        # Actions.unregister(Actions.ShowGraph)
        # Actions.unregister(Actions.ShowClasses)
        # Actions.unregister(Actions.GetStructureBySize)
        # Actions.unregister(Actions.RemoveArgument)
        # Actions.unregister(Actions.AddRemoveReturn)
        # Actions.unregister(Actions.ConvertToUsercall)
        # Actions.unregister(Actions.ShallowScanVariable)
        # Actions.unregister(Actions.DeepScanVariable)
        # Actions.unregister(Actions.DeepScanReturn)
        # Actions.unregister(Actions.RecognizeShape)
        # Actions.unregister(Actions.SelectContainingStructure)
        # Actions.unregister(Actions.ResetContainingStructure)
        # Actions.unregister(Actions.RecastItemRight)
        # Actions.unregister(Actions.RecastItemLeft)
        # Actions.unregister(Actions.RenameOther)
        # Actions.unregister(Actions.RenameInside)
        # Actions.unregister(Actions.RenameOutside)
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    print "HexRaysPyTools PLUGIN_ENTRY"
    idaapi.notify_when(idaapi.NW_OPENIDB, Helper.init_demangled_names)
    return MyPlugin()
