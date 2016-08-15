import HexRaysPyTools.Actions as Actions
from HexRaysPyTools.Core.TemporaryStructure import *
import HexRaysPyTools.Forms as Forms
import idaapi
import HexRaysPyTools.Core.NegativeOffsets as NegativeOffsets

# import Core.QtShim as QtShim

potential_negatives = {}


def hexrays_events_callback(*args):
    global potential_negatives

    hexrays_event = args[0]
    if hexrays_event == idaapi.hxe_keyboard:
        hx_view, key, shift = args[1:]
        if key == ord('F'):
            if Actions.ScanVariable.check(hx_view.cfunc, hx_view.item):
                idaapi.process_ui_action(Actions.ScanVariable.name)

    elif hexrays_event == idaapi.hxe_populating_popup:
        print args
        form, popup, hx_view = args[1:]
        item = hx_view.item  # current ctree_item_t
        print item.citype

        if Actions.ScanVariable.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.ScanVariable.name, None)

        if item.citype == idaapi.VDI_FUNC:
            # If we clicked on function
            if not hx_view.cfunc.entry_ea == idaapi.BADADDR:  # Probably never happen
                idaapi.attach_action_to_popup(form, popup, Actions.RemoveReturn.name, None)
                idaapi.attach_action_to_popup(form, popup, Actions.ConvertToUsercall.name, None)

        elif item.citype == idaapi.VDI_LVAR:
            # If we clicked on argument
            local_variable = hx_view.item.get_lvar()          # idaapi.lvar_t
            if local_variable.is_arg_var:
                idaapi.attach_action_to_popup(form, popup, Actions.RemoveArgument.name, None)

        elif item.citype == idaapi.VDI_EXPR:
            if item.e.op == idaapi.cot_num:
                number_format = item.e.n.nf                       # idaapi.number_format_t
                print "(number) flags: {0:#010X}, type_name: {1}, opnum: {2}".format(
                    number_format.flags,
                    number_format.type_name,
                    number_format.opnum
                )
                idaapi.attach_action_to_popup(form, popup, Actions.GetStructureBySize.name, None)
            elif item.e.op == idaapi.cot_var:
                # Check if we clicked on variable that is a pointer to a structure that is potentially part of
                # containing structure
                if item.e.v.idx in potential_negatives:
                    idaapi.attach_action_to_popup(form, popup, Actions.SelectContainingStructure.name, None)
                if Actions.ResetContainingStructure.check(hx_view.cfunc.get_lvars()[item.e.v.idx]):
                    idaapi.attach_action_to_popup(form, popup, Actions.ResetContainingStructure.name, None)

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
                        name = idaapi.get_short_name(function.startEA)
                        name = name.split('(')[0]
                        name = name.replace("`", '').replace("_", '').replace("'", '')
                        if name == member_name:
                            idaapi.open_pseudocode(function.startEA, 0)
                            return 1
    elif hexrays_event == idaapi.hxe_maturity:
        cfunc, level_of_maturity = args[1:]

        if level_of_maturity == idaapi.CMAT_BUILT:
            print '=' * 40
            print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            print '=' * 40
            print cfunc

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
                # NegativeOffsets.ReplaceVisitor.del_list[:] = []
                visitor = NegativeOffsets.ReplaceVisitor(negative_lvars)
                visitor.apply_to(cfunc.body, None)
                # hx_view.set_lvar_cmt(lvar, old + lvar.name)
        elif level_of_maturity == idaapi.CMAT_TRANS1:
            print '=' * 40
            print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            print '=' * 40
            print cfunc
    return 0


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"
    structure_builder = None
    temporary_structure = None

    @staticmethod
    def init():
        idaapi.msg("init() called\n")
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        MyPlugin.temporary_structure = TemporaryStructureModel()

        Actions.register(Actions.CreateVtable)
        Actions.register(Actions.ShowGraph)
        Actions.register(Actions.GetStructureBySize)
        Actions.register(Actions.RemoveArgument)
        Actions.register(Actions.RemoveReturn)
        Actions.register(Actions.ConvertToUsercall)
        Actions.register(Actions.ScanVariable, MyPlugin.temporary_structure)
        Actions.register(Actions.SelectContainingStructure, potential_negatives)
        Actions.register(Actions.ResetContainingStructure)

        idaapi.install_hexrays_callback(hexrays_events_callback)

        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(arg):
        idaapi.msg("run() called!\n")

        if not MyPlugin.structure_builder:
            MyPlugin.structure_builder = Forms.StructureBuilder(MyPlugin.temporary_structure)
        MyPlugin.structure_builder.Show()

    @staticmethod
    def term():
        MyPlugin.temporary_structure.clear()
        idaapi.msg("term() called!\n")
        Actions.unregister(Actions.CreateVtable)
        Actions.unregister(Actions.ShowGraph)
        Actions.unregister(Actions.GetStructureBySize)
        Actions.unregister(Actions.RemoveArgument)
        Actions.unregister(Actions.RemoveReturn)
        Actions.unregister(Actions.ConvertToUsercall)
        Actions.unregister(Actions.ScanVariable)
        Actions.unregister(Actions.SelectContainingStructure)
        Actions.unregister(Actions.ResetContainingStructure)
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return MyPlugin()
