import ctypes
import sys
import re
import struct

import idaapi
import idc

import HexRaysPyTools.Forms as Forms
import HexRaysPyTools.Core.Const as Const
import HexRaysPyTools.Core.Helper as Helper
from HexRaysPyTools.Core.StructureGraph import StructureGraph
from HexRaysPyTools.Core.TemporaryStructure import VirtualTable, TemporaryStructureModel
from HexRaysPyTools.Core.VariableScanner import ShallowSearchVisitor, DeepSearchVisitor, VariableLookupVisitor
from HexRaysPyTools.Core.Helper import FunctionTouchVisitor
from HexRaysPyTools.Core.Helper import potential_negatives


RECAST_LOCAL_VARIABLE = 0
RECAST_GLOBAL_VARIABLE = 1
RECAST_ARGUMENT = 2
RECAST_RETURN = 3
RECAST_STRUCTURE = 4


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


class TypeLibrary:

    class til_t(ctypes.Structure):
        pass

    til_t._fields_ = [
        ("name", ctypes.c_char_p),
        ("desc", ctypes.c_char_p),
        ("nbases", ctypes.c_int),
        ("base", ctypes.POINTER(ctypes.POINTER(til_t)))
    ]

    def __init__(self):
        pass

    @staticmethod
    def enable_library_ordinals(library_num):
        idaname = "ida64" if Const.EA64 else "ida"
        if sys.platform == "win32":
            dll = ctypes.windll[idaname + ".wll"]
        elif sys.platform == "linux2":
            dll = ctypes.cdll["lib" + idaname + ".so"]
        elif sys.platform == "darwin":
            dll = ctypes.cdll["lib" + idaname + ".dylib"]
        else:
            print "[ERROR] Failed to enable ordinals"
            return

        idati = ctypes.POINTER(TypeLibrary.til_t).in_dll(dll, "idati")
        dll.enable_numbered_types(idati.contents.base[library_num], True)

    @staticmethod
    def choose_til():
        idati = idaapi.cvar.idati
        list_type_library = [(idati, idati.name, idati.desc)]
        for idx in xrange(idaapi.cvar.idati.nbases):
            type_library = idaapi.cvar.idati.base(idx)          # idaapi.til_t type
            list_type_library.append((type_library, type_library.name, type_library.desc))

        library_chooser = Forms.MyChoose(
            list(map(lambda x: [x[1], x[2]], list_type_library)),
            "Select Library",
            [["Library", 10 | idaapi.Choose2.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose2.CHCOL_PLAIN]],
            69
        )
        library_num = library_chooser.Show(True)
        if library_num != -1:
            selected_library = list_type_library[library_num][0]
            max_ordinal = idaapi.get_ordinal_qty(selected_library)
            if max_ordinal == idaapi.BADORD:
                TypeLibrary.enable_library_ordinals(library_num - 1)
                max_ordinal = idaapi.get_ordinal_qty(selected_library)
            print "[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal)
            return selected_library, max_ordinal, library_num == 0
        return None

    @staticmethod
    def import_type(library, name):
        if library.name != idaapi.cvar.idati.name:
            last_ordinal = idaapi.get_ordinal_qty(idaapi.cvar.idati)
            type_id = idaapi.import_type(library, -1, name)  # tid_t
            if type_id != idaapi.BADORD:
                return last_ordinal
        return None


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


class AddRemoveReturn(idaapi.action_handler_t):

    name = "my:RemoveReturn"
    description = "Add/Remove Return"
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
        if function_details.rettype.equals_to(Const.VOID_TINFO):
            function_details.rettype = idaapi.tinfo_t(Const.PVOID_TINFO)
        else:
            function_details.rettype = idaapi.tinfo_t(idaapi.BT_VOID)
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ConvertToUsercall(idaapi.action_handler_t):

    name = "my:ConvertToUsercall"
    description = "Convert to __usercall"
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
        convention = idaapi.CM_CC_MASK & function_details.cc
        if convention == idaapi.CM_CC_CDECL:
            function_details.cc = idaapi.CM_CC_SPECIAL
        elif convention in (idaapi.CM_CC_STDCALL, idaapi.CM_CC_FASTCALL, idaapi.CM_CC_PASCAL, idaapi.CM_CC_THISCALL):
            function_details.cc = idaapi.CM_CC_SPECIALP
        elif convention == idaapi.CM_CC_ELLIPSIS:
            function_details.cc = idaapi.CM_CC_SPECIALE
        else:
            return
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GetStructureBySize(idaapi.action_handler_t):
    # TODO: apply type automatically if expression like `var = new(size)`

    name = "my:WhichStructHaveThisSize"
    description = "Structures with this size"
    hotkey = "W"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def select_structure_by_size(size):
        result = TypeLibrary.choose_til()
        if result:
            selected_library, max_ordinal, is_local_type = result
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
                [["Ordinal", 5 | idaapi.Choose2.CHCOL_HEX], ["Type Name", 25], ["Declaration", 50]],
                165
            )
            selected_type = type_chooser.Show(True)
            if selected_type != -1:
                if is_local_type:
                    return int(matched_types[selected_type][0])
                return TypeLibrary.import_type(selected_library, matched_types[selected_type][1])
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
        return idaapi.AST_DISABLE_FOR_FORM


class ShallowScanVariable(idaapi.action_handler_t):

    name = "my:ShallowScanVariable"
    description = "Scan Variable"
    hotkey = "F"

    def __init__(self):
        self.temporary_structure = Helper.temporary_structure
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        variable = hx_view.item.get_lvar()  # lvar_t
        if variable and Helper.is_legal_type(variable.type()):
            index = list(hx_view.cfunc.get_lvars()).index(variable)
            scanner = ShallowSearchVisitor(hx_view.cfunc, self.temporary_structure.main_offset, index)
            scanner.process()
            for field in scanner.candidates:
                self.temporary_structure.add_row(field)
            scanner.clear()

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanVariable(idaapi.action_handler_t):

    name = "my:DeepScanVariable"
    description = "Deep Scan Variable"
    hotkey = "shift+F"

    def __init__(self):
        self.temporary_structure = Helper.temporary_structure
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        variable = hx_view.item.get_lvar()  # lvar_t
        self.scan(hx_view, variable)

    def scan(self, hx_view, variable):
        if variable and Helper.is_legal_type(variable.type()):

            definition_address = None if variable.is_arg_var else variable.defea
            index = list(hx_view.cfunc.get_lvars()).index(variable)

            # index = list(hx_view.cfunc.get_lvars()).index(variable)
            if FunctionTouchVisitor(hx_view.cfunc).process():
                hx_view.refresh_view(True)

            # Because index of the variable can be changed after touching, we would like to calculate it appropriately

            for idx, lvar in enumerate(hx_view.cfunc.get_lvars()):
                print idx, hex(int(lvar.defea))

            lvars = hx_view.cfunc.get_lvars()

            if definition_address:
                index = next(x for x in xrange(len(lvars)) if lvars[x].defea == definition_address)

            scanner = DeepSearchVisitor(hx_view.cfunc, self.temporary_structure.main_offset, index)
            scanner.process()
            for field in scanner.candidates:
                self.temporary_structure.add_row(field)
            scanner.clear()

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanReturn(idaapi.action_handler_t):

    name = "my:DeepScanReturn"
    description = "Deep Scan Returned Variables"
    hotkey = None

    def __init__(self):
        self.temporary_structure = Helper.temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        return hx_view.cfunc.get_rettype().equals_to(Const.VOID_TINFO)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        address = hx_view.cfunc.entry_ea

        xref_ea = idaapi.get_first_cref_to(address)
        xrefs = set()
        while xref_ea != idaapi.BADADDR:
            xref_func_ea = idc.GetFunctionAttr(xref_ea, idc.FUNCATTR_START)
            if xref_func_ea != idaapi.BADADDR:
                xrefs.add(xref_func_ea)
            else:
                print "[Warning] Function not found at 0x{0:08X}".format(xref_ea)
            xref_ea = idaapi.get_next_cref_to(address, xref_ea)

        for func_ea in xrefs:
            visitor = VariableLookupVisitor(address)

            try:
                cfunc = idaapi.decompile(func_ea)
                if cfunc:
                    FunctionTouchVisitor(cfunc).process()
                    visitor.apply_to(cfunc.body, None)
                    for idx in visitor.result:
                        scanner = DeepSearchVisitor(cfunc, 0, idx)
                        scanner.process()
                        for field in scanner.candidates:
                            self.temporary_structure.add_row(field)

            except idaapi.DecompilationFailure:
                print "[Warning] Failed to decompile function at 0x{0:08X}".format(xref_ea)

        DeepSearchVisitor.clear()

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RecognizeShape(idaapi.action_handler_t):

    name = "my:RecognizeShape"
    description = "Recognize Shape"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        variable = hx_view.item.get_lvar()  # lvar_t
        if variable and filter(lambda x: x.equals_to(variable.type()), Const.LEGAL_TYPES):
            index = list(hx_view.cfunc.get_lvars()).index(variable)
            scanner = ShallowSearchVisitor(hx_view.cfunc, 0, index)
            scanner.process()
            structure = TemporaryStructureModel()
            for field in scanner.candidates:
                structure.add_row(field)
            tinfo = structure.get_recognized_shape()
            if tinfo:
                tinfo.create_ptr(tinfo)
                hx_view.set_lvar_type(variable, tinfo)
                hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
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
            self.graph_view.change_selected(list(ctx.chooser_selection))
            self.graph_view.Show()
        else:
            self.graph = StructureGraph(list(ctx.chooser_selection))
            self.graph_view = Forms.StructureGraphViewer("Structure Graph", self.graph)
            self.graph_view.Show()

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_LOCTYPS:
            idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class ShowClasses(idaapi.action_handler_t):

    name = "my:ShowClasses"
    description = "Classes"
    hotkey = "Alt+F1"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        tform = idaapi.find_tform('Classes')
        if not tform:
            class_viewer = Forms.ClassViewer()
            class_viewer.Show()
        else:
            idaapi.switchto_tform(tform, True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# class CreateVtable(idaapi.action_handler_t):
#
#     name = "my:CreateVtable"
#     description = "Create Virtual Table"
#     hotkey = "V"
#
#     def __init__(self):
#         idaapi.action_handler_t.__init__(self)
#
#     def activate(self, ctx):
#         ea = ctx.cur_ea
#         if ea != idaapi.BADADDR and VirtualTable.check_address(ea):
#             vtable = VirtualTable(0, ea)
#             vtable.import_to_structures(True)
#
#     def update(self, ctx):
#         if ctx.form_type == idaapi.BWN_DISASM:
#             idaapi.attach_action_to_popup(ctx.form, None, self.name)
#             return idaapi.AST_ENABLE_FOR_FORM
#         return idaapi.AST_DISABLE_FOR_FORM


class SelectContainingStructure(idaapi.action_handler_t):

    name = "my:SelectContainingStructure"
    description = "Select Containing Structure"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.potential_negative = potential_negatives

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        result = TypeLibrary.choose_til()
        if result:
            selected_library, max_ordinal, is_local_types = result
            lvar_idx = hx_view.item.e.v.idx
            candidate = self.potential_negative[lvar_idx]
            structures = candidate.find_containing_structures(selected_library)
            items = map(lambda x: [str(x[0]), "0x{0:08X}".format(x[1]), x[2], x[3]], structures)
            structure_chooser = Forms.MyChoose(
                items,
                "Select Containing Structure",
                [["Ordinal", 5], ["Offset", 10], ["Member_name", 20], ["Structure Name", 20]],
                165
            )
            selected_idx = structure_chooser.Show(modal=True)
            if selected_idx != -1:
                if not is_local_types:
                    TypeLibrary.import_type(selected_library, items[selected_idx][3])
                lvar = hx_view.cfunc.get_lvars()[lvar_idx]
                lvar_cmt = re.sub("```.*```", '', lvar.cmt)
                hx_view.set_lvar_cmt(
                    lvar,
                    lvar_cmt + "```{0}+{1}```".format(
                        structures[selected_idx][3],
                        structures[selected_idx][1])
                )
                hx_view.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ResetContainingStructure(idaapi.action_handler_t):

    name = "my:ResetContainingStructure"
    description = "Reset Containing Structure"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(lvar):
        return True if re.search("```.*```", lvar.cmt) else False

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        lvar = hx_view.cfunc.get_lvars()[hx_view.item.e.v.idx]
        hx_view.set_lvar_cmt(lvar, re.sub("```.*```", '', lvar.cmt))
        hx_view.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class RecastItemLeft(idaapi.action_handler_t):

    name = "my:RecastItemLeft"
    description = "Recast Item"
    hotkey = "Shift+L"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR:
            expression = ctree_item.it.to_specific_type

            child = None
            while expression and expression.op not in (idaapi.cot_asg, idaapi.cit_return, idaapi.cot_call):
                child = expression.to_specific_type
                expression = cfunc.body.find_parent_of(expression)

            if expression:
                expression = expression.to_specific_type
                if expression.op == idaapi.cot_asg and \
                        expression.x.op in (idaapi.cot_var, idaapi.cot_obj, idaapi.cot_memptr, idaapi.cot_memref):

                    right_expr = expression.y
                    right_tinfo = right_expr.x.type if right_expr.op == idaapi.cot_cast else right_expr.type

                    # Check if both left and right parts of expression are of the same types.
                    # If no then we can recast then.
                    if right_tinfo.dstr() == expression.x.type.dstr():
                        return

                    if expression.x.op == idaapi.cot_var:
                        variable = cfunc.get_lvars()[expression.x.v.idx]
                        idaapi.update_action_label(RecastItemLeft.name, 'Recast Variable "{0}"'.format(variable.name))
                        return RECAST_LOCAL_VARIABLE, right_tinfo, variable
                    elif expression.x.op == idaapi.cot_obj:
                        idaapi.update_action_label(RecastItemLeft.name, 'Recast Global')
                        return RECAST_GLOBAL_VARIABLE, right_tinfo, expression.x.obj_ea
                    elif expression.x.op == idaapi.cot_memptr:
                        idaapi.update_action_label(RecastItemLeft.name, 'Recast Field')
                        return RECAST_STRUCTURE, expression.x.x.type.get_pointed_object().dstr(), expression.x.m, right_tinfo
                    elif expression.x.op == idaapi.cot_memref:
                        idaapi.update_action_label(RecastItemLeft.name, 'Recast Field')
                        return RECAST_STRUCTURE, expression.x.x.type.dstr(), expression.x.m, right_tinfo

                elif expression.op == idaapi.cit_return:

                    idaapi.update_action_label(RecastItemLeft.name, "Recast Return")
                    child = child or expression.creturn.expr

                    if child.op == idaapi.cot_cast:
                        return RECAST_RETURN, child.x.type, None

                    func_tinfo = idaapi.tinfo_t()
                    cfunc.get_func_type(func_tinfo)
                    rettype = func_tinfo.get_rettype()

                    print func_tinfo.get_rettype().dstr(), child.type.dstr()
                    if func_tinfo.get_rettype().dstr() != child.type.dstr():
                        return RECAST_RETURN, child.type, None

                elif expression.op == idaapi.cot_call:

                    if expression.x.op == idaapi.cot_memptr:
                        # TODO: Recast arguments of virtual functions
                        return

                    if child and child.op == idaapi.cot_cast:
                        if child.cexpr.x.op == idaapi.cot_memptr:
                            idaapi.update_action_label(RecastItemLeft.name, 'Recast Virtual Function')
                            return RECAST_STRUCTURE, child.cexpr.x.x.type.get_pointed_object().dstr(), child.cexpr.x.m, child.type

                        arg_index, _ = Helper.get_func_argument_info(expression, child.cexpr)
                        idaapi.update_action_label(RecastItemLeft.name, "Recast Argument")
                        return (
                            RECAST_ARGUMENT,
                            arg_index,
                            expression.x.type.get_pointed_object(),
                            child.x.type,
                            expression.x.obj_ea
                        )

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            if result[0] == RECAST_LOCAL_VARIABLE:
                tinfo, lvar = result[1:]
                if hx_view.set_lvar_type(lvar, tinfo):
                    hx_view.refresh_view(True)

            elif result[0] == RECAST_GLOBAL_VARIABLE:
                tinfo, address = result[1:]
                if idaapi.apply_tinfo2(address, tinfo, idaapi.TINFO_DEFINITE):
                    hx_view.refresh_view(True)

            elif result[0] == RECAST_ARGUMENT:
                arg_index, func_tinfo, arg_tinfo, address = result[1:]
                if arg_tinfo.is_array():
                    arg_tinfo.convert_array_to_ptr()

                func_data = idaapi.func_type_data_t()
                func_tinfo.get_func_details(func_data)
                func_data[arg_index].type = arg_tinfo
                new_func_tinfo = idaapi.tinfo_t()
                new_func_tinfo.create_func(func_data)
                if idaapi.apply_tinfo2(address, new_func_tinfo, idaapi.TINFO_DEFINITE):
                    hx_view.refresh_view(True)

            elif result[0] == RECAST_RETURN:
                return_type, func_address = result[1:]
                try:
                    cfunc = idaapi.decompile(func_address) if func_address else hx_view.cfunc
                except idaapi.DecompilationFailure:
                    print "[ERROR] Ida failed to decompile function"
                    return

                function_tinfo = idaapi.tinfo_t()
                cfunc.get_func_type(function_tinfo)
                func_data = idaapi.func_type_data_t()
                function_tinfo.get_func_details(func_data)
                func_data.rettype = return_type
                function_tinfo.create_func(func_data)
                if idaapi.apply_tinfo2(cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE):
                    hx_view.refresh_view(True)

            elif result[0] == RECAST_STRUCTURE:
                structure_name, field_offset, new_type = result[1:]
                tinfo = idaapi.tinfo_t()
                tinfo.get_named_type(idaapi.cvar.idati, structure_name)

                ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, structure_name)

                if ordinal:
                    udt_member = idaapi.udt_member_t()
                    udt_member.offset = field_offset * 8
                    idx = tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
                    if udt_member.offset != field_offset * 8:
                        print "[Info] Can't handle with arrays yet"
                    elif udt_member.type.get_size() != new_type.get_size():
                        print "[Info] Can't recast different sizes yet"
                    else:
                        udt_data = idaapi.udt_type_data_t()
                        tinfo.get_udt_details(udt_data)
                        udt_data[idx].type = new_type
                        tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
                        tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.NTF_REPLACE, structure_name)
                        hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RecastItemRight(RecastItemLeft):

    name = "my:RecastItemRight"
    description = "Recast Item"
    hotkey = "Shift+R"

    def __init__(self):
        RecastItemLeft.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR:

            expression = ctree_item.it

            while expression and expression.op != idaapi.cot_cast:
                expression = expression.to_specific_type
                expression = cfunc.body.find_parent_of(expression)
            if expression:
                expression = expression.to_specific_type

                if expression.x.op == idaapi.cot_ref:
                    new_type = expression.type.get_pointed_object()
                    expression = expression.x
                else:
                    new_type = expression.type

                if expression.x.op == idaapi.cot_var:

                    variable = cfunc.get_lvars()[expression.x.v.idx]
                    idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{0}"'.format(variable.name))
                    return RECAST_LOCAL_VARIABLE, new_type, variable

                elif expression.x.op == idaapi.cot_obj:
                    idaapi.update_action_label(RecastItemRight.name, 'Recast Global')
                    return RECAST_GLOBAL_VARIABLE, new_type, expression.x.obj_ea

                elif expression.x.op == idaapi.cot_call:
                    idaapi.update_action_label(RecastItemRight.name, "Recast Return")
                    return RECAST_RETURN, new_type, expression.x.x.obj_ea


class RenameOther(idaapi.action_handler_t):
    name = "my:RenameOther"
    description = "Take other name"
    hotkey = "Ctrl+N"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_var:
            return

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_asg:
            return

        other = parent.theother(expression)
        if other.op != idaapi.cot_var:
            return

        this_lvar = ctree_item.get_lvar()
        other_lvar = cfunc.get_lvars()[other.v.idx]
        if (other_lvar.has_user_name or other_lvar.is_arg_var and re.search("a\d*$", other_lvar.name) is None) \
                and this_lvar.name.lstrip('_') != other_lvar.name.lstrip('_'):
            return '_' + other_lvar.name, this_lvar

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            name, lvar = result
            hx_view.rename_lvar(lvar, name, True)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RenameInside(idaapi.action_handler_t):
    name = "my:RenameInto"
    description = "Rename inside argument"
    hotkey = "Shift+N"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op == idaapi.cot_var:
            lvar = ctree_item.get_lvar()
            # Check if it's either variable with user name or argument with not standard `aX` name
            if lvar.has_user_name or lvar.is_arg_var and re.search("a\d*$", lvar.name) is None:
                parent = cfunc.body.find_parent_of(expression).to_specific_type
                if parent.op == idaapi.cot_call:
                    arg_index, _ = Helper.get_func_argument_info(parent, expression)
                    func_tinfo = parent.x.type.get_pointed_object()
                    func_data = idaapi.func_type_data_t()
                    func_tinfo.get_func_details(func_data)
                    if arg_index < func_tinfo.get_nargs() and lvar.name.lstrip('_') != func_data[arg_index].name:
                        return func_tinfo, parent.x.obj_ea, arg_index, lvar.name.lstrip('_')

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            func_tinfo, address, arg_index, name = result

            func_data = idaapi.func_type_data_t()
            func_tinfo.get_func_details(func_data)
            func_data[arg_index].name = name
            new_func_tinfo = idaapi.tinfo_t()
            new_func_tinfo.create_func(func_data)
            idaapi.apply_tinfo2(address, new_func_tinfo, idaapi.TINFO_DEFINITE)
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RenameOutside(idaapi.action_handler_t):
    name = "my:RenameOutside"
    description = "Take argument name"
    hotkey = "Ctrl+Shift+N"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op == idaapi.cot_var:
            lvar = ctree_item.get_lvar()
            parent = cfunc.body.find_parent_of(expression).to_specific_type

            if parent.op == idaapi.cot_call:
                arg_index, _ = Helper.get_func_argument_info(parent, expression)
                func_tinfo = parent.x.type.get_pointed_object()
                if func_tinfo.get_nargs() < arg_index:
                    return
                func_data = idaapi.func_type_data_t()
                func_tinfo.get_func_details(func_data)
                name = func_data[arg_index].name
                if name and re.search("a\d*$", name) is None and name != 'this' and name != lvar.name:
                    return name, lvar

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            name, lvar = result
            hx_view.rename_lvar(lvar, name, True)

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class SimpleCreateStruct(idaapi.action_handler_t):
    name = "my:CreateStruct"
    description = "Create simple struct"
    hotkey = "Shift+C"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        idaname = "ida64" if Const.EA64 else "ida"
        if sys.platform == "win32":
            self.g_dll = ctypes.windll[idaname + ".wll"]
        elif sys.platform == "linux2":
            self.g_dll = ctypes.cdll["lib" + idaname + ".so"]
        elif sys.platform == "darwin":
            self.g_dll = ctypes.cdll["lib" + idaname + ".dylib"]

        self.set_numbered_type = self.g_dll.set_numbered_type
        self.set_numbered_type.argtypes = [
            ctypes.c_void_p,                                    #til_t *ti,
            ctypes.c_int,                                       #uint32 ordinal,
            ctypes.c_int,                                       #int ntf_flags,
            ctypes.c_char_p,                                    #const char *name,
            ctypes.c_char_p,     #const type_t *type,
            ctypes.c_char_p,     #const p_list *fields=NULL,
            ctypes.c_char_p,     #const char *cmt=NULL,
            ctypes.c_char_p,     #const p_list *fldcmts=NULL,
            ctypes.POINTER(ctypes.c_ulong),                     #const sclass_t *sclass=NULL
        ]

    @staticmethod
    def check(cfunc, ctree_item):
        return True

    def create_struct_type(self, struc_size, name, field_size=4, fAllign=True):
        my_til = ctypes.c_void_p.in_dll(self.g_dll, 'idati')
        my_ti = idaapi.cvar.idati

        def make_field_str(field_num, fsize, pad=0):
            ret = ""
            for i in range(0, field_num):
                ret += struct.pack(">B", len("field_%X" % (i * fsize)) + 1) + "field_%X" % (i * fsize)
            k = 1
            while pad > 0:
                ret += struct.pack(">B", len("field_%X" % (i * fsize + k)) + 1) + "field_%X" % (i * fsize + k)
                pad -= 1
                k += 1
            return ret

        def encode_size(num):
            enc = 0
            if num > 0xF:
                t, pad = divmod(num, 0x10)
                if t < 0x100:
                    enc = 0x8100 | (pad << 11) | t
                    return struct.pack(">BB", enc >> 8, enc & 0xFF)
                else:
                    t1, t2, t3 = (0, 0, 0)
                    t1, pad = divmod(num, 0x400)
                    t3 = pad
                    if pad > 7:
                        t2, t3 = divmod(pad, 8)
                    return "\xFF\xFF" + struct.pack(">BBB", t1 | 0x80, t2 | 0x80, t3 << 3 | 0x40)
            else:
                return struct.pack(">B", num << 3 | 1)

        def decode_size(size_str):
            l = 0
            if size_str[:2] == "\xFF\xFF":
                l += 2
                size_str = size_str[2:]
            b1 = ord(size_str[0])
            l += 1
            if b1 & 0x80:
                b2 = ord(size_str[1])
                l += 1
                if b2 & 0x80:
                    b3 = ord(size_str[2])
                    l += 1
                    if b3 & 0x40:
                        t1 = (b1 & 0x7f) * 0x400
                        t2 = (b2 & 0x7f) * 8
                        t3 = (b3 & 0x3f) >> 3
                        return (l, t1 + t2 + t3)
                    else:
                        return None
                t1 = b2 * 0x10
                t2 = (b1 & 0x7f) >> 3
                return (l, t1 + t2)
            return (l, b1 >> 3)

        def make_type_string(field_num, fsize, pad=0):
            ret = "\x0d" + encode_size(field_num + pad)
            if fsize == 1:
                t = "\x32"
            elif fsize == 2:
                t = "\x03"
            elif fsize == 8:
                t = "\x05"
            else:
                t = "\x07"
            ret += t * field_num
            if pad > 0:
                ret += "\x32" * pad
            return ret

        struct_id = idc.GetStrucIdByName(name)
        if struct_id != idaapi.BADADDR:
            answer = idc.AskYN(0, "A structure for %s already exists. Are you sure you want to remake it?" % name)
            if answer == 1:
                idc.DelStruc(struct_id)
            else:
                return
        fields_num, pad = divmod(struc_size, field_size)
        if fAllign and pad:
            fields_num += 1
            pad = 0
        typ_type = ctypes.c_char_p(make_type_string(fields_num, field_size, pad))
        typ_fields = ctypes.c_char_p(make_field_str(fields_num, field_size, pad))
        typ_cmt = ctypes.c_char_p("")
        typ_fieldcmts = ctypes.c_char_p("")
        sclass = ctypes.c_ulong(0)
        idaapi.compact_til(my_ti)
        idx = idaapi.alloc_type_ordinal(my_ti)
        ret = self.set_numbered_type(
            my_til,
            idx,
            0x1,
            ctypes.c_char_p(name),
            typ_type,
            typ_fields,
            typ_cmt,
            typ_fieldcmts,
            ctypes.byref(sclass)
        )
        if ret != 0:
            idc.Til2Idb(-1, name)
        else:
            Warning("set_numbered_type error")

    def activate(self, ctx):
        vdui = idaapi.get_tform_vdui(ctx.form)
        vdui.get_current_item(idaapi.USE_KEYBOARD)
        struc_size = 0
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            if target_item.opname == "num":
                s = idaapi.tag_remove(target_item.cexpr.print1(None)).rstrip("u")
                if s.startswith("0x"):
                    struc_size = int(s,16)
                else:
                    struc_size = int(s,10)

        class SimpleCreateStructForm(idaapi.Form):
            def __init__(self):
                idaapi.Form.__init__(self, r"""STARTITEM 0
        Create struct

        <Struct name:{cStrArg}><Struct size:{numSize}>
        <Field size :{numFieldSize}>                                        <Align:{ckAlign}>{gAlign}>

        """, {
                    'cStrArg': idaapi.Form.StringInput(),
                    'numSize': idaapi.Form.StringInput(swidth=10),
                    'numFieldSize': idaapi.Form.DropdownListControl(
                        items=["1", "2", "4", "8"],
                        readonly=False,
                        selval="8" if  Const.EA64 else "4"),
                    'gAlign': idaapi.Form.ChkGroupControl(("ckAlign",)),
                })

            def Go(self,size = 0):
                self.Compile()
                self.ckAlign.checked = True
                # f.numFieldSize.value = 4
                self.numSize.value = str(size)
                ok = self.Execute()
                # print "Ok = %d"%ok
                if ok == 1:
                    # print sel
                    # print len(sel)
                    return (int(self.numSize.value,16) if self.numSize.value.startswith("0x") else int(self.numSize.value,10), self.cStrArg.value, int(self.numFieldSize.value),
                    self.ckAlign.checked)
                return None
        ret = SimpleCreateStructForm().Go(struc_size)
        if ret is not None:
            self.create_struct_type(*ret)
        return 1

    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

class RecastStructMember(idaapi.action_handler_t):

    name = "my:RecastStructMember"
    description = "Recast Struct Member"
    hotkey = "Shift+L"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.it.op in [idaapi.cot_memptr, idaapi.cot_memref]:
            parent = cfunc.body.find_parent_of(ctree_item.it)
            if parent and parent.op == idaapi.cot_call and parent.to_specific_type.x.op == idaapi.cot_helper:
                cast_helper = parent.to_specific_type.x.helper
                helpers = ["HIBYTE", "LOBYTE", "BYTE", "HIWORD", "LOWORD"]
                for h in helpers:
                    if cast_helper.startswith(h):
                        return ("%s"%ctree_item.it.to_specific_type.x.type).strip(" *"), ctree_item.it.to_specific_type.m, cast_helper
        return False

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            struct_name, member_offset, cast_helper = result
            sid = idaapi.get_struc_id(struct_name)
            if sid != idaapi.BADADDR:
                sptr = idaapi.get_struc(sid)
                mptr = idaapi.get_member(sptr,member_offset)
                member_name = idaapi.get_member_name(mptr.id)
                member_size = idaapi.get_member_size(mptr)
                if cast_helper.startswith("BYTE") or cast_helper in ("HIBYTE", "LOBYTE"):
                    idaapi.del_struc_member(sptr, member_offset)
                    for i in range(member_size):
                        idc.AddStrucMember(sptr.id,member_name if i == 0 else "field_%X"%(member_offset + i), member_offset+i, idaapi.FF_DATA|idaapi.FF_BYTE,idaapi.BADADDR, 1)
                if cast_helper in ("LOWORD","HIWORD"):
                    for i in range(0,member_size,2):
                        idc.AddStrucMember(sptr.id,member_name if i == 0 else "field_%X"%(member_offset + i), member_offset+i, idaapi.FF_DATA|idaapi.FF_WORD,idaapi.BADADDR, 2)
                hx_view.refresh_view(True)


    def update(self, ctx):
        if ctx.form_title[0:10] == "Pseudocode":
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM
