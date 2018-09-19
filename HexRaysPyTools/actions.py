import ctypes
import sys
import re
import logging

import idaapi
import idc

import HexRaysPyTools.forms as forms
import HexRaysPyTools.core.const as const
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.core.classes as classes
import HexRaysPyTools.api as api
import settings
from HexRaysPyTools.core.structure_graph import StructureGraph
from HexRaysPyTools.core.temporary_structure import VirtualTable, TemporaryStructureModel
from HexRaysPyTools.core.variable_scanner import NewShallowSearchVisitor, NewDeepSearchVisitor, DeepReturnVisitor
from HexRaysPyTools.core.helper import FunctionTouchVisitor
from HexRaysPyTools.core.spaghetti_code import *
from HexRaysPyTools.core.struct_xrefs import XrefStorage

RECAST_LOCAL_VARIABLE = 0
RECAST_GLOBAL_VARIABLE = 1
RECAST_ARGUMENT = 2
RECAST_RETURN = 3
RECAST_STRUCTURE = 4

logger = logging.getLogger(__name__)


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
        idaname = "ida64" if const.EA64 else "ida"
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

        library_chooser = forms.MyChoose(
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
        vu = idaapi.get_widget_vdui(ctx.widget)
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
        vu = idaapi.get_widget_vdui(ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        if function_details.rettype.equals_to(const.VOID_TINFO):
            function_details.rettype = idaapi.tinfo_t(const.PVOID_TINFO)
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
        vu = idaapi.get_widget_vdui(ctx.widget)
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

            type_chooser = forms.MyChoose(
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
        hx_view = idaapi.get_widget_vdui(ctx.widget)
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
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class ShallowScanVariable(idaapi.action_handler_t):

    name = "my:ShallowScanVariable"
    description = "Scan Variable"
    hotkey = "F"

    def __init__(self, temporary_structure):
        self.temporary_structure = temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        lvar = ctree_item.get_lvar()
        if lvar is not None:
            return helper.is_legal_type(lvar.type())

        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        obj = api.ScanObject.create(cfunc, ctree_item.e)
        return obj and helper.is_legal_type(obj.tinfo)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = self.temporary_structure.main_offset

        if self.check(cfunc, hx_view.item):
            obj = api.ScanObject.create(cfunc, hx_view.item)
            visitor = NewShallowSearchVisitor(cfunc, origin, obj, self.temporary_structure)
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanVariable(idaapi.action_handler_t):

    name = "my:DeepScanVariable"
    description = "Deep Scan Variable"
    hotkey = "shift+F"

    def __init__(self, temporary_structure):
        self.temporary_structure = temporary_structure
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        origin = self.temporary_structure.main_offset

        if ShallowScanVariable.check(cfunc, hx_view.item):
            obj = api.ScanObject.create(cfunc, hx_view.item)
            if FunctionTouchVisitor(cfunc).process():
                hx_view.refresh_view(True)
            visitor = NewDeepSearchVisitor(hx_view.cfunc, origin, obj, self.temporary_structure)
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanReturn(idaapi.action_handler_t):
    name = "my:DeepScanReturn"
    description = "Deep Scan Returned Variables"
    hotkey = None

    def __init__(self, temporary_structure):
        self.temp_struct = temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(hx_view):
        tinfo = idaapi.tinfo_t()
        hx_view.cfunc.get_func_type(tinfo)
        return not tinfo.get_rettype().equals_to(const.VOID_TINFO)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        func_ea = hx_view.cfunc.entry_ea

        obj = api.ReturnedObject(func_ea)
        visitor = DeepReturnVisitor(hx_view.cfunc, self.temp_struct.main_offset, obj, self.temp_struct)
        visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanFunctions(idaapi.action_handler_t):

    name = "my:DeepScanFunctions"
    description = "Scan First Argument"
    hotkey = None

    def __init__(self, temporary_structure):
        self.temporary_structure = temporary_structure
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        for idx in ctx.chooser_selection:
            func_ea = idaapi.getn_func(idx - 1).startEA
            cfunc = helper.decompile_function(func_ea)
            obj = api.VariableObject(cfunc.get_lvars()[0], 0)
            if cfunc:
                NewDeepSearchVisitor(cfunc, 0, obj, self.temporary_structure).process()

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_FUNCS:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RecognizeShape(idaapi.action_handler_t):

    name = "my:RecognizeShape"
    description = "Recognize Shape"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc

        if not ShallowScanVariable.check(cfunc, hx_view.item):
            return

        obj = api.ScanObject.create(cfunc, hx_view.item)
        temp_struct = TemporaryStructureModel()
        visitor = NewShallowSearchVisitor(cfunc, 0, obj, temp_struct)
        visitor.process()
        tinfo = temp_struct.get_recognized_shape()
        if tinfo:
            tinfo.create_ptr(tinfo)
            if obj.id == api.SO_LOCAL_VARIABLE:
                hx_view.set_lvar_type(obj.lvar, tinfo)
            elif obj.id == api.SO_GLOBAL_OBJECT:
                idaapi.apply_tinfo2(obj.obj_ea, tinfo, idaapi.TINFO_DEFINITE)
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class CreateNewField(idaapi.action_handler_t):
    name = "my:CreateNewField"
    description = "Create New Field"
    hotkey = "Ctrl+F"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        item = ctree_item.it.to_specific_type
        if item.op not in (idaapi.cot_memptr, idaapi.cot_memref):
            return

        parent = cfunc.body.find_parent_of(ctree_item.it).to_specific_type
        if parent.op != idaapi.cot_idx or parent.y.op != idaapi.cot_num:
            idx = 0
        else:
            idx = parent.y.numval()

        struct_type = item.x.type
        struct_type.remove_ptr_or_array()

        udt_member = idaapi.udt_member_t()
        udt_member.offset = item.m * 8
        struct_type.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        if udt_member.name[0:3] != "gap":
            return

        return struct_type, udt_member.offset // 8, idx

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)
        if result is None:
            return

        struct_tinfo, offset, idx = result
        ordinal = struct_tinfo.get_ordinal()
        struct_name = struct_tinfo.dstr()

        if (offset + idx) % 2:
            default_field_type = "_BYTE"
        elif (offset + idx) % 4:
            default_field_type = "_WORD"
        else:
            default_field_type = "_DWORD"

        declaration = idaapi.asktext(
            0x10000, "{0} field_{1:X}".format(default_field_type, offset + idx), "Enter new structure member:"
        )
        if declaration is None:
            return

        result = self.parse_declaration(declaration)
        if result is None:
            logger.warn("Bad member declaration")
            return

        field_tinfo, field_name = result
        field_size = field_tinfo.get_size()
        udt_data = idaapi.udt_type_data_t()
        udt_member = idaapi.udt_member_t()

        struct_tinfo.get_udt_details(udt_data)
        udt_member.offset = offset * 8
        struct_tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        gap_size = udt_member.size // 8

        gap_leftover = gap_size - idx - field_size

        if gap_leftover < 0:
            print "[ERROR] Too big size for the field. Type with maximum {0} bytes can be used".format(gap_size - idx)
            return

        iterator = udt_data.find(udt_member)
        iterator = udt_data.erase(iterator)

        if gap_leftover > 0:
            udt_data.insert(iterator, TemporaryStructureModel.get_padding_member(offset + idx + field_size, gap_leftover))

        udt_member = idaapi.udt_member_t()
        udt_member.offset = offset * 8 + idx
        udt_member.name = field_name
        udt_member.type = field_tinfo
        udt_member.size = field_size

        iterator = udt_data.insert(iterator, udt_member)

        if idx > 0:
            udt_data.insert(iterator, TemporaryStructureModel.get_padding_member(offset, idx))

        struct_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        struct_tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.BTF_STRUCT, struct_name)
        hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

    @staticmethod
    def parse_declaration(declaration):
        m = re.search(r"^(\w+[ *]+)(\w+)(\[(\d+)\])?$", declaration)
        if m is None:
            return

        type_name, field_name, _, arr_size = m.groups()
        if field_name[0].isdigit():
            print "[ERROR] Bad field name"
            return

        result = idc.ParseType(type_name, 0)
        if result is None:
            return

        _, tp, fld = result
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(idaapi.cvar.idati, tp, fld, None)
        if arr_size:
            assert tinfo.create_array(tinfo, int(arr_size))
        return tinfo, field_name


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
            self.graph_view.change_selected([sel + 1 for sel in ctx.chooser_selection])
            self.graph_view.Show()
        else:
            self.graph = StructureGraph([sel + 1 for sel in ctx.chooser_selection])
            self.graph_view = forms.StructureGraphViewer("Structure Graph", self.graph)
            self.graph_view.Show()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_LOCTYPS:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name)
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
            class_viewer = forms.ClassViewer(classes.ProxyModel(), classes.TreeModel())
            class_viewer.Show()
        else:
            idaapi.switchto_tform(tform, True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


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
        if ctx.widget_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class SelectContainingStructure(idaapi.action_handler_t):

    name = "my:SelectContainingStructure"
    description = "Select Containing Structure"
    hotkey = None

    def __init__(self, potential_negatives):
        idaapi.action_handler_t.__init__(self)
        self.potential_negative = potential_negatives

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = TypeLibrary.choose_til()
        if result:
            selected_library, max_ordinal, is_local_types = result
            lvar_idx = hx_view.item.e.v.idx
            candidate = self.potential_negative[lvar_idx]
            structures = candidate.find_containing_structures(selected_library)
            items = map(lambda x: [str(x[0]), "0x{0:08X}".format(x[1]), x[2], x[3]], structures)
            structure_chooser = forms.MyChoose(
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
        hx_view = idaapi.get_widget_vdui(ctx.widget)
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
    def check(cfunc, ctree_item, force=False):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        child = None

        # Look through parents until we found Return, Assignment or Call
        while expression and expression.op not in (idaapi.cot_asg, idaapi.cit_return, idaapi.cot_call):
            child = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type
        if expression.op == idaapi.cot_asg:

            if expression.x.opname not in ('var', 'obj', 'memptr', 'memref'):
                return

            right_expr = expression.y
            right_tinfo = right_expr.x.type if right_expr.op == idaapi.cot_cast else right_expr.type

            # Check if both left and right parts of expression are of the same types.
            # If not then we can recast then.
            if right_tinfo.dstr() == expression.x.type.dstr():
                return

            if expression.x.op == idaapi.cot_var:
                # var = (TYPE ) ...;
                variable = cfunc.get_lvars()[expression.x.v.idx]
                idaapi.update_action_label(RecastItemLeft.name, 'Recast Variable "{0}"'.format(variable.name))
                return RECAST_LOCAL_VARIABLE, right_tinfo, variable
            elif expression.x.op == idaapi.cot_obj:
                # g_var = (TYPE ) ...;
                idaapi.update_action_label(RecastItemLeft.name, 'Recast Global')
                return RECAST_GLOBAL_VARIABLE, right_tinfo, expression.x.obj_ea
            elif expression.x.op == idaapi.cot_memptr:
                # struct->member = (TYPE ) ...;
                idaapi.update_action_label(RecastItemLeft.name, 'Recast Field')
                return RECAST_STRUCTURE, expression.x.x.type.get_pointed_object().dstr(), expression.x.m, right_tinfo
            elif expression.x.op == idaapi.cot_memref:
                # struct.member = (TYPE ) ...;
                idaapi.update_action_label(RecastItemLeft.name, 'Recast Field')
                return RECAST_STRUCTURE, expression.x.x.type.dstr(), expression.x.m, right_tinfo

        elif expression.op == idaapi.cit_return:

            idaapi.update_action_label(RecastItemLeft.name, "Recast Return")
            child = child or expression.creturn.expr

            if child.op == idaapi.cot_cast:
                # return (TYPE) ...;
                return RECAST_RETURN, child.x.type, None

            func_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(func_tinfo)
            rettype = func_tinfo.get_rettype()
            if rettype.dstr() != child.type.dstr():
                # return ...;
                # This's possible when returned type and value are both pointers to different types
                return RECAST_RETURN, child.type, None

        elif expression.op == idaapi.cot_call:

            if expression.x == child:
                return
            func_ea = expression.x.obj_ea
            arg_index, param_tinfo = helper.get_func_argument_info(expression, child)
            if expression.x.op == idaapi.cot_memptr:
                if child.op == idaapi.cot_cast:
                    # struct_ptr->func(..., (TYPE) var, ...);
                    arg_tinfo = child.x.type
                else:
                    # struct_ptr->func(..., var, ...); When `var` and `arg` are different pointers
                    if param_tinfo.equals_to(child.type):
                        return
                    arg_tinfo = child.type

                struct_type = expression.x.x.type.get_pointed_object()
                funcptr_tinfo = expression.x.type
                helper.set_funcptr_argument(funcptr_tinfo, arg_index, arg_tinfo)
                return RECAST_STRUCTURE, struct_type.dstr(), expression.x.m, funcptr_tinfo
            if child.op == idaapi.cot_ref:
                if child.x.op == idaapi.cot_memref and child.x.m == 0:
                    # func(..., &struct.field_0, ...)
                    arg_tinfo = idaapi.tinfo_t()
                    arg_tinfo.create_ptr(child.x.x.type)
                elif child.x.op == idaapi.cot_memptr and child.x.m == 0:
                    # func(..., &struct->field_0, ...)
                    arg_tinfo = child.x.x.type
                else:
                    # func(..., &var, ...)
                    arg_tinfo = child.type
            elif child.op == idaapi.cot_cast:
                arg_tinfo = child.x.type
            else:
                arg_tinfo = child.type

            if force or not arg_tinfo.equals_to(param_tinfo):
                func_tinfo = expression.x.type.get_pointed_object()
                idaapi.update_action_label(RecastItemLeft.name, "Recast Argument")
                return RECAST_ARGUMENT, arg_index, func_tinfo, arg_tinfo, func_ea

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item, force=True)

        if not result:
            return

        if result[0] == RECAST_LOCAL_VARIABLE:
            logger.debug("Recasting local variable. Type - %s", result[1].dstr())
            tinfo, lvar = result[1:]
            if hx_view.set_lvar_type(lvar, tinfo):
                hx_view.refresh_view(True)

        elif result[0] == RECAST_GLOBAL_VARIABLE:
            logger.debug("Recasting global. Type - %s. Address - %s", result[1].dstr(), helper.to_hex(result[2]))
            tinfo, address = result[1:]
            if idaapi.apply_tinfo2(address, tinfo, idaapi.TINFO_DEFINITE):
                hx_view.refresh_view(True)

        elif result[0] == RECAST_ARGUMENT:
            arg_index, func_tinfo, arg_tinfo, address = result[1:]
            logger.debug("Recasting argument. Function at %s, arg_idx - %d, new type - %s",
                         idaapi.get_name(address), arg_index, arg_tinfo.dstr())
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
                print "[ERROR] Ida failed to decompile function at 0x{0:08X}".format(func_address)
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
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RecastItemRight(RecastItemLeft):

    name = "my:RecastItemRight"
    description = "Recast Item"
    hotkey = "Shift+R"

    def __init__(self):
        RecastItemLeft.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item, force=False):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it

        result = RecastItemRight._check_potential_array(cfunc, expression)
        if result:
            return result

        # Look through parents until we found Cast
        while expression and expression.op != idaapi.cot_cast:
            expression = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type

        # Find `(TYPE) something;` or `(TYPE *) &something;` and calculate appropriate type for recast
        if expression.x.op == idaapi.cot_ref:
            new_type = expression.type.get_pointed_object()
            expression = expression.x
        else:
            new_type = expression.type

        if expression.x.op == idaapi.cot_var:
            # (TYPE) var;
            variable = cfunc.get_lvars()[expression.x.v.idx]
            idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{0}"'.format(variable.name))
            return RECAST_LOCAL_VARIABLE, new_type, variable

        elif expression.x.op == idaapi.cot_obj:
            # (TYPE) g_var;
            if helper.is_code_ea(expression.x.obj_ea) and new_type.is_funcptr():
                # (TYPE) sub_XXXXXX;
                new_type = new_type.get_pointed_object()

            idaapi.update_action_label(RecastItemRight.name, 'Recast Global')
            return RECAST_GLOBAL_VARIABLE, new_type, expression.x.obj_ea

        elif expression.x.op == idaapi.cot_call:
            # (TYPE) call();
            idaapi.update_action_label(RecastItemRight.name, "Recast Return")
            return RECAST_RETURN, new_type, expression.x.x.obj_ea

        elif expression.x.op == idaapi.cot_memptr:
            # (TYPE) var->member;
            idaapi.update_action_label(RecastItemRight.name, "Recast Field")
            return RECAST_STRUCTURE, expression.x.x.type.get_pointed_object().dstr(), expression.x.m, new_type

    @staticmethod
    def _check_potential_array(cfunc, expr):
        """ Checks `call(..., &buffer, ..., number)` and returns information for recasting """
        if expr.op != idaapi.cot_var:
            return

        var_expr = expr.to_specific_type
        parent = cfunc.body.find_parent_of(expr)
        if parent.op != idaapi.cot_ref:
            return

        parent = cfunc.body.find_parent_of(parent)
        if parent.op != idaapi.cot_call:
            return

        call_expr = parent.to_specific_type
        for arg_expr in call_expr.a:
            if arg_expr.op == idaapi.cot_num:
                number = arg_expr.numval()
                if number:
                    variable = cfunc.lvars[var_expr.v.idx]
                    char_array_tinfo = idaapi.tinfo_t()
                    char_array_tinfo.create_array(idaapi.tinfo_t(idaapi.BTF_CHAR), number)
                    idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{}" to "{}"'.format(
                        variable.name, char_array_tinfo.dstr()
                    ))
                    return RECAST_LOCAL_VARIABLE, char_array_tinfo, variable


class RenameOther(idaapi.action_handler_t):
    name = "my:RenameOther"
    description = "Take other name"
    hotkey = "Ctrl+N"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item, force=False):
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
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            name, lvar = result
            hx_view.rename_lvar(lvar, name, True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
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
                    arg_index, _ = helper.get_func_argument_info(parent, expression)
                    func_tinfo = parent.x.type.get_pointed_object()
                    func_data = idaapi.func_type_data_t()
                    func_tinfo.get_func_details(func_data)
                    if arg_index < func_tinfo.get_nargs() and lvar.name.lstrip('_') != func_data[arg_index].name:
                        return func_tinfo, parent.x.obj_ea, arg_index, lvar.name.lstrip('_')

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
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
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
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
                arg_index, _ = helper.get_func_argument_info(parent, expression)
                func_tinfo = parent.x.type.get_pointed_object()
                if func_tinfo.get_nargs() < arg_index:
                    return
                func_data = idaapi.func_type_data_t()
                func_tinfo.get_func_details(func_data)
                name = func_data[arg_index].name
                if name and re.search("a\d*$", name) is None and name != 'this' and name != lvar.name:
                    return name, lvar

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            name, lvar = result
            hx_view.rename_lvar(lvar, name, True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RenameUsingAssertVisitor(idaapi.ctree_parentee_t):

    def __init__(self, cfunc, func_addr, arg_idx):
        idaapi.ctree_parentee_t.__init__(self)
        self.__cfunc = cfunc
        self.__func_addr = func_addr
        self.__arg_idx = arg_idx
        self.__possible_names = set()

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj and expr.x.obj_ea == self.__func_addr:
            arg_expr = expr.a[self.__arg_idx]
            if arg_expr.op != idaapi.cot_obj:
                logger.error("Argument is not string at {}".format(helper.to_hex(self._find_asm_address(expr))))
                return 1
            self.__add_func_name(arg_expr)
        return 0

    def process(self):
        self.apply_to(self.__cfunc.body, None)
        if len(self.__possible_names) == 1:
            self.__rename_func()
        else:
            logger.error("Function at {} has more than one candidate for renaming: {}".format(
                helper.to_hex(self.__cfunc.entry_ea), ", ".join(self.__possible_names)))

    def __add_func_name(self, arg_expr):
        new_name = idc.get_strlit_contents(arg_expr.obj_ea)
        if not idaapi.is_valid_typename(new_name):
            logger.warn("Argument has weird name `{}` at {}".format(
                new_name, helper.to_hex(self._find_asm_address(arg_expr))))
            return

        self.__possible_names.add(new_name)

    def __rename_func(self):
        idc.set_name(self.__cfunc.entry_ea, self.__possible_names.pop())


class RenameUsingAssert(idaapi.action_handler_t):

    name = "my:RenameUsingAssert"
    description = "Rename as assert argument"
    hotkey = None

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_obj:
            return False

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_call or parent.x.op != idaapi.cot_obj:
            return False

        obj_ea = expression.obj_ea
        if not helper.is_code_ea(obj_ea) and idc.get_str_type(obj_ea) == idc.STRTYPE_C:
            str_potential_name = idc.get_strlit_contents(obj_ea)
            return idaapi.is_valid_typename(str_potential_name)
        return False

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        ctree_item = hx_view.item
        if not self.check(cfunc, ctree_item):
            return

        expr_arg = ctree_item.it.to_specific_type
        expr_call = cfunc.body.find_parent_of(expr_arg).to_specific_type

        arg_idx, _ = helper.get_func_argument_info(expr_call, expr_arg)

        assert_ea = expr_call.x.obj_ea
        all_callers = helper.get_funcs_calling_address(assert_ea)

        for caller_ea in all_callers:
            try:
                cfunc = idaapi.decompile(caller_ea)
                if not cfunc:
                    raise idaapi.DecompilationFailure

                RenameUsingAssertVisitor(cfunc, assert_ea, arg_idx).process()

            except idaapi.DecompilationFailure:
                logger.warn("IDA failed to decompile at {}".format(helper.to_hex(caller_ea)))

        hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class PropagateName(idaapi.action_handler_t):
    name = "my:PropagateName"
    description = "Propagate name"
    hotkey = "P"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def callback_start(self):
        hx_view, _ = self._data
        hx_view.switch_to(self._cfunc, False)

    @staticmethod
    def callback_manipulate(self, cexpr, obj):
        if self.crippled:
            logger.debug("Skipping crippled function at {}".format(helper.to_hex(self._cfunc.entry_ea)))
            return

        if obj.id == api.SO_GLOBAL_OBJECT:
            old_name = idaapi.get_short_name(cexpr.obj_ea)
            if settings.PROPAGATE_THROUGH_ALL_NAMES or PropagateName._is_default_name(old_name):
                _, name = self._data
                new_name = PropagateName.rename(lambda x: idaapi.set_name(cexpr.obj_ea, x), name)
                logger.debug("Renamed global variable from {} to {}".format(old_name, new_name))
        elif obj.id == api.SO_LOCAL_VARIABLE:
            lvar = self._cfunc.get_lvars()[cexpr.v.idx]
            old_name = lvar.name
            if settings.PROPAGATE_THROUGH_ALL_NAMES or PropagateName._is_default_name(old_name):
                hx_view, name = self._data
                new_name = PropagateName.rename(lambda x: hx_view.rename_lvar(lvar, x, True), name)
                logger.debug("Renamed local variable from {} to {}".format(old_name, new_name))
        elif obj.id in (api.SO_STRUCT_POINTER, api.SO_STRUCT_REFERENCE):
            struct_tinfo = cexpr.x.type
            offset = cexpr.m
            struct_tinfo.remove_ptr_or_array()
            old_name = helper.get_member_name(struct_tinfo, offset)
            if settings.PROPAGATE_THROUGH_ALL_NAMES or PropagateName._is_default_name(old_name):
                _, name = self._data
                new_name = PropagateName.rename(lambda x: helper.change_member_name(struct_tinfo.dstr(), offset, x), name)
                logger.debug("Renamed struct member from {} to {}".format(old_name, new_name))

    @staticmethod
    def rename(rename_func, name):
        while not rename_func(name):
            name = "_" + name
        return name

    @staticmethod
    def _is_default_name(string):
        return re.match(r"[av]\d+$", string) is not None or \
               re.match(r"this|[qd]?word|field_|off_", string) is not None

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        obj = api.ScanObject.create(cfunc, ctree_item)
        if obj and not PropagateName._is_default_name(obj.name):
            return obj

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        obj = self.check(hx_view.cfunc, hx_view.item)
        if obj:
            cfunc = hx_view.cfunc
            visitor = api.RecursiveObjectDownwardsVisitor(cfunc, obj, (hx_view, obj.name), True)
            visitor.set_callbacks(
                manipulate=PropagateName.callback_manipulate,
                start_iteration=PropagateName.callback_start,
                finish=lambda x: hx_view.switch_to(cfunc, True)
            )
            visitor.process()
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class GuessAllocation(idaapi.action_handler_t):
    name = "my:ActionApi"
    description = "Guess allocation"
    hotkey = None

    class StructAllocChoose(forms.MyChoose):
        def __init__(self, items):
            forms.MyChoose.__init__(
                self, items, "Possible structure allocations",
                [["Function", 30], ["Variable", 10], ["Line", 50], ["Type", 10]]
            )

        def OnSelectLine(self, n):
            idaapi.jumpto(self.items[n][0])

        def OnGetLine(self, n):
            func_ea, var, line, alloc_type = self.items[n]
            return [helper.to_nice_str(func_ea), var, line, alloc_type]

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return
        return api.ScanObject.create(cfunc, ctree_item)

    @staticmethod
    def callback_manipulate(self, cexpr, obj):
        if obj.id == api.SO_LOCAL_VARIABLE:
            parent = self.parent_expr()
            if parent.op == idaapi.cot_asg:
                alloc_obj = api.MemoryAllocationObject.create(self._cfunc, self.parent_expr().y)
                if alloc_obj:
                    self._data.append([alloc_obj.ea, obj.name, self._get_line(), "HEAP"])
            elif self.parent_expr().op == idaapi.cot_ref:
                self._data.append([self._find_asm_address(cexpr), obj.name, self._get_line(), "STACK"])
        elif obj.id == api.SO_GLOBAL_OBJECT:
            self._data.append([self._find_asm_address(cexpr), obj.name, self._get_line(), "GLOBAL"])

    @staticmethod
    def callback_finish(self):
        chooser = GuessAllocation.StructAllocChoose(self._data)
        chooser.Show(False)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        item = hx_view.item
        obj = GuessAllocation.check(hx_view.cfunc, item)
        if obj:
            visitor = api.RecursiveObjectUpwardsVisitor(hx_view.cfunc, obj, data=[], skip_after_object=True)
            visitor.set_callbacks(
                manipulate=self.callback_manipulate,
                finish=self.callback_finish
            )
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class SwapThenElse(idaapi.action_handler_t):
    name = "my:SwapIfElse"
    description = "Swap then/else"
    hotkey = "Shift+S"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        insn = ctree_item.it.to_specific_type

        if insn.op != idaapi.cit_if or insn.cif.ielse is None:
            return False

        return insn.op == idaapi.cit_if and insn.cif.ielse

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        if self.check(hx_view.cfunc, hx_view.item):
            insn = hx_view.item.it.to_specific_type
            inverse_if(insn.cif)
            hx_view.refresh_ctext()

            InversionInfo(hx_view.cfunc.entry_ea).switch_inverted(insn.ea)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class FindFieldXrefs(idaapi.action_handler_t):
    name = "my:FindFieldXrefs"
    description = "Field Xrefs"
    hotkey = "Ctrl+X"

    @staticmethod
    def check(ctree_item):
        return ctree_item.citype == idaapi.VDI_EXPR and \
               ctree_item.it.to_specific_type.op in (idaapi.cot_memptr, idaapi.cot_memref)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        item = hx_view.item

        if not self.check(item):
            return

        data = []
        offset = item.e.m
        struct_type = idaapi.remove_pointer(item.e.x.type)
        ordinal = helper.get_ordinal(struct_type)
        result = XrefStorage().get_structure_info(ordinal, offset)
        for xref_info in result:
            data.append([
                idaapi.get_short_name(xref_info.func_ea) + "+" + hex(int(xref_info.offset)),
                xref_info.type,
                xref_info.line
            ])

        field_name = helper.get_member_name(struct_type, offset)
        chooser = forms.MyChoose(
            data,
            "Cross-references to {0}::{1}".format(struct_type.dstr(), field_name),
            [["Function", 20 | idaapi.Choose2.CHCOL_PLAIN],
             ["Type", 2 | idaapi.Choose2.CHCOL_PLAIN],
             ["Line", 40 | idaapi.Choose2.CHCOL_PLAIN]]
        )
        idx = chooser.Show(True)
        if idx == -1:
            return

        xref = result[idx]
        idaapi.open_pseudocode(xref.func_ea + xref.offset, False)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM
