import re
import logging
import idaapi

import actions
import callbacks
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.core.type_library as type_library
import HexRaysPyTools.forms as forms

logger = logging.getLogger(__name__)
potential_negatives = {}


def _has_magic_comment(lvar):
    # type: (idaapi.lvar_t) -> bool
    # FIXME: Use internal IDA storage for CONTAINING_RECORD macro
    return bool(re.search("```.*```", lvar.cmt))


def _parse_magic_comment(lvar):
    if lvar.type().is_ptr():
        m = re.search('```(.+)```', lvar.cmt)
        if m:
            structure_name, offset = m.group(1).split('+')
            offset = int(offset)
            parent_tinfo = idaapi.tinfo_t()
            if parent_tinfo.get_named_type(idaapi.cvar.idati, structure_name) and parent_tinfo.get_size() > offset:
                member_name = dict(find_deep_members(parent_tinfo, lvar.type().get_pointed_object())).get(offset, None)
                if member_name:
                    return NegativeLocalInfo(lvar.type().get_pointed_object(), parent_tinfo, offset, member_name)
    return None


def find_deep_members(parent_tinfo, target_tinfo):
    udt_data = idaapi.udt_type_data_t()
    parent_tinfo.get_udt_details(udt_data)
    result = []
    for udt_member in udt_data:
        if udt_member.type.equals_to(target_tinfo):
            result.append((udt_member.offset / 8, udt_member.name))
        elif udt_member.type.is_udt():
            for offset, name in find_deep_members(udt_member.type, target_tinfo):
                final_name = udt_member.name + '.' + name if udt_member.name else name
                result.append((udt_member.offset / 8 + offset, final_name))
    return result


class NegativeLocalInfo:
    def __init__(self, tinfo, parent_tinfo, offset, member_name):
        self.tinfo = tinfo
        self.size = tinfo.get_size() if tinfo.is_udt else 0
        self.parent_tinfo = parent_tinfo
        self.offset = offset
        self.member_name = member_name

    def __repr__(self):
        return "Type - {0}, parent type - {1}, offset - {2}, member_name - {3}".format(
            self.tinfo.dstr(),
            self.parent_tinfo.dstr(),
            self.offset,
            self.member_name
        )


class NegativeLocalCandidate:
    def __init__(self, tinfo, offset):
        """
        Tinfo - type of the structure tha local variable points to. So it's stripped from pointer. Offset - is first
        found offset that points outside of the structure.
        :param tinfo: idaapi.tinfo_t
        :param offset: int
        """
        self.tinfo = tinfo
        self.offsets = [offset]

    def __repr__(self):
        return self.tinfo.dstr() + ' ' + str(self.offsets)

    def is_structure_offset(self, tinfo, offset):
        # Checks if structure tinfo contains a member at given offset
        # TODO:array checking
        udt_member = idaapi.udt_member_t()
        udt_member.offset = offset * 8
        if offset >= 0 and tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member) != -1:
            if udt_member.type.is_udt():
                return self.is_structure_offset(udt_member.type, offset - udt_member.offset / 8)
            return udt_member.offset == offset * 8
        return False

    def find_containing_structures(self, type_library):
        """
        Given the type library creates a list of structures from this library, that contains this structure and
        satisfy offset conditions.
        :param type_library: idaapi.til_t
        :returns: ordinal, offset, member_name, containing structure name
        """

        min_offset = min(self.offsets)
        min_offset = min_offset if min_offset < 0 else 0
        max_offset = max(self.offsets)
        max_offset = max_offset if max_offset > 0 else self.tinfo.get_size()
        # TODO: Check if all offsets are legal

        # Least acceptable size of the containing structure
        min_struct_size = max_offset - min_offset
        result = []
        parent_tinfo = idaapi.tinfo_t()
        target_tinfo = idaapi.tinfo_t()
        if not target_tinfo.get_named_type(type_library, self.tinfo.dstr()):
            print "[Warning] Such type doesn't exist in '{0}' library".format(type_library.name)
            return result
        for ordinal in xrange(1, idaapi.get_ordinal_qty(type_library)):
            parent_tinfo.create_typedef(type_library, ordinal)
            if parent_tinfo.get_size() >= min_struct_size:
                for offset, name in find_deep_members(parent_tinfo, target_tinfo):
                    # print "[DEBUG] Found {0} at {1} in {2}".format(name, offset, parent_tinfo.dstr())
                    if offset + min_offset >= 0 and offset + max_offset <= parent_tinfo.get_size():
                        result.append((ordinal, offset, name, parent_tinfo.dstr()))
        return result


class ReplaceVisitor(idaapi.ctree_parentee_t):

    def __init__(self, negative_lvars):
        super(ReplaceVisitor, self).__init__()
        self.negative_lvars = negative_lvars
        self.pvoid_tinfo = idaapi.tinfo_t(idaapi.BT_VOID)
        self.pvoid_tinfo.create_ptr(self.pvoid_tinfo)

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_add and expression.x.op == idaapi.cot_var and expression.y.op == idaapi.cot_num:
            index = expression.x.v.idx
            if index in self.negative_lvars:
                offset = expression.y.numval()
                if offset >= self.negative_lvars[index].size:
                    self.create_containing_record(expression, index, offset)
        elif expression.op == idaapi.cot_sub and expression.x.op == idaapi.cot_var and expression.y.op == idaapi.cot_num:
            index = expression.x.v.idx
            if index in self.negative_lvars:
                offset = -expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                self.create_containing_record(expression, index, offset)
        return 0

    def create_containing_record(self, expression, index, offset):
        negative_lvar = self.negative_lvars[index]
        logger.debug("Creating CONTAINING_RECORD macro, offset: {}, negative offset: {}, TYPE: {}".format(
            negative_lvar.offset,
            offset,
            negative_lvar.parent_tinfo.dstr()
        ))

        arg_address = idaapi.carg_t()
        if expression.op == idaapi.cot_var:
            arg_address.assign(expression)
        else:
            arg_address.assign(expression.x)

        arg_type = idaapi.carg_t()
        cexpr_helper = idaapi.create_helper(True, self.pvoid_tinfo, negative_lvar.parent_tinfo.dstr())
        arg_type.assign(cexpr_helper)

        arg_field = idaapi.carg_t()
        cexpr_helper = idaapi.create_helper(
            True,
            self.pvoid_tinfo,
            negative_lvar.member_name
        )
        arg_field.assign(cexpr_helper)
        return_tinfo = idaapi.tinfo_t(negative_lvar.parent_tinfo)
        return_tinfo.create_ptr(return_tinfo)
        new_cexpr_call = idaapi.call_helper(return_tinfo, None, "CONTAINING_RECORD")
        new_cexpr_call.a.push_back(arg_address)
        new_cexpr_call.a.push_back(arg_type)
        new_cexpr_call.a.push_back(arg_field)
        new_cexpr_call.thisown = False

        parent = reversed(self.parents).next().cexpr

        diff = negative_lvar.offset + offset
        if diff:
            number = idaapi.make_num(diff)
            number.thisown = False
            new_cexpr_add = helper.my_cexpr_t(idaapi.cot_add, x=new_cexpr_call, y=number)
            new_cexpr_add.type = return_tinfo

            if parent.op == idaapi.cot_ptr:
                tmp_tinfo = idaapi.tinfo_t()
                tmp_tinfo.create_ptr(parent.type)
                new_cexpr_cast = helper.my_cexpr_t(idaapi.cot_cast, x=new_cexpr_add)
                new_cexpr_cast.thisown = False
                new_cexpr_cast.type = tmp_tinfo
                expression.assign(new_cexpr_cast)
            else:
                expression.assign(new_cexpr_add)
        else:
            if parent.op == idaapi.cot_ptr:
                tmp_tinfo = idaapi.tinfo_t()
                tmp_tinfo.create_ptr(parent.type)
                new_cexpr_cast = helper.my_cexpr_t(idaapi.cot_cast, x=new_cexpr_call)
                new_cexpr_cast.thisown = False
                new_cexpr_cast.type = tmp_tinfo
                expression.assign(new_cexpr_cast)
            else:
                expression.assign(new_cexpr_call)


class SearchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc):
        super(SearchVisitor, self).__init__()
        self.cfunc = cfunc
        self.result = {}

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_call and expression.x.op == idaapi.cot_helper and len(expression.a) == 3:
            if expression.x.helper == "CONTAINING_RECORD":
                if expression.a[0].op == idaapi.cot_var:
                    idx = expression.a[0].v.idx
                    if expression.a[1].op == idaapi.cot_helper and expression.a[2].op == idaapi.cot_helper:
                        parent_name = expression.a[1].helper
                        member_name = expression.a[2].helper
                        parent_tinfo = idaapi.tinfo_t()
                        if not parent_tinfo.get_named_type(idaapi.cvar.idati, parent_name):
                            return 0
                        udt_data = idaapi.udt_type_data_t()
                        parent_tinfo.get_udt_details(udt_data)
                        udt_member = filter(lambda x: x.name == member_name, udt_data)
                        if udt_member:
                            tinfo = udt_member[0].type
                            self.result[idx] = NegativeLocalInfo(
                                tinfo,
                                parent_tinfo,
                                udt_member[0].offset / 8,
                                member_name
                            )
                            return 1
        return 0


class AnalyseVisitor(idaapi.ctree_parentee_t):
    def __init__(self, candidates):
        global potential_negatives
        super(AnalyseVisitor, self).__init__()
        self.candidates = candidates
        self.potential_negatives = potential_negatives
        self.potential_negatives.clear()

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_add and expression.y.op == idaapi.cot_num:
            if expression.x.op == idaapi.cot_var and expression.x.v.idx in self.candidates:
                idx = expression.x.v.idx
                number = expression.y.numval()
                if self.candidates[idx].get_size() <= number:
                    if idx in self.potential_negatives:
                        self.potential_negatives[idx].offsets.append(number)
                    else:
                        self.potential_negatives[idx] = NegativeLocalCandidate(self.candidates[idx], number)
        elif expression.op == idaapi.cot_sub and expression.y.op == idaapi.cot_num:
            if expression.x.op == idaapi.cot_var and expression.x.v.idx in self.candidates:
                idx = expression.x.v.idx
                number = -expression.y.numval()
                if idx in self.potential_negatives:
                    self.potential_negatives[idx].offsets.append(number)
                else:
                    self.potential_negatives[idx] = NegativeLocalCandidate(self.candidates[idx], number)

        return 0


class PotentialNegativeCollector(callbacks.HexRaysEventHandler):
    def __init__(self):
        super(PotentialNegativeCollector, self).__init__()

    def handle(self, event, *args):
        global potential_negatives

        cfunc, level_of_maturity = args
        if level_of_maturity == idaapi.CMAT_BUILT:
            # First search for CONTAINING_RECORD made by Ida
            visitor = SearchVisitor(cfunc)
            visitor.apply_to(cfunc.body, None)
            negative_lvars = visitor.result

            # Second get saved information from comments
            lvars = cfunc.get_lvars()
            for idx in xrange(len(lvars)):
                result = _parse_magic_comment(lvars[idx])
                if result and result.tinfo.equals_to(lvars[idx].type().get_pointed_object()):
                    negative_lvars[idx] = result

            # Third analyze local variables that are a structure pointers and have references going beyond
            # structure boundaries. This variables will be considered as potential pointers to substructure
            # and will get a special menu on right click

            # First collect all structure pointers
            structure_pointer_variables = {}
            for idx in set(range(len(lvars))) - set(negative_lvars.keys()):
                if lvars[idx].type().is_ptr():
                    pointed_tinfo = lvars[idx].type().get_pointed_object()
                    if pointed_tinfo.is_udt():
                        structure_pointer_variables[idx] = pointed_tinfo

            # Then use them in order to find all potential negative offset situations
            if structure_pointer_variables:
                visitor = AnalyseVisitor(structure_pointer_variables)
                visitor.apply_to(cfunc.body, None)

            # If negative offsets were found, then we replace them with CONTAINING_RECORD macro
            if negative_lvars:
                visitor = ReplaceVisitor(negative_lvars)
                visitor.apply_to(cfunc.body, None)


callbacks.hx_callback_manager.register(idaapi.hxe_maturity, PotentialNegativeCollector())


class ResetContainingStructure(actions.HexRaysPopupAction):
    description = "Reset Containing Structure"

    def __init__(self):
        super(ResetContainingStructure, self).__init__()

    def check(self, hx_view):
        ctree_item = hx_view.item
        if ctree_item.citype != idaapi.VDI_EXPR or ctree_item.e.op != idaapi.cot_var:
            return False
        return _has_magic_comment(hx_view.cfunc.get_lvars()[ctree_item.e.v.idx])

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        lvar = hx_view.cfunc.get_lvars()[hx_view.item.e.v.idx]
        hx_view.set_lvar_cmt(lvar, re.sub("```.*```", '', lvar.cmt))
        hx_view.refresh_view(True)


actions.action_manager.register(ResetContainingStructure())


class SelectContainingStructure(actions.HexRaysPopupAction):
    description = "Select Containing Structure"

    def __init__(self):
        super(SelectContainingStructure, self).__init__()

    def check(self, hx_view):
        ctree_item = hx_view.item
        if ctree_item.citype != idaapi.VDI_EXPR or ctree_item.e.op != idaapi.cot_var:
            return False
        return ctree_item.e.v.idx in potential_negatives

    def activate(self, ctx):
        global potential_negatives

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = type_library.choose_til()
        if not result:
            return

        selected_library, max_ordinal, is_local_types = result
        lvar_idx = hx_view.item.e.v.idx
        candidate = potential_negatives[lvar_idx]
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
                type_library.import_type(selected_library, items[selected_idx][3])
            lvar = hx_view.cfunc.get_lvars()[lvar_idx]
            lvar_cmt = re.sub("```.*```", '', lvar.cmt)
            hx_view.set_lvar_cmt(
                lvar,
                lvar_cmt + "```{0}+{1}```".format(
                    structures[selected_idx][3],
                    structures[selected_idx][1])
            )
            hx_view.refresh_view(True)


actions.action_manager.register(SelectContainingStructure())
