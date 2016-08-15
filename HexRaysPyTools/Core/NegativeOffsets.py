import re

import idaapi

import idc
EA64 = idc.__EA64__
EA_SIZE = 8 if EA64 else 4


def parse_lvar_comment(lvar):
    if lvar.type().is_ptr():
        m = re.search('```(.+)```', lvar.cmt)
        if m:
            name, offset = m.group(1).split('+')
            offset = int(offset)
            parent_tinfo = idaapi.tinfo_t()
            if not parent_tinfo.get_named_type(idaapi.cvar.idati, name):
                return None
            udt_data = idaapi.udt_type_data_t()
            parent_tinfo.get_udt_details(udt_data)
            udt_member = filter(lambda x: x.offset == offset*8, udt_data)
            if udt_member:
                member_name = udt_member[0].name
                return NegativeLocalInfo(udt_member[0].type, parent_tinfo, offset, member_name)
    return None


class NegativeLocalInfo:
    def __init__(self, tinfo, parent_tinfo, offset, member_name):
        self.tinfo = tinfo
        tmp_tinfo = self.tinfo.get_pointed_object()
        self.size = tmp_tinfo.get_size() if tmp_tinfo.is_udt else 0
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
        :returns: str(ordinal), str(offset), member_name, containing structure name
        """

        self.offsets = set(self.offsets)
        result = []
        parent_tinfo = idaapi.tinfo_t()
        udt_member = idaapi.udt_member_t()
        tmp_tinfo = idaapi.tinfo_t()
        if not tmp_tinfo.get_named_type(type_library, self.tinfo.dstr()):
            print "[Warning] Such type doesn't exist in '{0}' library".format(type_library.name)
            return result
        for ordinal in xrange(1, idaapi.get_ordinal_qty(type_library)):
            parent_tinfo.create_typedef(type_library, ordinal)
            udt_member.type = tmp_tinfo
            if parent_tinfo.find_udt_member(idaapi.STRMEM_TYPE, udt_member) != -1:
                # TODO: What if containing structure have more than one instance of structure?
                member_offset = udt_member.offset / 8
                is_nice_parent = True
                for offset in self.offsets:
                    if not self.is_structure_offset(parent_tinfo, member_offset + offset):
                        print "BAD FATHER", parent_tinfo.dstr()
                        is_nice_parent = False
                        break
                if is_nice_parent:
                    result.append([ordinal, member_offset + min(self.offsets), udt_member.name, parent_tinfo.dstr(), udt_member.offset / 8])
        return result


class ReplaceVisitor(idaapi.ctree_parentee_t):
    del_list = []

    def __init__(self, negative_lvars):
        super(ReplaceVisitor, self).__init__()
        self.negative_lvars = negative_lvars
        self.pvoid_tinfo = idaapi.tinfo_t(idaapi.BT_VOID)
        self.pvoid_tinfo.create_ptr(self.pvoid_tinfo)

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_add and expression.x.op == idaapi.cot_var and expression.y.op == idaapi.cot_num:
            # print "ADD TYPE", expression.type.dstr()
            index = expression.x.v.idx
            if index in self.negative_lvars:
                offset = expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                if offset < self.negative_lvars[index].size:
                    self.create_containing_record(expression, index, offset)
        elif expression.op == idaapi.cot_sub and expression.x.op == idaapi.cot_var and expression.y.op == idaapi.cot_num:
            # print "SUB TYPE", expression.type.dstr(), expression.x.type.dstr()
            index = expression.x.v.idx
            if index in self.negative_lvars:
                offset = -expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                self.create_containing_record(expression, index, offset)
        # elif expression.op == idaapi.cot_var:
        #     index = expression.v.idx
        #     if index in self.negative_lvars:
        #         self.create_containing_record(expression, index, 0)
        return 0

    def create_containing_record(self, expression, index, offset):

        negative_lvar = self.negative_lvars[index]
        print "[DEBUG] Rebuilding negative offset", negative_lvar.offset, offset, negative_lvar.parent_tinfo.dstr()
        diff = negative_lvar.offset + offset

        # if check_ida_bug(negative_lvar.parent_tinfo, diff * 8):
        #     print "[IDA ERROR] Try another member pointer in CONTAINING_RECORD macro"
        #     return
        # if diff:
        #     return

        arg_address = idaapi.carg_t()
        if expression.op == idaapi.cot_var:
            arg_address.consume_cexpr(expression)
        else:
            arg_address.consume_cexpr(expression.x)

        arg_type = idaapi.carg_t()
        cexpr_helper = idaapi.create_helper(
            True,
            self.pvoid_tinfo,
            negative_lvar.parent_tinfo.dstr()
        )
        arg_type.consume_cexpr(cexpr_helper)

        arg_field = idaapi.carg_t()
        cexpr_helper = idaapi.create_helper(
            True,
            self.pvoid_tinfo,
            negative_lvar.member_name
        )
        arg_field.consume_cexpr(cexpr_helper)
        return_tinfo = idaapi.tinfo_t(negative_lvar.parent_tinfo)
        return_tinfo.create_ptr(return_tinfo)
        new_cexpr_call = idaapi.call_helper(return_tinfo, None, "CONTAINING_RECORD")
        new_cexpr_call.a.push_back(arg_address)
        new_cexpr_call.a.push_back(arg_type)
        new_cexpr_call.a.push_back(arg_field)
        # new_cexpr_call.ea = expression.ea
        # new_cexpr_call.x.ea = expression.ea

        parent = reversed(self.parents).next().cexpr
        if diff:
            number = idaapi.make_num(diff)
            new_cexpr_add = idaapi.cexpr_t(idaapi.cot_add, new_cexpr_call, number)
            new_cexpr_add.type = return_tinfo
            if parent.op == idaapi.cot_ptr:
                tmp_tinfo = idaapi.tinfo_t()
                tmp_tinfo.create_ptr(parent.type)
                new_cexpr_cast = idaapi.cexpr_t(idaapi.cot_cast, new_cexpr_add)
                new_cexpr_cast.type = tmp_tinfo
                ReplaceVisitor.del_list.append(new_cexpr_cast)
                ReplaceVisitor.del_list.append(new_cexpr_add)
                expression.replace_by(new_cexpr_cast)
            else:
                ReplaceVisitor.del_list.append(new_cexpr_add)
                expression.replace_by(new_cexpr_add)
        else:
            if parent.op == idaapi.cot_ptr:
                tmp_tinfo = idaapi.tinfo_t()
                tmp_tinfo.create_ptr(parent.type)
                new_cexpr_cast = idaapi.cexpr_t(idaapi.cot_cast, new_cexpr_call)
                new_cexpr_cast.type = tmp_tinfo
                ReplaceVisitor.del_list.append(new_cexpr_cast)
                expression.replace_by(new_cexpr_cast)
            else:
                expression.replace_by(new_cexpr_call)


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
                            return None
                        udt_data = idaapi.udt_type_data_t()
                        parent_tinfo.get_udt_details(udt_data)
                        udt_member = filter(lambda x: x.name == member_name, udt_data)
                        if udt_member:
                            tinfo = udt_member[0].type
                            tinfo.create_ptr(tinfo)
                            # if tinfo.dstr() == "int *":
                            #     tinfo = idaapi.dummy_ptrtype(EA_SIZE, 0)
                            self.result[idx] = NegativeLocalInfo(
                                tinfo,
                                parent_tinfo,
                                udt_member[0].offset / 8,
                                member_name
                            )
                            return 1
        return 0


class AnalyseVisitor(idaapi.ctree_parentee_t):
    def __init__(self, candidates, potential_negatives):
        super(AnalyseVisitor, self).__init__()
        self.candidates = candidates
        self.potential_negatives = potential_negatives
        self.potential_negatives.clear()

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_add and expression.y.op == idaapi.cot_num:
            if expression.x.op == idaapi.cot_var and expression.x.v.idx in self.candidates:
                idx = expression.x.v.idx
                number = expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                if self.candidates[idx].get_size() <= number:
                    if idx in self.potential_negatives:
                        self.potential_negatives[idx].offsets.append(number)
                    else:
                        self.potential_negatives[idx] = NegativeLocalCandidate(self.candidates[idx], number)
        elif expression.op == idaapi.cot_sub and expression.y.op == idaapi.cot_num:
            if expression.x.op == idaapi.cot_var and expression.x.v.idx in self.candidates:
                idx = expression.x.v.idx
                number = -expression.y.n.value(idaapi.tinfo_t(idaapi.BT_INT))
                if idx in self.potential_negatives:
                    self.potential_negatives[idx].offsets.append(number)
                else:
                    self.potential_negatives[idx] = NegativeLocalCandidate(self.candidates[idx], number)

        return 0
