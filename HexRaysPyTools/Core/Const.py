import idaapi
import idc

EA64 = idc.__EA64__
EA_SIZE = 8 if EA64 else 4

COT_ARITHMETIC = (idaapi.cot_num, idaapi.cot_fnum, idaapi.cot_add, idaapi.cot_fadd, idaapi.cot_sub, idaapi.cot_fsub,
                  idaapi.cot_mul, idaapi.cot_fmul, idaapi.cot_fdiv)

VOID_TINFO = None
PVOID_TINFO = idaapi.tinfo_t()
CONST_PVOID_TINFO = idaapi.tinfo_t()
BYTE_TINFO = None
PBYTE_TINFO = None

X_WORD_TINFO = None                 # DWORD for x32 and QWORD for x64
PX_WORD_TINFO = None

DUMMY_FUNC = None

LEGAL_TYPES = []


def init():
    global VOID_TINFO, PVOID_TINFO, CONST_PVOID_TINFO, BYTE_TINFO, PBYTE_TINFO, LEGAL_TYPES, X_WORD_TINFO, \
        PX_WORD_TINFO, DUMMY_FUNC

    VOID_TINFO = idaapi.tinfo_t(idaapi.BT_VOID)
    PVOID_TINFO.create_ptr(VOID_TINFO)
    CONST_PVOID_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID | idaapi.BTM_CONST))
    BYTE_TINFO = idaapi.tinfo_t(idaapi.BTF_BYTE)
    PBYTE_TINFO = idaapi.dummy_ptrtype(1, False)
    X_WORD_TINFO = idaapi.get_unk_type(EA_SIZE)
    PX_WORD_TINFO = idaapi.dummy_ptrtype(EA_SIZE, False)

    func_data = idaapi.func_type_data_t()
    func_data.rettype = PVOID_TINFO
    func_data.cc = idaapi.CM_CC_UNKNOWN
    DUMMY_FUNC = idaapi.tinfo_t()
    DUMMY_FUNC.create_func(func_data, idaapi.BT_FUNC)

    LEGAL_TYPES = [PVOID_TINFO, PX_WORD_TINFO, X_WORD_TINFO, PBYTE_TINFO]
