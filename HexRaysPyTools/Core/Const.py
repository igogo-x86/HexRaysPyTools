import idaapi
import idc

EA64 = idc.__EA64__
EA_SIZE = 8 if EA64 else 4

PVOID_TINFO = idaapi.tinfo_t()
CONST_PVOID_TINFO = idaapi.tinfo_t()
BYTE_TINFO = None

X_WORD_TINFO = None                 # DWORD for x32 and QWORD for x64
PX_WORD_TINFO = None

LEGAL_TYPES = []


def init():
    global PVOID_TINFO, CONST_PVOID_TINFO, BYTE_TINFO, LEGAL_TYPES, X_WORD_TINFO, PX_WORD_TINFO

    PVOID_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID))
    CONST_PVOID_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID | idaapi.BTM_CONST))
    BYTE_TINFO = idaapi.tinfo_t(idaapi.BTF_BYTE)
    X_WORD_TINFO = idaapi.get_unk_type(EA_SIZE)
    PX_WORD_TINFO = idaapi.dummy_ptrtype(EA_SIZE, False)

    LEGAL_TYPES = [PVOID_TINFO, PX_WORD_TINFO, X_WORD_TINFO]
