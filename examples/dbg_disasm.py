import sys
from dotnetutils import dotnetpefile

SAMPLE = r'C:\Users\Research\Documents\Malware\samples\Nklnfovxuqt.dll'

dpe = dotnetpefile.try_get_dotnetpe(SAMPLE)

def show(rid, center_off=None, window=40):
    m = dpe.get_method_by_rid(rid)
    print('==== method rid={} token={} name={}'.format(rid, hex(m.get_token()), m.get_full_name()))
    dis = m.disassemble_method()
    instrs = dis.get_list_of_instrs()
    # find center index
    ci = 0
    if center_off is not None:
        for i, ins in enumerate(instrs):
            if ins.get_instr_offset() == center_off:
                ci = i
                break
    lo = max(0, ci - window)
    hi = min(len(instrs), ci + 8)
    for i in range(lo, hi):
        ins = instrs[i]
        mark = '  >>>' if ins.get_instr_offset() == center_off else '     '
        try:
            arg = ins.get_argument()
        except Exception as e:
            arg = '<argerr:{}>'.format(e)
        print('{} {:<6} {:<14} astack={} pstack={} arg={}'.format(
            mark, hex(ins.get_instr_offset()), ins.get_name(),
            ins.get_astack(), ins.get_pstack(), arg))

if __name__ == '__main__':
    rid = int(sys.argv[1])
    off = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
    win = int(sys.argv[3]) if len(sys.argv) > 3 else 40
    show(rid, off, win)
