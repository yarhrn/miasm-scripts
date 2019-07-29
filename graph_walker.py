from __future__ import print_function
import logging
from argparse import ArgumentParser
from pdb import pm

from future.utils import viewitems, viewvalues

from miasm.analysis.binary import Container
from miasm.core.asmblock import log_asmblock, AsmCFG, AsmConstraint
from miasm.core.interval import interval
from miasm.analysis.machine import Machine
from miasm.analysis.data_flow import dead_simp, \
    DiGraphDefUse, ReachingDefinitions, \
    replace_stack_vars, load_from_int, del_unused_edges
from miasm.expression.simplifications import expr_simp
from miasm.analysis.ssa import SSADiGraph
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA

log = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

parser = ArgumentParser("Disassemble a binary")
parser.add_argument('filename', help="File to disassemble")
parser.add_argument('address', help="Starting address for disassembly engine")
parser.add_argument('-dst', "--file-destination", help="File to write results")
parser.add_argument('-r', "--recurfunctions", action="store_true",
                    help="Disassemble founded functions")
parser.add_argument('-v', "--verbose", action="count", help="Verbose mode",
                    default=0)
parser.add_argument('-z', "--dis-nulstart-block", action="store_true",
                    help="Do not disassemble NULL starting block")
parser.add_argument('-s', "--simplify", action="count",
                    help="Apply simplifications rules (liveness, graph simplification, ...)",
                    default=0)
parser.add_argument('-a', "--try-disasm-all", action="store_true",
                    help="Try to disassemble the whole binary")
parser.add_argument('-i', "--image", action="store_true",
                    help="Display image representation of disasm")
parser.add_argument('-c', "--rawbinary", default=False, action="store_true",
                    help="Don't interpret input as ELF/PE/...")
parser.add_argument('-d', "--defuse", action="store_true",
                    help="Dump the def-use graph in file 'defuse.dot'."
                    "The defuse is dumped after simplifications if -s option is specified")
parser.add_argument('-p', "--ssa", action="store_true",
                    help="Generate the ssa form in  'ssa.dot'.")
parser.add_argument('-x', "--propagexpr", action="store_true",
                    help="Do Expression propagation.")
parser.add_argument('-y', "--stack2var", action="store_true",
                    help="*Try* to do transform stack accesses into variables. "
                    "Use only with --propagexpr option. "
                    "WARNING: not reliable, may fail.")
parser.add_argument('-e', "--loadint", action="store_true",
                    help="Load integers from binary in fixed memory lookup.")
parser.add_argument('-j', "--calldontmodstack", action="store_true",
                    help="Consider stack high is not modified in subcalls")


args = parser.parse_args()



with open(args.filename, "rb") as fdesc:
    cont = Container.from_stream(fdesc, addr=0)

bs = cont.bin_stream
e = cont.executable

arch = cont.arch
if not arch:
    print("Architecture recognition fail. Please specify it in arguments")
    exit(-1)

# Instance the arch-dependent machine
machine = Machine(arch)
mn, dis_engine = machine.mn, machine.dis_engine
ira, ir = machine.ira, machine.ir


mdis = dis_engine(bs, loc_db=cont.loc_db)
# configure disasm engine
mdis.dontdis_retcall = False
mdis.blocs_wd = None
mdis.dont_dis_nulstart_bloc = False
mdis.follow_call = True

adr = int(args.address,0)
todo = [(mdis, None, adr)]

done = set()
all_funcs = set()
all_funcs_blocks = {}


done_interval = interval()
finish = False

entry_points = set()
# Main disasm loop
while not finish and todo:
    while not finish and todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        asmcfg = mdis.dis_multiblock(ad)
        entry_points.add(mdis.loc_db.get_offset_location(ad))

        all_funcs.add(ad)
        all_funcs_blocks[ad] = asmcfg
        for block in asmcfg.blocks:
            for l in block.lines:
                done_interval += interval([(l.offset, l.offset + l.l)])

        if args.recurfunctions:
            for block in asmcfg.blocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.loc_db):
                    if not dest.is_loc():
                        continue
                    offset = mdis.loc_db.get_location_offset(dest.loc_key)
                    todo.append((mdis, instr, offset))


    if args.try_disasm_all:
        for a, b in done_interval.intervals:
            if b in done:
                continue
            log.debug('add func %s' % hex(b))
            todo.append((mdis, None, b))


# Generate dotty graph
all_asmcfg = AsmCFG(mdis.loc_db)
for blocks in viewvalues(all_funcs_blocks):
    all_asmcfg += blocks


visited_locs = []
stack = [asmcfg.loc_key_to_block(mdis.loc_db.get_offset_location(adr))]

destination = None
if args.file_destination:
    destination = open(args.file_destination,'w')

while stack:
    asm_block = stack.pop()
    if asm_block.loc_key in visited_locs:
        continue
    visited_locs.append(asm_block.loc_key)
    if destination is not None:
        destination.write(asm_block.to_string())
    else:
        print(asm_block)
    visited_locs.append(asm_block.loc_key)
    for obj in asm_block.bto:
        if obj.c_t == AsmConstraint.c_next:
            stack.append(asmcfg.loc_key_to_block(obj.loc_key))
    for obj in asm_block.bto:
        if obj.c_t == AsmConstraint.c_to:
            stack.append(asmcfg.loc_key_to_block(obj.loc_key))


