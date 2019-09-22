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
from miasm.expression.expression import ExprMem


log = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

parser = ArgumentParser("Disassemble a binary")
parser.add_argument('filename', help="File to disassemble")
parser.add_argument('-l', "--limit", help="File to write results", default=9223372036854775807)
parser.add_argument('-dst', "--file-destination", help="File to write results")
parser.add_argument('-m', "--memory-access-destination", help="File to write memory access")


args = parser.parse_args()



fdesc = open(args.filename, 'rb')

cont = Container.from_stream(fdesc)
machine = Machine(cont.arch)
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
addr = cont.entry_point
asmcfg = mdis.dis_multiblock(addr)


ir_arch = machine.ir(mdis.loc_db)
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

visited_locs = []
stack = [asmcfg.loc_key_to_block(mdis.loc_db.get_offset_location(addr))]

destination = None
if args.file_destination:
    destination = open(args.file_destination,'w')

memory_access_destination = None
if args.memory_access_destination:
    memory_access_destination = open(args.memory_access_destination,'w')

finish = False
processed_lines = 0
limit = int(args.limit)

while stack and not finish:
    asm_block = stack.pop()
    if asm_block.loc_key in visited_locs:
        continue
    visited_locs.append(asm_block.loc_key)
    if destination is not None:
       destination.write(asm_block.to_string())
    else:
        print(ircfg.get_block(asm_block.loc_key))
        print(asm_block)

    if memory_access_destination is not None:
        for instruction in asm_block.lines:
            for arg in instruction.args:
                if isinstance(arg, ExprMem):
                    memory_access_destination.write(hex(instruction.offset) + " " + instruction.to_string() + "\n")

    visited_locs.append(asm_block.loc_key)
    processed_lines += len(asm_block.lines)
    if processed_lines >= limit:
        finish = True
    for obj in asm_block.bto:
        if obj.c_t == AsmConstraint.c_next:
            stack.append(asmcfg.loc_key_to_block(obj.loc_key))
    for obj in asm_block.bto:
        if obj.c_t == AsmConstraint.c_to:
            stack.append(asmcfg.loc_key_to_block(obj.loc_key))