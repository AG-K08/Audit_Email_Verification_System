
####### fns
print("\n\n############### TESTING FNS OBJECT ####################")

# analysis.fns[ea_start:ea_end] would return an iterator over all bfunctions in this address range
fns = list(analysis.fns[analysis.map.from_phys(0) : analysis.map.from_phys(0x5000)])
print(f"there are {len(fns)} functions in range[#0-#5000[")

first_function = analysis.fns.find_forward(0)
if first_function is not None:
    print(f"first function of file: {first_function} at [0x{analysis.map.to_virt(first_function.start):x} - 0x{analysis.map.to_virt(first_function.end):x}[")
last_function = analysis.fns.find_backward(len(analysis.map))
if last_function is not None:
    print(f"last function of file: {last_function} at 0x{analysis.map.to_virt(last_function.start):x} ({len(last_function)} bytes)")

for fn in itertools.islice(analysis.fns, 3):
    print(f"* function {fn.fullname} at #{analysis.map.to_phys(fn.start):x}")
    print(f"  module part of name: {fn.module}")        # X1.X2.Y<Z1, Z2>(A1, A2) -> X1.X2
    print(f"  identifier part of name: {fn.name}")      # X1.X2.Y<Z1, Z2>(A1, A2) -> Y
    print(f"  template parameters: {fn.template_args}") # X1.X2.Y<Z1, Z2>(A1, A2) -> [Z1, Z2]
    print(f"  arguments: {fn.args}")                    # X1.X2.Y<Z1, Z2>(A1, A2) -> [A1, A2]
    print(f"  number of instructions: {fn.num_instructions}")     
    print(f"  number of intra-jumps: {fn.num_intra_jumps}")     
    print(f"  number of basic blocks: {fn.num_bb}")     
    print(f"  opcode stats:")
    for type in malcat.Instruction.Type.__members__.values():
        print(f"    num_{type.name.lower()}: {getattr(fn, 'num_' + type.name.lower())}")




####### cfg
print("\n\n############### TESTING CFG OBJECT ####################")
#The CFG, or control flow graph, divides executable code into a graph of basic blocks. Basic blocks are contiguous file ranges that satisfies:
#  * control flow always starts at the beginning of the block for every possible execution of the program
#  * control flow always goes to the end of the block for every possible execution of the program
#  * the basic block is located in a single region
#  * basic blocks have incoming and outgoing edges, which can be of 4 types: STEP, JUMP, CALL or EXCEPTION
#In order to simplify the interface a bit and make code easier to read, non-code regions (i.e. data) also belong to special basic blocks named data blocks, which have no incoming nor outgoing edges. 

# analysis.cfg[ea_start:ea_end] would return an iterator over all basic blocks in this address range
bbs = list(analysis.cfg[analysis.map.from_phys(0) : analysis.map.from_phys(0x5000)])
print("there are {} basic blocks in range[#0-#5000[".format(len(bbs)))

# describe first 10 basic blocks
for bb in itertools.islice(analysis.cfg, 10):
    print(f"* BasicBlock at [#{analysis.map.to_phys(bb.start):x}-#{analysis.map.to_phys(bb.end):x}[ ({bb.code and 'CODE' or 'DATA'})")
    # incoming edges
    for inc_edge in itertools.islice(bb.incoming, 5):
        # you can use analysis.cfg[<ea>] to get the basic block contain address <ea>
        source_bb = analysis.cfg[inc_edge.address]
        print("    > incoming edge ({}) from [#{:x}:#{:x}[".format(inc_edge.type, analysis.map.to_phys(source_bb.start), analysis.map.to_phys(source_bb.end)))

    # you can use analysis.cfg.align(x) to align address <x> to the previous instruction boundary
    # It is more precise than analysis.asm.align since it uses basic block start address 
    # as a known valid instruction start
    if bb.code:
        last_instr_adr = analysis.cfg.align(bb.end - 1)
        print("    Last instruction is at #{:x} : {}".format(last_instr_adr, analysis.asm[last_instr_adr]))


####### analysis.xref
print("\n\n############### TESTING XREF OBJECT ####################")
for xref in itertools.islice(analysis.xref, 5):
    print(f"* 0x{analysis.map.to_virt(xref.address):x} is referenced by:")
    for ref_type, ref_source in xref:
        print(f"    * 0x{analysis.map.to_virt(ref_source):x} ({ref_type})")

first_function = analysis.fns.find_forward(0)
if first_function is not None and first_function.address in analysis.xref:
    xref = analysis.xref[first_function.address]
    print(f"\nFunction {first_function.name} is referenced {len(xref)}: times")
    for ref_type, ref_source in xref:
        print(f"    * 0x{analysis.map.to_virt(ref_source):x} ({ref_type})")


####### analysis.syms
print("\n\n############### TESTING SYMS OBJECT ####################")
for sym in itertools.islice(analysis.syms[0:len(analysis.map)], 5):
    print(f"* 0x{analysis.map.to_virt(sym.address):x} = {sym.name} ({sym.type})")

print("")
for tname in ("functions", "labels", "imports", "exports", "entrypoints", "variables", "typedefs"):
    print(f"* Number of {tname}: {getattr(analysis.syms, 'number_of_' + tname)}")

if "EntryPoint" in analysis.syms:
    ep_address = analysis.syms["EntryPoint"]
    print(f"\n* Entrypoint defined at address 0x{ analysis.map.to_virt(ep_address):x}")
    print(f"* List of symbols defined at 0x{ analysis.map.to_virt(ep_address):x}:")
    for sym in analysis.syms[ep_address]:
        print(f"    * 0x{analysis.map.to_virt(sym.address):x} = {sym.name} ({sym.type})")


####### analysis.sigs
print("\n\n############### TESTING SIGS OBJECT ####################")
for sig in analysis.sigs:
    print(f"yara rule {sig.name} ({sig.id}) : {sig.type} matched !")
    for pattern in sig.patterns:
        for offset, size in pattern.matches:
            print(f"    - pattern {pattern.id} matched at #{offset:x}-#{offset + size:x}")


print("\n\n############### TESTING STRINGS OBJECT ####################")
for s in itertools.islice(analysis.strings, 15):
    print(f"* string {repr(s.text)} found at #{analysis.map.to_phys(s.address):x}: {s.type}:{s.encoding} [tag={s.tag}] [score={s.score}] [entropy={s.entropy}]: bytes={s.bytes}")
print(f"sample has {'VirtualProtect' not in analysis.strings and 'not' or ''} the string VirtualProtect")


print("\n\n############### TESTING ENTROPY OBJECT ####################")
mid_address = analysis.map.from_phys(analysis.file.size // 2)
print(f"* Entropy of first half of the file: {analysis.entropy[:mid_address]} ({100*analysis.entropy[:mid_address] // 255}%)")
print(f"* Entropy of second half of the file: {analysis.entropy[mid_address:]} ({100*analysis.entropy[mid_address:] // 255}%)")


print("\n\n############### TESTING CARVED FILES OBJECT ####################")
if ".rsrc" in analysis.map:
    rsrc = analysis.map[".rsrc"]
    for sub in analysis.carved[rsrc.start:rsrc.end]:
        print(f"* Found sub-file '{sub.name}' in .rsrc at #{analysis.map.to_phys(sub.address):x} ({sub.size} bytes): {sub.type} [{sub.category}]")

print("\n\n############### TESTING VIRTUAL FILES OBJECT ####################")

for vfile in analysis.vfiles:
    print(f"* Virtual file '{vfile.path}' ({vfile.size} bytes)")