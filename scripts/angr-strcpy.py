import angr

p = angr.Project('../backdoor.o');

init_state = p.factory.entry_state( args = [ "backdoor.o",  angr.StringSpec(sym_length=2, nonnull=True)], add_options={"BYPASS_UNSUPPORTED_SYSCALL"} )

pg = p.factory.path_group(init_state, immutable=False)

pg.explore(find=0x400598, avoid=0x40057d)

print pg



