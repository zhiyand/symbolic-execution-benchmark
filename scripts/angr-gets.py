import angr

p = angr.Project('../gets.o');

init_state = p.factory.entry_state( args = [ "gets.o",  angr.StringSpec(sym_length=15, nonnull=True)], add_options={"BYPASS_UNSUPPORTED_SYSCALL"} )

pg = p.factory.path_group(init_state, immutable=False)

pg.explore()

print pg



