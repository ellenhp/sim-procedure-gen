import angr
import IPython
import auto_simproc

def gen_simprocedure(proj, symbol_name):
    addr = proj.loader.find_symbol(symbol_name).addr
    sim_procedure = auto_simproc.AutomaticSimProcedure(proj, addr)
    proj.hook(addr, sim_procedure)

proj = angr.Project("a.out", load_options={"auto_load_libs":False})

gen_simprocedure(proj, 'validateChar')
gen_simprocedure(proj, 'toLower')

s = proj.factory.entry_state()
simgr = proj.factory.simgr(s)
simgr.run()

def isRetNonzero(state):
    return state.history.events[-1].objects['exit_code'] != 0

for state in simgr.deadended:
    if isRetNonzero(state)._model_concrete:
        print 'found flag:', list(state.posix.dumps(0))
