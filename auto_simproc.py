import angr
import IPython
import claripy
from auto_simproc_argument import AutomaticSimProcedureArgument

class AutomaticSimProcedure(angr.SimProcedure):
    def __init__(self, proj, addr, **kwargs):
        angr.SimProcedure.__init__(self, project=proj, **kwargs)
        cc = proj.factory.cc()
        c = proj.factory.callable(addr, perform_merge=False)

        self.template_args = [claripy.BVS("auto_simproc_template_arg{}_MUST_REPLACE".format(i), 64) for i in range(self.num_args)]
        self.template_arg_annotations = {}
        self.symbolic_return_templates = []
        self.staged_return_buckets = {}
        self.return_buckets = {}

        for template_arg in self.template_args:
            annotation = AutomaticSimProcedureArgument()
            self.template_arg_annotations[annotation] = template_arg
            template_arg.append_annotation(annotation)

        c.perform_call(*self.template_args)
        states = c.result_path_group.active
        constraint_sets = {}
        for state in states:
            state.se.simplify()
            ret = cc.get_return_val(state)
            key = ret.cache_key
            if key not in constraint_sets.keys():
                constraint_sets[key] = []
            constraint_sets[key].append(claripy.And(*state.se.constraints))

        self._constrain_argument_sizes(constraint_sets)
        self._linearize(constraint_sets)

    def _create_return_bucket(self, return_key, constraint_sets, linearized=False):
        # We can do this right away, since any constraint set in our list results in this return value
        constraints = claripy.Or(*constraint_sets)

        # Tentatively say that the claripy value we'll return is going to be the ast associated with the key
        # This is problematic when the argument (or some AST that depends on it) is returned by the simproc.
        retval = return_key.ast

        if not linearized:
            # return_key might be tainted by an argument, which makes replacement really tricky during the application of this template
            # To handle this, we'll create an intermediate symbolic value and add a constraint that this value is equal to return_key.ast
            retval = claripy.BVS('auto_simproc_symbolic_return_MUST_REPLACE', 64)
            constraints = claripy.And(constraints, retval == return_key.ast)

        # That's all there is to it!
        self.return_buckets[retval.cache_key] = constraints

    def _constrain_argument_sizes(self, constraint_sets):
        arg_size_maps = []
        for key in constraint_sets.keys():
            arg_size_maps.append(self._walk_ast(key.ast))
            for constraint_set in constraint_sets[key]:
                arg_size_maps.append(self._walk_ast(constraint_set))

        #maps args to the highest order bit observed to be used in the constraints and return values
        arg_sizes = {}
        for arg in self.template_args:
            arg_sizes[arg.cache_key] = 0
        for arg_size_map in arg_size_maps:
            for bit_key in arg_size_map.keys():
                for arg_key, bit in arg_size_map[bit_key]:
                    arg_sizes[arg_key] = max(bit + 1, arg_sizes[arg_key])

        size_costraints = []

        for arg in self.template_args:
            size = arg_sizes[arg.cache_key]
            size_costraints.append(arg[63:size] == 0)

        self.arg_size_constraint = claripy.And(*size_costraints)

    def _walk_ast(self, ast):
        if not isinstance(ast, claripy.ast.base.Base):
            return {}
        elif ast.op == 'BVV':
            return {}
        elif ast.op == 'BVS':
            if ast.cache_key in [ast.cache_key for ast in self.template_args]:
                return {i: {(ast.cache_key, i)} for i in xrange(len(ast))}
            else:
                return {}
        elif ast.op == 'Extract':
            left, right, sub = ast.args
            sub_bitmap = self._walk_ast(sub)
            return {i - right: sub_bitmap[i] for i in xrange(right, left+1)}
        elif ast.op == 'Concat':
            out = {}
            sofar = 0
            for sub in ast.args:
                sub_bitmap = self._walk_ast(sub)
                for i in sub_bitmap:
                    out[i + sofar] = set(sub_bitmap[i])
                sofar += len(sub)
            return out
        elif ast.op in ('__and__', '__or__', '__xor__', '__invert__'):
            out = {}
            for sub in ast.args:
                sub_bitmap = self._walk_ast(sub)
                for i in sub_bitmap:
                    if i not in out:
                        out[i] = set(sub_bitmap[i])
                    else:
                        out[i] |= sub_bitmap[i]
            return out
        # TODO: ror/rol, lshift/rshift/arshift
        # TODO: something fun where we analyze how bits propogate through arithmetic operations
        else:
            # assume all unknown operations mix all bits
            all_bits = set()
            for sub in ast.args:
                sub_bitmap = self._walk_ast(sub)
                for i in sub_bitmap:
                    all_bits |= sub_bitmap[i]

            if isinstance(ast, claripy.ast.bool.Bool):
                return {0: all_bits}
            elif isinstance(ast, claripy.ast.bits.Bits):
                return {i: set(all_bits) for i in xrange(len(ast))}
            else:
                raise ValueError('Unknown AST type')

    def _linearize(self, constraint_sets):
        solver = claripy.Solver()

        def fully_constrained(value, key):
            tmp_solver = claripy.Solver()
            tmp_solver.add(constraint_sets[key][0])
            tmp_solver.add(self.arg_size_constraint)
            return len(tmp_solver.eval(value, 2)) == 1

        def can_linearize(key):
            if self.num_args != 1:
                # It sure would be cool if we could do more fancy stuff than just linearizing, but that's for later.
                return False
            if len(constraint_sets[key]) != 1:
                # There's more than one input that leads to this output, so we can't linearize
                # Don't get rid of this behavior because it's relied upon for correctness later on.
                return False
            else:
                # Note that we can linearize symbolic values, the only requirement is that they must be fully constrained by the accompanying constraint set
                # This is imperative because we're going to apply a continuous (linear) function to the input to get the output
                return all([fully_constrained(arg, key) for arg in self.template_args])

        # This is a list of the keys associated with all return values
        all_keys = constraint_sets.keys()

        # Seperate out linearizable keys from unlinearizable keys
        linearizable_keys = [key for key in all_keys if can_linearize(key)]
        unlinearizable_keys = [key for key in all_keys if key not in linearizable_keys]

        # Each unlinearizable key gets its own return bucket
        for key in unlinearizable_keys:
            self._create_return_bucket(key, constraint_sets[key])

        # These are methods to get the values of the return val and argument for any given key
        # We've already checked that these are fully constrained values
        def val_ret(key):
            tmp_solver = claripy.Solver()
            tmp_solver.add(constraint_sets[key])
            return tmp_solver.eval(key.ast, 1)[0]

        def val_arg(key):
            tmp_solver = claripy.Solver()
            tmp_solver.add(constraint_sets[key])
            return tmp_solver.eval(self.template_args[0], 1)[0] # Grabbing the first arg is correct because we've already verified there's only one!

        # Linearization happens here. it's basically y=mx+b, restarting with a new line every time there's a discontinuity.
        buckets = []
        bucket = []
        coefficient = 0
        for key in sorted(linearizable_keys, key=lambda key: val_ret(key)):
            if len(bucket) == 0:
                bucket.append(key)
                continue

            dy = val_ret(key) - val_ret(bucket[-1])
            dx = val_arg(key) - val_arg(bucket[-1])

            if len(bucket) == 1:
                if dy % dx == 0:
                    #define the coefficient, greedily add this key to the bucket
                    coefficient = dy/dx
                    bucket.append(key)
                else:
                    #we can't do anything with this bucket if the coefficient isn't an integer
                    buckets.append(bucket)
                    bucket = [key]
            else:
                if dy % dx == 0 and coefficient == dy/dx:
                    #the linear pattern continues! add it to the bucket
                    bucket.append(key)
                else:
                    #done with this bucket, start a new one
                    buckets.append(bucket)
                    bucket = [key]

        #after all that, make sure to add the last bucket to our list of all buckets
        if len(bucket) != 0:
            buckets.append(bucket)

        for bucket in buckets:
            if len(bucket) == 1:
                #this is an easy case, bucketing bought us nothing.
                self._create_return_bucket(bucket[0], constraint_sets[key][0])
            else:
                #create the constraint
                constraints = claripy.Or(*[claripy.Or(*constraint_sets[key]) for key in bucket])

                #define a symbolic return
                retval = claripy.BVS('auto_simproc_linearized_return_MUST_REPLACE', 64)
                self.symbolic_return_templates.append(retval.cache_key)

                #save this so we can use it later to establish mutual exclusivity! this is sort of a hack but it's very important
                # constraints_without_bucket_info[retval.cache_key] = constraints

                #now we constrain the symbolic return value to be a function of the input, with good old y=mx+b
                m = (val_ret(bucket[1]) - val_ret(bucket[0])) / (val_arg(bucket[1]) - val_arg(bucket[0]))
                b = val_ret(bucket[0]) - m * val_arg(bucket[0])
                constraints = claripy.And(retval == ((m * self.template_args[0]) + b), constraints)

                #now add the whole bucket with one key
                self._create_return_bucket(retval.cache_key, (constraints,), linearized=True)

    def run(self, arg):
        actual_args = self.cc.arg(self.state, 0)

        symbolic_ret = claripy.BVS('auto_simproc_symbolic_return_allstates', 64)

        ret_addr = None
        if self.use_state_arguments:
            ret_addr = self.cc.teardown_callsite(
                    self.state,
                    symbolic_ret,
                    arg_types=[False]*self.num_args if self.cc.args is None else None)

        for key in self.return_buckets.keys():
            arg_size_constraint = self.arg_size_constraint
            template_constraint = self.return_buckets[key]

            retval = claripy.BVS('auto_simproc_symbolic_return', 64)
            template_constraint = template_constraint.replace(key.ast, retval)

            symbolic_args = []
            for arg in self.template_args:
                symbolic_arg = claripy.BVS('auto_simproc_symbolic_arg', 64)
                symbolic_args.append(symbolic_arg)
                template_constraint = template_constraint.replace(arg, symbolic_arg)
                arg_size_constraint = arg_size_constraint.replace(arg, symbolic_arg)

            successor = self.state.copy()
            successor.se.add(arg_size_constraint)
            successor.se.add(template_constraint)
            successor.se.add(symbolic_ret == retval)

            for actual_arg, symbolic_arg in zip([self.cc.arg(self.state, arg_index) for arg_index in range(len(symbolic_args))], symbolic_args):
                successor.se.add(actual_arg == symbolic_arg)

            self._exit_action(successor, ret_addr)
            self.successors.add_successor(successor, ret_addr, self.state.se.true, 'Ijk_Ret')
