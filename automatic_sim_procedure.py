import angr
import IPython
import claripy

class AutomaticSimProcedure(angr.SimProcedure):

    def define_behavior(self, proj, addr):
        cc = proj.factory.cc()
        c = proj.factory.callable(addr, perform_merge=False)
        self.template_arg = claripy.BVS("arg", 64)
        self.symbolic_return_templates = []

        c.perform_call(self.template_arg)
        states = c.result_path_group.active
        constraint_sets = {}
        for state in states:
            state.se.simplify()
            ret = cc.get_return_val(state)
            key = ret.cache_key
            if key not in constraint_sets.keys():
                constraint_sets[key] = []
            constraint_sets[key].append(claripy.And(*state.se.constraints))

        self._linearize(constraint_sets)

    def _bucket_by_return(self, constraint_sets):
        self.constraints_for_ret = {}
        for key in constraint_sets.keys():
            self.constraints_for_ret[key] = claripy.Or(*constraint_sets[key])


    def _linearize(self, constraint_sets):
        solver = claripy.Solver()

        # This will contain tuples of return values.
        # Return values are grouped together in a tuple of they do not require different successor states
        # This determination will be made by linear bucketing.

        def fully_constrained(value):
            if len(constraint_sets[key]) != 1:
                #There's more than one input that leads to this output, so we can't linearize
                #Don't get rid of this behavior because it's relied upon for correctness later on.
                return False
            tmp_solver = claripy.Solver()
            tmp_solver.add(constraint_sets[key][0])
            return len(tmp_solver.eval(value, 2)) == 1

        def can_linarize(key):
            if key.ast.symbolic:
                # can't linearize symbolic values
                return False
            else:
                # the input must be fully constrained, since we're going to apply a continuous function to the input to get the output
                return fully_constrained(self.template_arg)

        all_keys = constraint_sets.keys()

        # Seperate out linearizable keys from unlinearizable keys
        linearizable_keys = [key for key in all_keys if can_linarize(key)]
        unlinearizable_keys = [key for key in all_keys if key not in linearizable_keys]


        #each unlinearizable key gets its own successor state
        self.constraints_for_ret = {}
        constraints_without_bucket_info = {}
        for key in unlinearizable_keys:
            self.constraints_for_ret[key] = claripy.Or(*constraint_sets[key])
            constraints_without_bucket_info[key] = self.constraints_for_ret[key]

        #these are methods to get the values of the return val and argument for any given key
        val_ret = lambda key: solver.eval(key.ast, 1)[0]
        def val_arg(key):
            tmp_solver = claripy.Solver()
            tmp_solver.add(constraint_sets[key])
            return tmp_solver.eval(self.template_arg, 1)[0]

        #linearization happens here. it's basically y=mx+b, restarting with a new line every time there's a discontinuity.
        buckets = []
        bucket = []
        coefficient = 0
        for key in sorted(linearizable_keys, key=lambda key: solver.eval(key.ast, 1)[0]):
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
                self.constraints_for_ret[key] = claripy.Or(*constraint_sets[key])
                constraints_without_bucket_info[key] = self.constraints_for_ret[key]
            else:
                #this looks a little weird, but remember that the whole point of bucketing is reducing the effective number of keys
                #create the constraint
                constraints = claripy.Or(*[claripy.Or(*constraint_sets[key]) for key in bucket])

                #define a symbolic return
                retval = claripy.BVS('auto_sim_ret_bucket', 64)
                self.symbolic_return_templates.append(retval.cache_key)

                #save this so we can use it later to establish mutual exclusivity! this is sort of a hack but it's very important
                constraints_without_bucket_info[retval.cache_key] = constraints

                #now we constrain the symbolic return value to be a function of the input, with good old y=mx+b
                m = (val_ret(bucket[1]) - val_ret(bucket[0])) / (val_arg(bucket[1]) - val_arg(bucket[0]))
                b = val_ret(bucket[0]) - m * val_arg(bucket[0])
                constraints = claripy.And(retval == ((m * self.template_arg) + b), constraints)

                #now add the whole bucket with one key
                self.constraints_for_ret[retval.cache_key] = constraints

        #make sure that all successor states happen under mutually exclusive conditions
        for key in constraints_without_bucket_info.keys():
            other_keys = [k for k in constraints_without_bucket_info.keys() if k != key]
            other_constraints = [constraints_without_bucket_info[k] for k in other_keys]
            any_other_constraint_true = claripy.Or(*other_constraints)
            self.constraints_for_ret[key] = claripy.And(self.constraints_for_ret[key], claripy.Not(any_other_constraint_true))

    def run(self, arg):
        symbolic_ret = claripy.BVS('auto_sim_procedure_ret', 64)
        symbolic_arg = claripy.BVS('auto_sim_procedure_arg', 64)

        ret_addr = None
        if self.use_state_arguments:
            ret_addr = self.cc.teardown_callsite(
                    self.state,
                    symbolic_ret,
                    arg_types=[False]*self.num_args if self.cc.args is None else None)

        for key in self.constraints_for_ret.keys():
            retval = key.ast
            template_constraint = self.constraints_for_ret[key]
            retval = retval.replace(self.template_arg, symbolic_arg)
            if key in self.symbolic_return_templates:
                new_retval = claripy.BVS('bucket_symbolic_return', 64)
                template_constraint.replace(retval, new_retval)
                retval = new_retval
            actual_constraint = template_constraint.replace(self.template_arg, symbolic_arg).replace(retval, symbolic_ret)
            successor = self.state.copy()
            successor.se.add(actual_constraint)
            successor.se.add(symbolic_ret == retval)
            successor.se.add(symbolic_arg == arg)

            self._exit_action(successor, ret_addr)
            self.successors.add_successor(successor, ret_addr, self.state.se.true, 'Ijk_Ret')
