# sim-procedure-gen

This project is for development and testing of automatic SimProcedure generation in angr. Currently, functions taking a single integral argument and returning a single integral argument are well-tested and supported. Bucketing of output states is supported via linearization for functions that take exactly one integral argument. Arbitrary numbers of integral arguments should work and as well as floating point arguments or mixes of the two, but these cases are currently untested.

Development may be sporatic, but automatically analyzing binaries for functions that would be ideal candidates for summarization is planned, as well as performance optimizations to the the summary/linearization process.
