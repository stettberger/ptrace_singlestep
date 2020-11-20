ptrace_singlestep
=================

This is an example of using ptrace to singlestep through an x86 program on Linux.

This works for statically linked binaries, if ASLR is disabled[1].

[1] sudo sysctl kernel.randomize_va_space=0 
