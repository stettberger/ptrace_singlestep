ptrace_singlestep
=================

This is an example of using ptrace to singlestep through an x86 program on Linux.

This works for statically linked binaries, if ASLR is disabled[1].

Example output:

```
$ ./singlestepper null
Child stopped: 5
0x401bfd main+0
0x401bfe main+1
0x401c01 main+4
0x401c06 main+9
0x401c07 main+10
0x4023e9 __libc_start_main+953
0x4023eb __libc_start_main+955
Child exited: 1
Detaching
```

[1] sudo sysctl kernel.randomize_va_space=0 
