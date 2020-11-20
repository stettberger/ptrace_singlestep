#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include <stdint.h>
#include <map>
#include <pstreams/pstream.h>
#include <string>
#include <iostream>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

void fprint_wait_status(FILE *stream, int status)
{
    if( WIFSTOPPED(status) ) {
        fprintf(stream, "Child stopped: %d\n", WSTOPSIG(status));
    }
    if( WIFEXITED(status) ) {
        fprintf(stream, "Child exited: %d\n", WEXITSTATUS(status));
    }
    if( WIFSIGNALED(status) ) {
        fprintf(stream, "Child signaled: %d\n", WTERMSIG(status));
    }
    if( WCOREDUMP(status) ) {
        fprintf(stream, "Core dumped.\n");
    }
}

int ptrace_instruction_pointer(int pid, void **pc)
{
    struct user_regs_struct regs;
    if( ptrace(PTRACE_GETREGS, pid, NULL, (void*)&regs) ) {
        fprintf(stderr, "Error fetching registers from child process: %s\n",
            strerror(errno));
        return -1;
    }
    if( pc )
        *pc = (void*) regs.rip;
    return 0;
}

int singlestep(int pid)
{
    int retval, status;
    retval = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if( retval ) {
        return retval;
    }
    waitpid(pid, &status, 0);
    return status;
}

int main(int argc, char ** argv, char **envp)
{
    void* pc;
    pid_t pid;
    int status;
    char *program;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s elffile arg0 arg1 ...\n", argv[0]);
        exit(-1);
    }
    program = argv[1];
    char ** child_args = (char**) &argv[1];


    // run a process and create a streambuf that reads its stdout and stderr
    std::string cmd= std::string("nm -S ") + program;
    redi::ipstream proc(cmd, redi::pstreams::pstdout | redi::pstreams::pstderr);
    std::string line;
    // read child's stdout
    
    typedef std::map<long int, std::string> SymbolTable;
    SymbolTable symbols;
    static boost::regex expr("^([A-Fa-f0-9]+) ([A-Fa-f0-9]+) . (.*)$");
    while (std::getline(proc.out(), line)) {
		boost::smatch res;
		if (boost::regex_search(line, res, expr)) {
            std::string r0 = res[1];
            long int address = strtol(r0.c_str(), nullptr, 16);

            std::string symbol = res[3];

            symbols[address] = symbol;
        }
    }

    if (proc.eof() && proc.fail())
        proc.clear();

// read child's stderr
    while (std::getline(proc.err(), line))
        std::cout << "stderr: " << line << '\n';

    pid = fork();
    if( pid == -1 ) {
        fprintf(stderr, "Error forking: %s\n", strerror(errno));
        exit(-1);
    }
    if( pid == 0 ) {
        /* child */
        if( ptrace(PTRACE_TRACEME, 0, 0, 0) ) {
            fprintf(stderr, "Error setting TRACEME: %s\n", strerror(errno));
            exit(-1);
        }
        execve(program,child_args,envp);
    } else {
        /* parent */

        std::map<void*, unsigned> histogram;

        waitpid(pid, &status, 0);
        fprint_wait_status(stderr,status);

        bool trace = false;
        
        while( WIFSTOPPED(status) ) {
            if( ptrace_instruction_pointer(pid, &pc) ) {
                break;
            }
            SymbolTable::iterator it = symbols.lower_bound((long int)pc);
            if (it != symbols.begin()) {
                if ((long int) it->first != (long int)pc)
                    it--;

                long int offset = ((long int)pc - (long int)it->first);
                if (it->second == "main" && offset == 0)
                    trace = true;
                if (it->second == "exit" && offset == 0)
                    trace = false;
                if (trace)
                    std::cout << pc << " " << it->second << "+" << offset << std::endl;
            } else if (trace) {
                std::cout << pc << std::endl;
            }

            // auto search = histogram.find(pc);
            // if (search != histogram.end()) {
            //     *search ++;
            // } else {
            //     // histogram[pc] = 1;
            // }
            // fprintf(stderr, "PC: %p\n", (void*)pc);
            status = singlestep(pid);
        }
        fprint_wait_status(stderr, status);
        fprintf(stderr, "Detaching\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);

        for (auto h : histogram) {
            printf("%p: %d\n", h.first, h.second);
        }
    }

    return 0;
}
