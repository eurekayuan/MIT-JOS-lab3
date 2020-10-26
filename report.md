# MIT 6.828 Lab 3 Report
Created by Arnold Z. Yuan on Oct. 25, 2020.

Original lab website: https://pdos.csail.mit.edu/6.828/2018/labs/lab3/

## Preliminaries
In order to manage user environments, the kernel should maintain a list containing all the user environments called `envs`, as well as a list of all the free envs called `env_free_list` for performance reasons. (So that we no longer need to walk through the whole list just to get a free block.) Every element in these two lists is a process control block (PCB) containing critical information regarding to the user environments. Also, `curenv` always points to the current environment as its name suggests.

Now that the structure of PCB and two lists of PCB have been defined, their memory should be allocated before using them later. But before going through the following exercises, we should first take a brief look at the memory management implementations of JOS (i.e. what TA has already done for us in exercise 1). In `kern/pmap.c`, `mem_init` allocates memory for `envs`, and maps the region to `UENVS` in order to enable the user process read from this array, which will be useful in exercise 8.

```c
N = ROUNDUP(pages_length, PGSIZE); 
boot_map_region(kern_pgdir, UPAGES, N, PADDR(pages), PTE_U);
```
## Exercise 2
### General Logic
During kernel initiation, it sets up memory for the user environment list. JOS leverages this list to keep track all of the critical information related to process control. Also, kernel sets up the Interrupt Descriptor Table (IDT) and trap handler during initiation.
```c
mem_init();
env_init();
trap_init();
```
Then, the kernel creates a user environment and executes it.
```c
ENV_CREATE(user_hello, ENV_TYPE_USER);

// We only have one user environment, so just use index 0 is okay.
env_run(&envs[0]); 
```
The kernel allocates a new environment with `env_alloc`. It loads the named elf binary into it with `load_icode`. Till now, the new environment's address space `env -> env_pgdir` and saved registers `env_tf` have already been set up. The `%eip` in the trap frame now points to the entry point of the ELF binary. `lcr3` and `env_pop_tf` switches address space and registers to the user environment respectively.
```c
lcr3(PADDR(curenv -> env_pgdir));
env_pop_tf(&(curenv -> env_tf));
```


### Details
This exercise is quite easy. We only have to follow the instructions given in the comments, so that it's just like comment translation. The difficult parts have already been implemented by TA (thanks a lot).

In `env_init`, the kernel sets up the `envs` list by linking the blocks together. Currently the list is all free, so that we can just let pointer `env_free_list` be the same as `envs`, both pointing to the first block in the list.

```c
for (int i = 0; i < NENV; i++) {
    struct Env *e = envs + i;
    if (i < NENV - 1)
        e -> env_link = e + 1;
    else
        e -> env_link = NULL;
    e -> env_id = 0;
    e -> env_status = ENV_FREE;
}
env_free_list = envs;
```

In `env_create`, we allocate a new environment and then load the ELF binary as described above.

```c
struct Env *e = NULL;
int r = env_alloc(&e, 0);
if (r < 0)
    panic("env_create: %e", r);
load_icode(e, binary);
e -> env_type = type;
```

In `env_run`, we just need to follow the instructions in the comments to perform context switch. Although there will only be one user environment in this lab, `env_run` assumes there may exist multiple environments. Therefore, it should first check the status of the current environment, and switch it to runnable if running. Then we set the status, update the counter and switch the address space and registers. However, it should also save the current registers before context switching, otherwise we cannot recover a currently running process. This is not yet implemented in this lab.
```c
if (curenv && curenv -> env_status == ENV_RUNNING)
    curenv -> env_status = ENV_RUNNABLE;

// Set 'curenv' to the new environment,
curenv = e;

// Set its status to ENV_RUNNING,
curenv -> env_status = ENV_RUNNING;

// Update its 'env_runs' counter,
curenv -> env_runs++;

// Use lcr3() to switch to its address space.
lcr3(PADDR(curenv -> env_pgdir));

// Use env_pop_tf() to restore the environment's registers and drop into user mode in the environment.
env_pop_tf(&(curenv -> env_tf));
```

## Exercise 4
### General Logic
When encountering a trap, the processor switches to the stack defined by the `SS0` and `ESP0` fields of the `TSS`, which in JOS will hold the values `GD_KD` and `KSTACKTOP`, respectively. Next, the processor pushes the exception parameters on the kernel stack, starting at address `KSTACKTOP`. These actions are taken in `trap_init_percpu`.

After that, the processor looks up IDT and enters the relative trap handler defined in `trapentry.S`. `TRAPHANDLER` and `TRAPHANDLER_NOEC` pushes an optional error code and the trap number onto the stack. Then, it jumps to `_alltraps`, which is a shared part of all trap handlers.

```assembly
pushl $0
pushl $(num)
jmp _alltraps
```
Now let's take a look at the structure of `Trapframe`. Before calling trap, we have to push its parameter `struct Trapframe *tf` onto the stack, which is a pointer pointing to a `Trapframe` struct. During the above steps, the kernel has already pushed everything including and below `tf_trapno`, leaving `tf_ds`, `tf_es` and general registers to be pushed right now.
```c
struct Trapframe {
	struct PushRegs tf_regs;
	uint16_t tf_es;
	uint16_t tf_padding1;
	uint16_t tf_ds;
	uint16_t tf_padding2;
	uint32_t tf_trapno;
	uint32_t tf_err;
	uintptr_t tf_eip;
	uint16_t tf_cs;
	uint16_t tf_padding3;
	uint32_t tf_eflags;
	uintptr_t tf_esp;
	uint16_t tf_ss;
	uint16_t tf_padding4;
} __attribute__((packed));
```
After calling `trap`, the kernel handles the trap in `trap_dispatch` and recovers the user environment (`env_run(curenv)`)

### Details
In `trap_init`, we should set up the IDT table. Note that in the `SETGATE` macro JOS has already provided for us, the second parameter indicates whether the trap is an interrupt or an exception. The definations can be found in the Intel 80386 manual. Besides, the fifth parameter decides the privilege level by whom the trap can be intrigued. In the gates of `T_BRKPT` and `T_SYSCALL`, this parameter should be 3, so that users can set the breakpoint and make system calls.
```c
void t_divide();
void t_debug();
void t_nmi();
void t_brkpt();
void t_oflow();
void t_bound();
void t_illop();
void t_device();
void t_dblflt();
void t_tss();
void t_segnp();
void t_stack();
void t_gpflt();
void t_pgflt();
void t_fperr();
void t_align();
void t_mchk();
void t_simderr();
void t_syscall();

SETGATE(idt[T_DIVIDE], true, GD_KT, t_divide, 0);
SETGATE(idt[T_DEBUG], true, GD_KT, t_debug, 0);
SETGATE(idt[T_NMI], false, GD_KT, t_nmi, 0);
SETGATE(idt[T_BRKPT], true, GD_KT, t_brkpt, 3);
SETGATE(idt[T_OFLOW], true, GD_KT, t_oflow, 0);
SETGATE(idt[T_BOUND], true, GD_KT, t_bound, 0);
SETGATE(idt[T_ILLOP], true, GD_KT, t_illop, 0);
SETGATE(idt[T_DEVICE], true, GD_KT, t_device, 0);
SETGATE(idt[T_DBLFLT], false, GD_KT, t_dblflt, 0);
SETGATE(idt[T_TSS], true, GD_KT, t_tss, 0);
SETGATE(idt[T_SEGNP], true, GD_KT, t_segnp, 0);
SETGATE(idt[T_STACK], true, GD_KT, t_stack, 0);
SETGATE(idt[T_GPFLT], true, GD_KT, t_gpflt, 0);
SETGATE(idt[T_PGFLT], true, GD_KT, t_pgflt, 0);
SETGATE(idt[T_FPERR], true, GD_KT, t_fperr, 0);
SETGATE(idt[T_ALIGN], true, GD_KT, t_align, 0);
SETGATE(idt[T_MCHK], false, GD_KT, t_mchk, 0);
SETGATE(idt[T_SIMDERR], true, GD_KT, t_simderr, 0);
SETGATE(idt[T_SYSCALL], true, GD_KT, t_syscall, 3);
```
In `trapentry.S`, we set up the handlers.
```c
TRAPHANDLER_NOEC(t_divide, T_DIVIDE);
TRAPHANDLER_NOEC(t_debug, T_DEBUG);
TRAPHANDLER_NOEC(t_nmi, T_NMI);
TRAPHANDLER_NOEC(t_brkpt, T_BRKPT);
TRAPHANDLER_NOEC(t_oflow, T_OFLOW);
TRAPHANDLER_NOEC(t_bound, T_BOUND);
TRAPHANDLER_NOEC(t_illop, T_ILLOP);
TRAPHANDLER_NOEC(t_device, T_DEVICE);
TRAPHANDLER(t_dblflt, T_DBLFLT);
TRAPHANDLER(t_tss, T_TSS);
TRAPHANDLER(t_segnp, T_SEGNP);
TRAPHANDLER(t_stack, T_STACK);
TRAPHANDLER(t_gpflt, T_GPFLT);
TRAPHANDLER(t_pgflt, T_PGFLT);
TRAPHANDLER_NOEC(t_fperr, T_FPERR);
TRAPHANDLER(t_align, T_ALIGN);
TRAPHANDLER_NOEC(t_mchk, T_MCHK);
TRAPHANDLER_NOEC(t_simderr, T_SIMDERR);
TRAPHANDLER_NOEC(t_syscall, T_SYSCALL);
```
In `_alltraps`, we write the following assembly code to fulfill the objectives proposed above.
```assembly
_alltraps:
	pushl %ds
	pushl %es
	pushal
	movw $GD_KD, %ax
	movw %ax, %ds
	movw %ax, %es
	pushl %esp
	call trap
```

## Exercise 5/6/7
### General logic
These three exercises are quite similar, so we combine them as one segment in this report. `trap` calls `trap_dispatch` to further handle the traps. It will first read `trapno` from its paramter passed previously. In this lab, we only need to handle three kinds of traps: page fault, breakpoint and system call. The first two is fair easy, we just have to call `page_fault_handler` and `monitor` respectively. 
```c
if (tf->tf_trapno == T_PGFLT) {
    page_fault_handler(tf);
    return;
} else if (tf->tf_trapno == T_BRKPT) {
    monitor(tf);
    return;
}
```
Handling system calls is a bit complex. Let's walk it through step by step. 

The user can only use system functions provided in `lib/syscall.c`, like `sys_cputs`. `sys_cputs` further calls `syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0)`. This `syscall` is a generic function template. The assembly code inside executes the `int` instruction, which trigers a trap. Therefore, when the user delivers a system call, it will intrigue a `T_SYSCALL` trap in the kernal. We can also notice that the following assembly code sets `%eax` to the type of the system call (and several other registers), which will be useful later. 
```assembly
"a" (num),
"d" (a1),
"c" (a2),
"b" (a3),
"D" (a4),
"S" (a5)
```
The kernel then calls `syscall` in `kern/syscall.c`, decides which function to call by `syscallno`, and finally executes the required function in kernel mode. The code in `syscall` of `kern/syscall.c` is given below.
```c
switch (syscallno) {

case SYS_cputs:
    sys_cputs((const char*)a1, a2);
    return 0;
case SYS_getenvid:
    return sys_getenvid();
case SYS_cgetc:
    return sys_cgetc();
case SYS_env_destroy:
    return sys_env_destroy((envid_t)a1);
default:
    return -E_INVAL;
}
```
In `trap.c`, we should pass the registers (previously set by `lib/syscall.c`) to `syscall`, so that it can receive the paramters. The result will be saved in `%eax`.
```c
else if (tf->tf_trapno == T_SYSCALL) {
    struct PushRegs *regs = &curenv->env_tf.tf_regs;
    int32_t result = syscall(regs->reg_eax,
                    regs->reg_edx,
                    regs->reg_ecx,
                    regs->reg_ebx,
                    regs->reg_edi,
                    regs->reg_esi);
    regs->reg_eax = result;
    return;
}
```

## Exercise 8
Notice that in `lib/entry.S`, we have already set `envs` to `UENVS`, so actually we are using the user version of `envs`.
```assembly
.set envs, UENVS
```
To set `thisenv` to point at our `Env` structure in `envs[]`, we can use `sys_getenvid` to the id and then get its index.
```c
envid_t envid = sys_getenvid();
thisenv = &envs[ENVX(envid)];
```

## Implement SYS_show_environments
With the previous knowledge, this part is not so difficult. First we should define the `sys_show_environments` function in `lib/syscall.c` to provide the user with API, which can directly be used by the user. Then, we define `sys_showenv` in `kern/sys.c`, which is responsible for handling the trap when an exception happens. In `sys_showenv`, we walk through the `envs` list. If each struct in the list is not free, we print out its id, status and register information using the already defined `print_regs`.
```c
for (int i = 0; i < NENV; i++) {
    struct Env *e = envs + i;
    if (e -> env_status != ENV_FREE) {
        cprintf("Environment ID: %08x\n", e -> env_id);
        cprintf("Environment status: %d\n", e -> env_status);
        struct PushRegs *regs = &e -> env_tf.tf_regs;
        print_regs(regs);
    }
}
```
The results are quite successful.
```
Environment ID: 00001000
Environment status: 3
  edi  0x00000000
  esi  0x00000000
  ebp  0xeebfdfb0
  oesp 0xefffffdc
  ebx  0x00000000
  edx  0x00000000
  ecx  0x00000000
  eax  0x00000004
```

## Question Answering
1. The page base address is stored in `kern_pgdir` and in register `cr3`. OS switches context by `lcr3()`. (A pointer to the page is saved in `pgdir`.)
2. `iret` (interrupt return) is the last instruction executed by the trap handler. After that, the kernel should switch context back to user mode. The top of kernel stack is defined in `KSTACKTOP`. `%esp` and `%eip` are saved by the processor, while `%eax` and `%ebx` are save by the JOS kernel.
3. Both IDT and GDT are containers for segment information. However, IDT stores executable segment for trap handlers, containing the handler entry point offset and base segment descriptor. GDT is the global descriptor table storing segment information (base address, privilege levels, ...) pertaining to the operating system's virtual memory. GDT is used for memory mapping. Segment selector and segment offset work coherently to consult the GDT.


## Acknowlegements
**The code of the required exercises are written on my own, except the IDT setup, which is so obscure that I didn't know where to start.** Therefore, I consulted online for others' implementation for some inspiration. From the author's code, I understand that we can use macro `SETGATE` for convience. I shall post the github link here: https://github.com/Babtsov/jos/tree/master/lab3

