#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"

int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint argc, sz, sp, ustack[3+MAXARG+1];
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pde_t *pgdir, *oldpgdir;
  struct proc *curproc = myproc();

  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    cprintf("exec: fail\n");
    return -1;
  }
  ilock(ip);
  pgdir = 0;

  // Check ELF header
  if(readi(ip, (char*)&elf, 0, sizeof(elf)) != sizeof(elf))// opens executable and parses it
    goto bad;
  if(elf.magic != ELF_MAGIC)

  if((pgdir = setupkvm()) == 0) //initializes kernel memory
    goto bad;
  
  // The stack is loaded in from here
  // Load program into memory.
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))    //reads memory
      goto bad;
    if(ph.type != ELF_PROG_LOAD)           //checks if file is loadable
      continue;
    if(ph.memsz < ph.filesz)       //checks if there is enough memory to load file size
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)  //checks if loading the address will overflow
      goto bad;
    if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0) //allocated the memory
      goto bad;
    if(ph.vaddr % PGSIZE != 0)  //checks if stack takes one page
      goto bad;
    if(loaduvm(pgdir, (char*)ph.vaddr, ip, ph.off, ph.filesz) < 0) 
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
  //sz = PGROUNDUP(sz);	//gives top of of the stack
  //if((sz = allocuvm(pgdir, sz, sz + 2*PGSIZE)) == 0)   //allocuvm initialized pte so va to page is allocated and now the page may be used
  //
  //
  //			Changed allocuvm so that the newly allocated memory in the stack will be pointing to the bottom of the user space (KERNBASE -4 )
    if((sp = allocuvm(pgdir, KERNBASE- 4, KERNBASE - 2*PGSIZE) == 0)  
	goto bad;
  clearpteu(pgdir, (char*)(sp - 2*PGSIZE)); //makes sure the heap and stack dont touch this zone buffer.

//--------------------------------------------------------------------------------------------------------------------
  sp = KERNBASE - 4; 				// changes the stack pointer so that it points tothe top of the stack	                     
//--------------------------------------------------------------------------------------------------------------------
  // heap is loaded in here, the second page is being filled now 
  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {     
    if(argc >= MAXARG)
      goto bad;
    sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
    if(copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[3+argc] = sp;
  }
  ustack[3+argc] = 0;

  ustack[0] = 0xffffffff;  // fake return PC
  ustack[1] = argc;
  ustack[2] = sp - (argc+1)*4;  // argv pointer

  sp -= (3+argc+1) * 4;
  if(copyout(pgdir, sp, ustack, (3+argc+1)*4) < 0)
    goto bad;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(curproc->name, last, sizeof(curproc->name));

  // Commit to the user image.
  oldpgdir = curproc->pgdir;
  curproc->pgdir = pgdir;
  curproc->sz = sz;
  curproc->tf->eip = elf.entry;  // main
  curproc->tf->esp = sp;
  switchuvm(curproc);
  freevm(oldpgdir);
  return 0;

 bad:
  if(pgdir)
    freevm(pgdir);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
