# Functions and classes for creating core dump.
# Code is inspired by criucoredump [1].
#
# [1] https://github.com/checkpoint-restore/criu/tree/criu-dev/coredump

#
import io
import elf
import ctypes

PAGESIZE = 4096

class elf_note:
    nhdr	= None	# Elf_Nhdr;
    owner	= None	# i.e. CORE or LINUX;
    data	= None	# Ctypes structure with note data;


class coredump:
    """
    A class to keep elf core dump components inside and
    functions to properly write them to file.
    """
    ehdr	= None	# Elf ehdr;
    phdrs	= []	# Array of Phdrs;
    notes	= []	# Array of elf_notes;
    vmas	= []	# Array of BytesIO with memory content;

    def __init__(self,task,vma_list,threads_registers,x86=False):
        self.task=task
        self.vma_list=vma_list
        self.threads_registers=threads_registers
        self.x86=x86

    def get_vma_flags(self,vma_flags):
            flags=0
            if vma_flags[0]=='r':
                flags = flags | elf.PF_R
            if vma_flags[1]=='w':
                flags = flags | elf.PF_W
            if vma_flags[2]=='x':
                flags = flags | elf.PF_X

            return flags

    def read_addr_range(self, task, start, end):
        pagesize = 4096

        # set the as with our new dtb so we can read from userland
        proc_as = task.get_process_address_space()

        # xrange doesn't support longs :(
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize



    def gen_vmas(self,):

        class vma_class:
            data = None
            filesz = None
            memsz = None
            flags = None
            start = None

        vmas_tmp = []
        for vma in  self.vma_list:
            size = vma.vm_end - vma.vm_start
            v = vma_class()
            v.filesz = size
            v.data =""
            for page in self.read_addr_range(self.task, vma.vm_start, vma.vm_end):
                 v.data+=page
            v.memsz = size
            v.start = vma.vm_start
            v.flags = self.get_vma_flags(str(vma.vm_flags))
            vmas_tmp.append(v)
        return vmas_tmp

    def gen_prpsinfo(self):
        """
        Generate NT_PRPSINFO note for process pid.
        """

        if self.x86 is True:
            prpsinfo = elf.elf_prpsinfo32()
        else:
            prpsinfo = elf.elf_prpsinfo()

        ctypes.memset(ctypes.addressof(prpsinfo), 0, ctypes.sizeof(prpsinfo))

        TASK_ALIVE	= 0x1
        TASK_DEAD	= 0x2
        TASK_STOPPED	= 0x3

        if self.task.state == TASK_ALIVE:
            prpsinfo.pr_state	= 0
        if self.task.state == TASK_DEAD:
            prpsinfo.pr_state	= 4
        if self.task.state == TASK_STOPPED:
            prpsinfo.pr_state	= 3

        prpsinfo.pr_sname	= '.' if prpsinfo.pr_state > 5 else "RSDTZW"[prpsinfo.pr_state]
        prpsinfo.pr_zomb	= 1 if prpsinfo.pr_state == 4 else 0
        prpsinfo.pr_nice	= 0 #default
        prpsinfo.pr_flag	= 0 #default
        prpsinfo.pr_uid		= self.task.uid
        prpsinfo.pr_gid		= self.task.gid
        prpsinfo.pr_pid		= self.task.pid
        prpsinfo.pr_ppid	= self.task.parent.pid
        prpsinfo.pr_pgrp	= self.task.parent.gid
        prpsinfo.pr_sid		= 0 #default
        prpsinfo.pr_fname	= self.task.comm
        prpsinfo.pr_psargs	= self.task.get_commandline()


        if self.x86 is True:
            nhdr = elf.Elf32_Nhdr()
            nhdr.n_namesz	= 5
            nhdr.n_descsz	= ctypes.sizeof(elf.elf_prpsinfo32())
            nhdr.n_type	= elf.NT_PRPSINFO

        else:
            nhdr = elf.Elf64_Nhdr()
            nhdr.n_namesz	= 5
            nhdr.n_descsz	= ctypes.sizeof(elf.elf_prpsinfo())
            nhdr.n_type	= elf.NT_PRPSINFO

        note = elf_note()
        note.data	= prpsinfo
        note.owner	= "CORE"
        note.nhdr 	= nhdr


        return note



    def gen_prstatus(self,thread):
        """
        Generate NT_PRSTATUS note for thread tid of process pid.
        """
        regs	= self.threads_registers[str(thread.pid)]

        prstatus = elf.elf_prstatus()

        ctypes.memset(ctypes.addressof(prstatus), 0, ctypes.sizeof(prstatus))

        prstatus.pr_pid		= thread.pid
        prstatus.pr_ppid	= thread.parent.pid
        prstatus.pr_pgrp	= thread.parent.gid
        prstatus.pr_sid		= 0        #default


        prstatus.pr_reg.r15		= regs["r15"]
        prstatus.pr_reg.r14		= regs["r14"]
        prstatus.pr_reg.r13		= regs["r13"]
        prstatus.pr_reg.r12		= regs["r12"]
        prstatus.pr_reg.rbp		= regs["rbp"]
        prstatus.pr_reg.rbx		= regs["rbx"]
        prstatus.pr_reg.r11		= regs["r11"]
        prstatus.pr_reg.r10		= regs["r10"]
        prstatus.pr_reg.r9		= regs["r9"]
        prstatus.pr_reg.r8		= regs["r8"]
        prstatus.pr_reg.rax		= regs["rax"]
        prstatus.pr_reg.rcx		= regs["rcx"]
        prstatus.pr_reg.rdx		= regs["rdx"]
        prstatus.pr_reg.rsi		= regs["rsi"]
        prstatus.pr_reg.rdi		= regs["rdi"]
        #prstatus.pr_reg.orig_rax	= regs["unknown?"]
        prstatus.pr_reg.rip		= regs["rip"]
        prstatus.pr_reg.cs		= regs["cs"]
        prstatus.pr_reg.eflags		= regs["eflags"]
        prstatus.pr_reg.rsp		= regs["rsp"]
        prstatus.pr_reg.ss		= regs["ss"]
    #	prstatus.pr_reg.fs_base		= regs["fs_base"]
    #	prstatus.pr_reg.gs_base		= regs["gs_base"]
    #	prstatus.pr_reg.ds		= regs["ds"]		MISSING
    #	prstatus.pr_reg.es		= regs["es"]
    #	prstatus.pr_reg.fs		= regs["fs"]
    #	prstatus.pr_reg.gs		= regs["gs"]

        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz	= 5
        nhdr.n_descsz	= ctypes.sizeof(elf.elf_prstatus())
        nhdr.n_type	= elf.NT_PRSTATUS

        note = elf_note()
        note.data	= prstatus
        note.owner	= "CORE"
        note.nhdr 	= nhdr

        return note


    def gen_prstatus_x86(self,thread):
        """
        Generate NT_PRSTATUS note for thread tid of process pid.
        """
        regs	= self.threads_registers[str(thread.pid)]

        prstatus = elf.elf_prstatus32()

        ctypes.memset(ctypes.addressof(prstatus), 0, ctypes.sizeof(prstatus))

        prstatus.pr_pid		= thread.pid
        prstatus.pr_ppid	= thread.parent.pid
        prstatus.pr_pgrp	= thread.parent.gid
        prstatus.pr_sid		= 0 #default

        if "ebx" in regs:
            prstatus.pr_reg.ebx	= regs["ebx"]
            prstatus.pr_reg.ecx	= regs["ecx"]
            prstatus.pr_reg.edx	= regs["edx"]
            prstatus.pr_reg.esi	= regs["esi"]
            prstatus.pr_reg.edi	= regs["edi"]
            prstatus.pr_reg.ebp	= regs["ebp"]
            prstatus.pr_reg.eax	= regs["eax"]
            prstatus.pr_reg.ds	= regs["ds"]
            prstatus.pr_reg.es	= regs["es"]
            prstatus.pr_reg.fs	= regs["fs"]
            prstatus.pr_reg.gs	= regs["gs"]
            prstatus.pr_reg.orig_eax	= regs["orig_eax"]
            prstatus.pr_reg.eip	= regs["eip"]
            prstatus.pr_reg.cs	= regs["cs"]
            prstatus.pr_reg.eflags	= regs["eflags"]
            prstatus.pr_reg.esp	= regs["esp"]
            prstatus.pr_reg.ss	= regs["ss"]
        else:
            prstatus.pr_reg.ebx	= regs["rbx"]
            prstatus.pr_reg.ecx	= regs["rcx"]
            prstatus.pr_reg.edx	= regs["rdx"]
            prstatus.pr_reg.esi	= regs["rsi"]
            prstatus.pr_reg.edi	= regs["rdi"]
            prstatus.pr_reg.ebp	= regs["rbp"]
            prstatus.pr_reg.eax	= regs["rax"]
            #prstatus.pr_reg.ds	= regs["ds"]
            #prstatus.pr_reg.es	= regs["es"]
            #prstatus.pr_reg.fs	= regs["fs"]
            #prstatus.pr_reg.gs	= regs["gs"]
            #prstatus.pr_reg.orig_eax	= regs["orig_eax"]
            prstatus.pr_reg.eip	= regs["rip"]
            prstatus.pr_reg.cs	= regs["cs"]
            prstatus.pr_reg.eflags	= regs["eflags"]
            prstatus.pr_reg.esp	= regs["rsp"]
            prstatus.pr_reg.ss	= regs["ss"]


        nhdr = elf.Elf32_Nhdr()
        nhdr.n_namesz	= 5
        nhdr.n_descsz	= ctypes.sizeof(elf.elf_prstatus32())
        nhdr.n_type	= elf.NT_PRSTATUS

        note = elf_note()
        note.data	= prstatus

        note.owner	= "CORE"
        note.nhdr 	= nhdr

        return note

    def gen_siginfo(self):
        """
        Generate NT_SIGINFO note for thread tid of process pid.
        """
        siginfo = elf.siginfo_t()
        # FIXME zeroify everything for now
        ctypes.memset(ctypes.addressof(siginfo), 0, ctypes.sizeof(siginfo))

        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz	= 5
        nhdr.n_descsz	= ctypes.sizeof(elf.siginfo_t())
        nhdr.n_type	= elf.NT_SIGINFO

        note = elf_note()
        note.data	= siginfo
        note.owner	= "CORE"
        note.nhdr 	= nhdr

        return note


    def gen_thread_notes(self, thread):
        notes = []

        notes.append(self.gen_prstatus(thread))
    #	notes.append(self.gen_fpregset(pid, tid))  floating point register do not know hot to get them
    #	notes.append(self.gen_x86_xstate(pid, tid)) unknown
    #	notes.append(self.gen_siginfo())

        return notes

    def gen_thread_notes_x86(self, thread):
        notes = []

        notes.append(self.gen_prstatus_x86(thread))

        return notes

    def _gen_files(self):
        """
        Generate NT_FILE note for process pid.
        """


        class mmaped_file_info:
            start		= None
            end		= None
            file_ofs	= None
            name		= None

        infos = []
        for vma in self.vma_list:
            (fname, major, minor, ino, pgoff) = vma.info(self.task)
            if fname.startswith('/') == False:
                continue

            off	= pgoff


            info = mmaped_file_info()
            info.start	= vma.vm_start
            info.end	= vma.vm_end
            info.file_ofs	= off
            info.name	= fname

            infos.append(info)

        # /*
        #  * Format of NT_FILE note:
        #  *
        #  * long count     -- how many files are mapped
        #  * long page_size -- units for file_ofs
        #  * array of [COUNT] elements of
        #  *   long start
        #  *   long end
        #  *   long file_ofs
        #  * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
        #  */
        fields = []
        fields.append(("count",		ctypes.c_long))
        fields.append(("page_size",	ctypes.c_long))
        for i in range(len(infos)):
            fields.append(("start"+str(i),		ctypes.c_long))
            fields.append(("end"+str(i),		ctypes.c_long))
            fields.append(("file_ofs"+str(i),	ctypes.c_long))
        for i in range(len(infos)):
            fields.append(("name"+str(i),	ctypes.c_char*(len(infos[i].name)+1)))

        class elf_files(ctypes.Structure):
            _fields_ = fields

        data = elf_files()
        data.count	= len(infos)
        data.page_size	= PAGESIZE
        for i in range(len(infos)):
            info = infos[i]
            setattr(data,	"start"+str(i),		info.start)
            setattr(data,	"end"+str(i),		info.end)
            setattr(data,	"file_ofs"+str(i),	info.file_ofs)
            setattr(data,	"name"+str(i),		info.name)


        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz	= 5#XXX strlen + 1
        nhdr.n_descsz	= ctypes.sizeof(elf_files())
        nhdr.n_type	= elf.NT_FILE

        note = elf_note()
        note.nhdr	= nhdr
        note.owner	= "CORE"
        note.data	= data

        return note

    def _gen_files_x86(self):
        """
        Generate NT_FILE note for process pid.
        """


        class mmaped_file_info:
            start		= None
            end		= None
            file_ofs	= None
            name		= None

        infos = []
        for vma in self.vma_list:
            (fname, major, minor, ino, pgoff) = vma.info(self.task)
            if fname.startswith('/') == False:
                continue

            off	= pgoff
            info = mmaped_file_info()
            info.start	= vma.vm_start
            info.end	= vma.vm_end
            info.file_ofs	= off
            info.name	= fname

            infos.append(info)

        fields = []
        fields.append(("count",		ctypes.c_uint32))
        fields.append(("page_size",	ctypes.c_uint32))
        for i in range(len(infos)):
            fields.append(("start"+str(i),		ctypes.c_uint32))
            fields.append(("end"+str(i),		ctypes.c_uint32))
            fields.append(("file_ofs"+str(i),	ctypes.c_uint32))
        for i in range(len(infos)):
            fields.append(("name"+str(i),	ctypes.c_char*(len(infos[i].name)+1)))

        class elf_files(ctypes.Structure):
            _fields_ = fields

        data = elf_files()
        data.count	= len(infos)
        data.page_size	= PAGESIZE
        for i in range(len(infos)):
            info = infos[i]
            setattr(data,	"start"+str(i),		info.start)
            setattr(data,	"end"+str(i),		info.end)
            setattr(data,	"file_ofs"+str(i),	info.file_ofs)
            setattr(data,	"name"+str(i),		info.name)


        nhdr = elf.Elf32_Nhdr()
        nhdr.n_namesz	= 5#XXX strlen + 1
        nhdr.n_descsz	= ctypes.sizeof(elf_files())
        nhdr.n_type	= elf.NT_FILE

        note = elf_note()
        note.nhdr	= nhdr
        note.owner	= "CORE"
        note.data	= data

        return note




    def gen_notes(self):
        """
        Generate notes for core dump of process pid.
        """
        notes = []
        notes.append(self.gen_prpsinfo())

        threads = self.task.threads()

        # Main thread first
        notes += self.gen_thread_notes(self.task)

        # Then other threads
        for t in threads:
            if t.pid == self.task.pid:
                continue

            notes += self.gen_thread_notes(t)

#		notes.append(self._gen_auxv(pid))  unknown
        notes.append(self._gen_files())
        return notes

    def gen_notes_x86(self):
        """
        Generate notes for core dump of process pid.
        """
        notes = []
        notes.append(self.gen_prpsinfo())

        threads = self.task.threads()

        # Main thread first
        notes += self.gen_thread_notes_x86(self.task)

        # Then other threads
        for t in threads:
            if t.pid == self.task.pid:
                continue

            notes += self.gen_thread_notes_x86(t)

        notes.append(self._gen_files_x86())
        return notes

    def gen_phdrs(self, notes, vmas):
        """
        Generate program headers for process pid.
        """
        phdrs = []

        if self.x86 is True:
            offset = ctypes.sizeof(elf.Elf32_Ehdr())
            offset += (len(vmas) + 1)*ctypes.sizeof(elf.Elf32_Phdr())
            phdr = elf.Elf32_Phdr()

        else:
            offset = ctypes.sizeof(elf.Elf64_Ehdr())
            offset += (len(vmas) + 1)*ctypes.sizeof(elf.Elf64_Phdr())
            phdr = elf.Elf64_Phdr()

        filesz = 0

        for note in notes:
            filesz += ctypes.sizeof(note.nhdr) + ctypes.sizeof(note.data) + 8



        # PT_NOTE

        ctypes.memset(ctypes.addressof(phdr), 0, ctypes.sizeof(phdr))
        phdr.p_type	= elf.PT_NOTE
        phdr.p_offset	= offset
        phdr.p_filesz	= filesz

        phdrs.append(phdr)

        note_align	= PAGESIZE - ((offset + filesz) % PAGESIZE)

        if note_align == PAGESIZE:
            note_align = 0

        offset += note_align

        # VMA phdrs

        for vma in self.vmas:
            offset += filesz
            filesz = vma.filesz

            if self.x86 is True:
                phdr = elf.Elf32_Phdr()
            else:
                phdr = elf.Elf64_Phdr()

            ctypes.memset(ctypes.addressof(phdr), 0, ctypes.sizeof(phdr))
            phdr.p_type	= elf.PT_LOAD
            phdr.p_align	= PAGESIZE
            phdr.p_paddr	= 0
            phdr.p_offset	= offset
            phdr.p_vaddr	= vma.start
            phdr.p_memsz	= vma.memsz
            phdr.p_filesz	= vma.filesz
            phdr.p_flags	= vma.flags

            phdrs.append(phdr)

        return phdrs


    def gen_ehdr(self, phdrs):
        """
        Generate elf header for process pid with program headers phdrs.
        """
        ehdr = elf.Elf64_Ehdr()

        ctypes.memset(ctypes.addressof(ehdr), 0, ctypes.sizeof(ehdr))
        ehdr.e_ident[elf.EI_MAG0]	= elf.ELFMAG0
        ehdr.e_ident[elf.EI_MAG1]	= elf.ELFMAG1
        ehdr.e_ident[elf.EI_MAG2]	= elf.ELFMAG2
        ehdr.e_ident[elf.EI_MAG3]	= elf.ELFMAG3
        ehdr.e_ident[elf.EI_CLASS]	= elf.ELFCLASS64
        ehdr.e_ident[elf.EI_DATA]	= elf.ELFDATA2LSB
        ehdr.e_ident[elf.EI_VERSION]	= elf.EV_CURRENT

        ehdr.e_type		= elf.ET_CORE
        ehdr.e_machine		= elf.EM_X86_64
        ehdr.e_version		= elf.EV_CURRENT
        ehdr.e_phoff		= ctypes.sizeof(elf.Elf64_Ehdr())
        ehdr.e_ehsize		= ctypes.sizeof(elf.Elf64_Ehdr())
        ehdr.e_phentsize	= ctypes.sizeof(elf.Elf64_Phdr())
        #FIXME Case len(phdrs) > PN_XNUM should be handled properly.
        # See fs/binfmt_elf.c from linux kernel.
        ehdr.e_phnum	= len(phdrs)

        return ehdr

    def gen_ehdr_x86(self, phdrs):
        """
        Generate elf header for process pid with program headers phdrs.
        """
        ehdr = elf.Elf32_Ehdr()

        ctypes.memset(ctypes.addressof(ehdr), 0, ctypes.sizeof(ehdr))
        ehdr.e_ident[elf.EI_MAG0]	= elf.ELFMAG0
        ehdr.e_ident[elf.EI_MAG1]	= elf.ELFMAG1
        ehdr.e_ident[elf.EI_MAG2]	= elf.ELFMAG2
        ehdr.e_ident[elf.EI_MAG3]	= elf.ELFMAG3
        ehdr.e_ident[elf.EI_CLASS]	= elf.ELFCLASS32
        ehdr.e_ident[elf.EI_DATA]	= elf.ELFDATA2LSB
        ehdr.e_ident[elf.EI_VERSION]	= elf.EV_CURRENT

        ehdr.e_type		= elf.ET_CORE
        ehdr.e_machine		= elf.EM_386
        ehdr.e_version		= elf.EV_CURRENT
        ehdr.e_phoff		= ctypes.sizeof(elf.Elf32_Ehdr())
        ehdr.e_ehsize		= ctypes.sizeof(elf.Elf32_Ehdr())
        ehdr.e_phentsize	= ctypes.sizeof(elf.Elf32_Phdr())
        ehdr.e_phnum	= len(phdrs)

        return ehdr

    def generate_coredump(self):
        """
        Generate core dump for pid.
        """

        # Generate everything backwards so it is easier to calculate offset.
        self.vmas         = self.gen_vmas()
        if not self.x86:
            self.notes        = self.gen_notes()
            self.phdrs        = self.gen_phdrs(self.notes,self.vmas)
            self.ehdr         = self.gen_ehdr(self.phdrs)
        else:
            self.notes        = self.gen_notes_x86()
            self.phdrs        = self.gen_phdrs(self.notes,self.vmas)
            self.ehdr         = self.gen_ehdr_x86(self.phdrs)

        return

    def write(self, f):
        """
        Write core dump to file f.
        """
        buf = io.BytesIO()
        buf.write(self.ehdr)

        for phdr in self.phdrs:
            buf.write(phdr)

        for note in self.notes:
            buf.write(note.nhdr)
            buf.write(note.owner)
            buf.write("\0"*(8-len(note.owner)))
            buf.write(note.data)

        if self.x86 is True:
            offset = ctypes.sizeof(elf.Elf32_Ehdr())
            offset += (len(self.vmas) + 1)*ctypes.sizeof(elf.Elf32_Phdr())
        else:
            offset = ctypes.sizeof(elf.Elf64_Ehdr())
            offset += (len(self.vmas) + 1)*ctypes.sizeof(elf.Elf64_Phdr())


        filesz = 0

        for note in self.notes:
            filesz += ctypes.sizeof(note.nhdr) + ctypes.sizeof(note.data) + 8

        note_align	= PAGESIZE - ((offset + filesz) % PAGESIZE)

        if note_align == PAGESIZE:
            note_align = 0

        if note_align != 0:
            scratch = (ctypes.c_char * note_align)()
            ctypes.memset(ctypes.addressof(scratch), 0, ctypes.sizeof(scratch))
            buf.write(scratch)

        for vma in self.vmas:
            buf.write(vma.data)

        buf.seek(0)
        f.write(buf.read())
