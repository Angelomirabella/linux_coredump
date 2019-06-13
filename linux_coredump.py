import os
import volatility.plugins.linux.common as common
import volatility.debug as debug
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.dump_map as dump_map
import volatility.plugins.linux.info_regs as info_regs
import volatility.conf as conf
import coredump



class linux_coredump(linux_pslist.linux_pslist):
    """Creates a core dump for a given process """
    cd=None

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)

        self._config.add_option('PID', short_option='P', default=None, help='PID of the process', action='store')
        self._config.add_option('DUMP-DIR', short_option='D', default=None, help='Output directory', action='store',type='str')
        self._config.add_option('OUTPUT-FILE', short_option='O', default=None, help='Output file', action='store',type='str')


    def build_conf(self):
        # Create conf obj
        plugin_conf = conf.ConfObject()
        # Define conf
        plugin_conf.readonly = {}
        plugin_conf.PROFILE = self._config.PROFILE
        plugin_conf.DUMP_DIR = self._config.DUMP_DIR
        plugin_conf.PID = self._config.PID
        return plugin_conf



    def calculate(self):

        if (not self._config.PID):
            debug.error("Please specify a process pid (--pid)")
        if (not self._config.DUMP_DIR or not os.path.isdir(self._config.DUMP_DIR)):
            debug.error("Please specify an existing output dir (--dump-dir)")
        if (not self._config.OUTPUT_FILE):
            debug.error("Please specify an output file (--output-file)")

        common.set_plugin_members(self)
        x86 = False

        if self.profile.metadata['arch'] not in ["x64" , "x86"]:
            debug.error("This plugin is only supported on Intel-based memory captures")



        plugin_conf = self.build_conf()
        plugin = dump_map.linux_dump_map(plugin_conf)
        data = plugin.calculate()
        tsk = None
        vma_list = []
        empty = True

        for (task, vma) in data:
            empty = False
            tsk = task
            vma_list.append(vma)
            (fname, major, minor, ino, pgoff) = vma.info(task)
            if fname == '[stack]':
                if self.addr_space.profile.metadata['arch'] == "x86" or vma.vm_end < 2**32:
                    x86=True
        if empty is True:
            debug.error("The reqeusted pid does not exist!")

        threads_registers = {}
        plugin = info_regs.linux_info_regs(plugin_conf)
        data = plugin.calculate()
        t_pids = [None] * len(tsk.threads())

        i = 0
        for t in tsk.threads():
            t_pids[i] = t.pid
            i += 1

        i = 0
        for task,name,thread_regs in data:
            for thread_name, regs in thread_regs:
                threads_registers[str(t_pids[i])] = regs
                i += 1

        self.cd=coredump.coredump(tsk,vma_list,threads_registers,x86)
        self.cd.generate_coredump()



        del plugin
        return

    def render_text(self, outfd, data):
        file_path = os.path.join(self._config.DUMP_DIR, self._config.OUTPUT_FILE)
        outfile=open(file_path,'wb')
        if self.cd:
            self.cd.write(outfile)
        else:
            debug.error('An error occurred while creatng the core dump!')
        os.unlink(outfd.name)
