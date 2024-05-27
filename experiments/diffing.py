import argparse, subprocess, os, sqlite3, time, pickle, re, multiprocessing, sys, struct, logging
from prettytable import PrettyTable
import pefile
from macholib.MachO import MachO
from macholib.mach_o import *
from elftools.elf.elffile import ELFFile
import idb

logging.basicConfig(level=logging.ERROR) # to suppress python-idb warning

# paths (should be edited)
g_out_dir = r'C:\Users\Owner\Desktop\bindiff_out'
g_ida_dir = r'C:\Users\Owner\Desktop\IDA Pro 7.7'

g_differ_path = r"C:\Program Files\BinDiff\bin\bindiff.exe"

g_exp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bindiff_export.idc')
g_save_fname_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'save_func_names_7x.py')

# parameters
g_ws_th = 0.20 # whole binary similarity threshold
g_fs_th = 0.70 # function similarity threshold
g_ins_th = 10 # instruction threshold
g_bb_th = 0 # basic block threshold
g_size_th = 10 # file size threshold (MB)
#g_func_regex = r'sub_|fn_|chg_' # function name filter rule
g_func_regex = r'.*' # function name filter rule

class LocalError(Exception): pass
class ProcExportError(LocalError): pass
class ProcDiffError(LocalError): pass
class LoadFuncNamesError(LocalError): pass
class FileNotFoundError(LocalError): pass
class ChildProcessError(LocalError): pass

class BinDiff(object):
    
    def __init__ (self, primary, out_dir, debug=False, clear=False, newidb=False):
    #def __init__ (self, primary, out_dir, ws_th, fs_th, ins_th, bb_th, size_th, debug=False, clear=False, noidb=False, use_pyidb=False):        
        self._debug = debug
        self._clear = clear
        self._newidb = newidb
        self._lock = multiprocessing.Lock()        
        self._primary = primary
        self._out_dir = out_dir

        self._format, self._arch = self._get_machine_type(primary)
        if self._format is None:
            raise ProcExportError('primary binary should be PE/Mach-O/ELF'.format(primary))
        self._dprint('primary binary format: {}'.format(self._format))
        self._dprint('primary binary architecture: {}'.format(self._arch))
        
        self._ida_path = self._get_ida_path(self._arch)
        res = self._files_not_found()
        if res is not None:
            raise FileNotFoundError('file is not found: {}'.format(res))
        self._dprint('IDA binary path for primary: {}'.format(self._ida_path))
        
        if self._make_BinExport(self._primary, self._ida_path) != 0:
            raise ProcExportError('primary BinExport failed: {}'.format(primary))

        self._diff_cnt = 0

    def _dprint(self, msg):
        if self._debug:
            self._lock.acquire()            
            print('[+] [{}]: {}'.format(os.getpid(), msg))
            self._lock.release()

    def _get_machine_type(self, path):
        try:
            pe = pefile.PE(path)
            format_ = 'PE'
            if pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine].find('I386') != -1:
                arch = '32-bit'
            else:
                arch = '64-bit'
        except (pefile.PEFormatError,KeyError) as detail:
            try:
                self._dprint(detail)
                m = MachO(path)
                format_ = 'Mach-O'
                for header in m.headers:
                    if CPU_TYPE_NAMES.get(header.header.cputype,header.header.cputype) == 'x86_64':
                    #if header.MH_MAGIC == MH_MAGIC_64:
                        arch = '64-bit'
                    else:
                        arch = '32-bit'
            except:
                try:
                    elffile = ELFFile(open(path, 'rb'))
                    format_ = 'ELF'
                    e_ident = elffile.header['e_ident']
                    if e_ident['EI_CLASS'] == 'ELFCLASS64':
                        arch = '64-bit'
                    else:
                        arch = '32-bit'
                except:                    
                    return None, None
                    #format_ = 'shellcode'
                    #arch = '32-bit' # 32-bit fixed
        return format_, arch

    def _files_not_found(self):
        #for path in (self._ida_path, g_exp_path, g_save_fname_path, g_differ_path):
        for path in (self._ida_path, g_exp_path, g_differ_path):
            if not os.path.isfile(path):
                return path
        return None

    def _get_db_path_noext(self, target):
        return os.path.join(self._out_dir, os.path.splitext(os.path.basename(target))[0])
        #return os.path.join(self._out_dir, os.path.basename(target))

    def _get_idb_path(self, target, arch):
        db_ext = '.idb' if arch == '32-bit' else '.i64'
        target_split = os.path.splitext(target)[0]
        
        if os.path.exists(target_split + db_ext):
            return target_split + db_ext
        else:
            return target + db_ext # for recent IDA versions

    def _get_ida_path(self, arch):
        #idaq = 'idaq.exe' if arch == '32-bit' else 'idaq64.exe'
        idaq = 'ida.exe' if arch == '32-bit' else 'ida64.exe'
        return os.path.join(g_ida_dir, idaq)        

    def _make_BinExport(self, target, ida_path):
        binexp_path = self._get_db_path_noext(target) + '.BinExport'
        #binexp_path = os.path.splitext(target)[0] + '.BinExport'
        if not self._clear and os.path.exists(binexp_path):
            self._dprint('already existed BinExport: {}'.format(binexp_path))
            return 0

        cmd = [ida_path, '-A', '-S{}'.format(g_exp_path), '-OBinExportModule:{}'.format(binexp_path), target]

        self._dprint('getting BinExport for {}'.format(target))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return proc.returncode

    def _get_BinDiff_path(self, secondary):
        primary_noext = self._get_db_path_noext(self._primary)
        secondary_noext = os.path.splitext(secondary)[0]
        return primary_noext + '_vs_' + os.path.basename(secondary_noext) + '.BinDiff'

    def _make_BinDiff(self, secondary):
        pri_binexp = self._get_db_path_noext(self._primary) + '.BinExport'
        sec_binexp = self._get_db_path_noext(secondary) + '.BinExport'

        bindiff_path = self._get_BinDiff_path(secondary)
        if not self._clear and os.path.exists(bindiff_path):
            self._dprint('already existed BinDiff: {}'.format(bindiff_path))
            return 0, None            
        
        cmd = [g_differ_path, '--primary={}'.format(pri_binexp), '--secondary={}'.format(sec_binexp), '--output_dir={}'.format(self._out_dir)]
        #print cmd
        
        self._dprint('diffing the binaries..')
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        self._dprint('differ output:')
        self._dprint(stdout)
        self._dprint(stderr)
        return proc.returncode, cmd

    def is_skipped(self, secondary, count=0):
        if count >5:
            print(f"Skip Count: {count}")
            return True
        # file check (in case of the same dir)
        #if os.path.splitext(self._primary)[0] == os.path.splitext(secondary)[0]:
        if self._primary == secondary:
            return True
        
        # target at executables
        if os.path.splitext(secondary)[1] in ('.BinExport', '.BinDiff', '.idb', '.i64'):
            return True
        
        # format/arch check
        format_, arch = self._get_machine_type(secondary)
        if format_ is None:
            return True
        #elif format_ != self._format or arch != self._arch:
        elif format_ != self._format: # only check the format 
            self._dprint('different executable format (skipped): {}'.format(secondary))
            return True

        # skip if idb not found
        idb_path = self._get_idb_path(secondary, arch)
        if not self._newidb and not os.path.exists(idb_path):
            self._dprint('no existing idb (skipped): {}'.format(secondary))
            if self._make_BinExport(secondary, self._ida_path) != 0:
                return self.is_skipped(secondary,count +1)
            
        
        return False

    def check_similarity(self, secondary, q=None):
        format_, arch = self._get_machine_type(secondary)
        ida_path = self._get_ida_path(arch)
        self._dprint('IDA binary path for secondary: {}'.format(ida_path))        
        if self._make_BinExport(secondary, ida_path) != 0:
            if q is not None:
                q.put((None, None))            
            raise ProcExportError('secondary BinExport failed: {}'.format(secondary))

        retcode, cmd = self._make_BinDiff(secondary)
        if retcode != 0:
            if q is not None:
                q.put((None, None))            
            raise ProcDiffError('BinDiff failed: {}'.format(cmd))

        conn = sqlite3.connect(self._get_BinDiff_path(secondary))
        c = conn.cursor()
        try:
            c.execute("SELECT similarity,confidence FROM metadata")
        except sqlite3.OperationalError as detail:
            print('[!] .BinDiff database ({}) is something wrong: {}'.format(self._get_BinDiff_path(secondary), detail))
            return
            
        ws, wc = c.fetchone()
        self._dprint('whole binary similarity={} confidence={}'.format(ws, wc))
        c.execute("SELECT name1,address1,name2,address2,similarity,confidence FROM function where name1 like 'websgetvar'")# WHERE similarity > ? and instructions > ? and basicblocks > ?", (self._fs_th, self._ins_th, self._bb_th))
        frows = c.fetchall()
        self._dprint('{} similar functions detected'.format(len(frows)))
        conn.close()
        
        for row in frows:
            name1, addr1, name2, addr2, fs, fc = row
            self._dprint('name1={}, addr1={:#x}, name2={},addr2={:#x}, similarity={}, confidence={}'.format(name1, addr1, name2, addr2, fs, fc))
            print('[+] path {}, name1={}, addr1={:#x}, name2={},addr2={:#x}, similarity={}, confidence={}\n'.format(secondary, name1, addr1, name2, addr2, fs, fc))

        c_high_ws = {}
        c_high_fs = {}

        if q is None:
            self._high_ws = c_high_ws
            self._high_fs = c_high_fs
        else:
            q.put((c_high_ws, c_high_fs))

    def check_similarities(self, secondary_dir):
   
        seconds = [os.path.join(secondary_dir, entry) for entry in os.listdir(secondary_dir) if os.path.isfile(os.path.join(secondary_dir, entry))]

        procs = []            
        for secondary in seconds:
            print(f"Execute Secondary: {secondary}")
            if self.is_skipped(secondary):
                
                continue

            q = multiprocessing.Queue()
            p = multiprocessing.Process(target=self.check_similarity, args=(secondary, q))
            p.start()
            procs.append((p,q))
        self._diff_cnt = len(procs)
        for p,q in procs:
            p.join()

    def increment_count(self):
        self._diff_cnt += 1
    
    def get_result(self):
        return self._high_ws, self._high_fs, self._diff_cnt

    
def main():    
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('primary', help="primary binary to compare")
    parser.add_argument('--out_dir', '-o', default=g_out_dir, help="output directory including .BinExport/.BinDiff")
    parser.add_argument('--debug', '-d', action='store_true', help="print debug output")
    parser.add_argument('--clear', '-c', action='store_true', help="clear .BinExport, .BinDiff and function name cache")

    args = parser.parse_args()

    high_ws = high_fs = None
    if os.path.isfile(args.primary):
        start = time.time()
        try:
            bd = BinDiff(args.primary, args.out_dir, args.debug, args.clear)
            bd.check_similarities("C:\\Users\\Owner\\Desktop\\my_input2")           
        except LocalError as e:
            print('[!] {} ({})'.format(str(e), type(e)))
            return 
        elapsed = time.time() - start

        print('---------------------------------------------')
        print('[*] BinDiff result')
        print('[*] elapsed time = {} sec, number of diffing = {}'.format(elapsed, 1337))
        print('[*] primary binary: (({}))'.format(os.path.basename(args.primary)))
        if high_ws:
            print('\n============== {} high similar binaries (>{}) ================'.format(len(high_ws), args.ws_th))
            table = PrettyTable(['similarity', 'secondary binary'])
            for path,res in sorted(list(high_ws.items()), key=lambda x:x[1]['similarity'], reverse=True):
                table.add_row([res['similarity'], '(({}))'.format(os.path.basename(path))])
            print(table)
        if high_fs:
            print('\n============== {} high similar functions (>{}), except high similar binaries ================'.format(len(high_fs), args.fs_th))
            table = PrettyTable(['similarity', 'primary addr', 'primary name', 'secondary addr', 'secondary name', 'secondary binary'])
            for key,res in sorted(list(high_fs.items()), key=lambda x:(x[1]['similarity'], x[0][0]), reverse=True):
                addr1, func_name1, addr2, func_name2, path = key
                table.add_row([res['similarity'], '{:#x}'.format(addr1), func_name1[:0x20], '{:#x}'.format(addr2), func_name2[:0x20], '{}'.format(os.path.basename(path))])
            print(table)
        if (not high_ws) and (not high_fs):
            print('\nno similar binaries/functions found')
        print('---------------------------------------------')
        
if ( __name__ == "__main__" ):
    main()
