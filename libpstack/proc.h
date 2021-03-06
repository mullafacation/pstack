#include <elf.h>
extern "C" {
#include <thread_db.h>
}
#include <libpstack/ps_callback.h>
#include <libpstack/dwarf.h>
#include <map>
#include <set>
#include <sstream>
#include <functional>
#include <bitset>

struct ps_prochandle {};

class Process;
struct StackFrame;

class DwarfExpressionStack : public std::stack<Elf_Addr> {
public:
    bool isReg;
    int inReg;
    Elf_Addr poptop() { Elf_Addr tos = top(); pop(); return tos; }
    DwarfExpressionStack(): isReg(false) {}
    Elf_Addr eval(const Process &, DWARFReader &r, const StackFrame *frame, Elf_Addr);
    Elf_Addr eval(const Process &, const DwarfAttribute *, const StackFrame *, Elf_Addr);
};

// this works for i386 and x86_64 - might need to change for other archs.
typedef unsigned long cpureg_t;

struct StackFrame {
    Elf_Addr ip;
    Elf_Addr cfa;
    std::map<unsigned, cpureg_t> regs;
    std::shared_ptr<ElfObject> elf;
    Elf_Addr elfReloc;
    std::shared_ptr<DwarfInfo> dwarf;
    const DwarfEntry * function;
    DwarfFrameInfo *frameInfo;
    const DwarfFDE *fde;
    StackFrame()
        : ip(-1)
        , cfa(0)
        , dwarf(0)
        , function(0)
        , frameInfo(0)
        , fde(0)
    {}
    void setReg(unsigned regno, cpureg_t value);
    cpureg_t getReg(unsigned regno) const;
    Elf_Addr getCFA(const Process &proc, const DwarfCallFrame &cfi) const;
    StackFrame *unwind(Process &p);
    void setCoreRegs(const CoreRegisters &core);
    void getCoreRegs(CoreRegisters &core) const;
    void getFrameBase(const Process &p, intmax_t offset, DwarfExpressionStack *stack) const;
};

struct ThreadStack {
    td_thrinfo_t info;
    std::vector<StackFrame *> stack;
    ThreadStack() {
        memset(&info, 0, sizeof info);
    }
    ~ThreadStack() {
        for (auto i = stack.begin(); i != stack.end(); ++i)
            delete *i;
    }
    void unwind(Process &, CoreRegisters &regs);
};


class PstackOptions {
public:
    enum PstackOption {
        nosrc,
        doargs,
        maxopt
    };
    void operator += (PstackOption);
    void operator -= (PstackOption);
    bool operator() (PstackOption) const;
    std::bitset<maxopt> values;
};

typedef std::vector<std::pair<std::string, std::string>> PathReplacementList;
class Process : public ps_prochandle {
    Elf_Addr findRDebugAddr();
    Elf_Off entry; // entrypoint of process.
    Elf_Addr interpBase;
    Elf_Addr vdsoBase;
    void loadSharedObjects(Elf_Addr);
    bool isStatic;
    Elf_Addr sysent; // for AT_SYSINFO

protected:
    td_thragent_t *agent;
    std::shared_ptr<ElfObject> execImage;
    std::string abiPrefix;
    PathReplacementList pathReplacements;

public:
    DwarfImageCache &imageCache;

    struct LoadedObject {
        Elf_Off reloc;
        std::shared_ptr<ElfObject> object;
        LoadedObject(Elf_Off reloc_, std::shared_ptr<ElfObject> object_) : reloc(reloc_), object(object_) {}
    };
    std::vector<LoadedObject> objects;
    void processAUXV(const Reader &);
    std::shared_ptr<Reader> io;

    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) = 0;
    void addElfObject(std::shared_ptr<ElfObject> obj, Elf_Addr load);
    std::shared_ptr<ElfObject> findObject(Elf_Addr addr, Elf_Off *reloc) const;
    std::shared_ptr<DwarfInfo> getDwarf(std::shared_ptr<ElfObject>, bool debug = true);
    Process(std::shared_ptr<ElfObject> obj, std::shared_ptr<Reader> mem, const PathReplacementList &prl, DwarfImageCache &cache);
    virtual void stop(pid_t lwpid) = 0;
    virtual void stopProcess() = 0;

    virtual void resumeProcess() = 0;
    virtual void resume(pid_t lwpid) = 0;
    virtual pid_t getPID() const = 0;
    std::ostream &dumpStackText(std::ostream &, const ThreadStack &, const PstackOptions &);
    std::ostream &dumpStackJSON(std::ostream &, const ThreadStack &);
    template <typename T> void listThreads(const T &);
    Elf_Addr findNamedSymbol(const char *objName, const char *symbolName) const;
    ~Process();
    virtual void load();
};

template <typename T> int
threadListCb(const td_thrhandle_t *thr, void *v)
{ T &callback = *(T *)v; callback(thr); return 0; }

template <typename T> void
Process::listThreads(const T &callback)
{
    td_ta_thr_iter(agent,
            threadListCb<T>,
            (void *)&callback, TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
}

struct ThreadInfo {
    int stopCount;
    ThreadInfo() : stopCount(0) {}
};

class LiveReader : public FileReader {
public:
    off_t size() const override { return std::numeric_limits<off_t>::max(); }
    LiveReader(pid_t pid_, const std::string &base_);
};
std::string procname(pid_t pid, const std::string &file);

struct LiveThreadList;
class LiveProcess : public Process {
    pid_t pid;
    std::map<pid_t, ThreadInfo> stoppedLwps;
    friend class LiveReader;
    int stopCount;
    timeval start;
    std::set<pid_t> lwps; // lwps we could not suspend.
    friend class StopLWP;
public:
    LiveProcess(std::shared_ptr<ElfObject> ex, pid_t pid, const PathReplacementList &repls, DwarfImageCache &cache);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg);
    virtual void stop(pid_t lwpid);
    virtual void resume(pid_t lwpid);
    virtual pid_t getPID()  const{ return pid; }
    void stopProcess();
    void resumeProcess();
    virtual void load();
};

class CoreProcess;
class CoreReader : public Reader {
    CoreProcess *p;
protected:
    virtual size_t read(off_t offset, size_t count, char *ptr) const override;
public:
    CoreReader (CoreProcess *p);
    virtual void describe(std::ostream &os) const override;
    off_t size() const override { return std::numeric_limits<off_t>::max(); }
};

class CoreProcess : public Process {
    std::shared_ptr<ElfObject> coreImage;
    friend class CoreReader;
public:
    CoreProcess(std::shared_ptr<ElfObject> exec, std::shared_ptr<ElfObject> core, const PathReplacementList &, DwarfImageCache &);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg);
    virtual void stop(lwpid_t);
    virtual void resume(lwpid_t);
    virtual pid_t getPID() const;
    void stopProcess() { }
    void resumeProcess() { }
    virtual void load();
};

// RAII to stop a process.
struct StopProcess {
    Process *proc;
public:
    StopProcess(Process *proc_) : proc(proc_) { proc->stopProcess(); }
    ~StopProcess() { proc->resumeProcess(); } 
};
