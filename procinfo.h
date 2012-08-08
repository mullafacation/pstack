#include "elfinfo.h"
#include <sstream>
#include <functional>

struct ps_prochandle {};

class Process;

struct StackFrame {
    Elf_Addr ip;
    Elf_Addr bp;
    std::vector<Elf_Word> args;
    const char *unwindBy;
    StackFrame(Elf_Addr ip_, Elf_Addr bp_) : ip(ip_), bp(bp_), unwindBy(0) {}
};

struct ThreadStack {
    const td_thrhandle_t *handle;
    std::list<StackFrame *> stack;
    ThreadStack(const td_thrhandle_t *handle_) : handle(handle_) {}
    void unwind(Process &);
};

class Process : public Reader, public ps_prochandle {
    Elf_Addr findRDebugAddr();
    void loadSharedObjects();
    char *vdso;
protected:
    td_thragent_t *agent;
    std::list<ElfObject *> objectList;
    ElfObject *execImage;
    std::string abiPrefix;
    std::list<Reader *> readers; // readers allocated for objects.
    void addVDSOfromAuxV(const void *data, size_t len);
public:
    virtual void load(); // loads shared objects, gets stack traces.
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const = 0;
    void addElfObject(struct ElfObject *obj, Elf_Addr load);
    ElfObject *findObject(Elf_Addr addr) const;
    Process(Reader &ex);
    virtual void stop(pid_t lwpid) const = 0;
    virtual void resume(pid_t lwpid) const = 0;
    virtual pid_t getPID() const = 0;
    void dumpStack(FILE *file, int indent, const ThreadStack &, bool verbose);
    template <typename T> void listThreads(const T &);
    Elf_Addr findNamedSymbol(const char *objectName, const char *symbolName) const;
    ~Process();
};

template <typename T> void
Process::listThreads(const T &callback)
{
    td_ta_thr_iter(agent,
            [] (const td_thrhandle_t *thr, void *v) -> int { T &callback = *(T *)v; callback(thr); return 0; },
            (void *)&callback, TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
}

struct LiveProcess : public Process {
    pid_t pid;
    FILE *procMem;
protected:
    virtual void read(off_t offset, size_t count, char *ptr) const;
public:
    LiveProcess(Reader &ex, pid_t pid);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void stop(pid_t lwpid) const;
    virtual void resume(pid_t lwpid) const;
    virtual void load();
    virtual pid_t getPID()  const{ return pid; }

    virtual std::string describe() const {
        std::ostringstream os;
        os << "process pid " << pid;
        return os.str();
    }
};

struct CoreProcess : public Process {
    pid_t pid;
    ElfObject coreImage;
    virtual void read(off_t offset, size_t count, char *ptr) const;
public:
    CoreProcess(Reader &ex, Reader &core);
    virtual bool getRegs(lwpid_t pid, CoreRegisters *reg) const;
    virtual void load();
    virtual void stop(lwpid_t) const;
    virtual void resume(lwpid_t) const;
    virtual pid_t getPID() const;
    virtual std::string describe() const {
        std::ostringstream os;
        os << "process loaded from core " << coreImage.io;
        return os.str();
    }
};