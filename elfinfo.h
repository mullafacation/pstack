/*
 * Copyright (c) 2002 Peter Edwards
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Utility interface for accessing ELF images.
 */
extern bool noDebugLibs;

#ifndef elfinfo_h_guard
#define elfinfo_h_guard

#include <tuple>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <elf.h>
#include <memory>
extern "C" {
#include <thread_db.h>
}
#include <elf.h>
#include "reader.h"


/*
 * FreeBSD defines all elf types with a common header, defining the
 * 64 and 32 bit versions through a common body, giving us platform
 * independent names for each one. We work backwards on Linux to
 * provide the same handy naming.
 */

#define ELF_WORDSIZE ((ELF_BITS)/8)

#ifndef __FreeBSD__

#define ElfTypeForBits(type, bits, uscore) typedef Elf##bits##uscore##type Elf##uscore##type ;
#define ElfType2(type, bits) ElfTypeForBits(type, bits, _)
#define ElfType(type) ElfType2(type, ELF_BITS)

typedef Elf32_Nhdr Elf32_Note;
typedef Elf64_Nhdr Elf64_Note;

template<size_t size>
class Elf {
};

template<> class Elf<32> {
    typedef Elf32_Addr Addr;
    typedef Elf32_Ehdr Ehdr;
    typedef Elf32_Phdr Phdr;
    typedef Elf32_Shdr Shdr;
    typedef Elf32_Sym Sym;
    typedef Elf32_Dyn Dyn;
    typedef Elf32_Word Word;
    typedef Elf32_Note Note;
    typedef Elf32_auxv_t auxv_t;
    typedef Elf32_Off Off;
};

template<> class Elf<64> {
    typedef Elf64_Addr Addr;
    typedef Elf64_Ehdr Ehdr;
    typedef Elf64_Phdr Phdr;
    typedef Elf64_Shdr Shdr;
    typedef Elf64_Sym Sym;
    typedef Elf64_Dyn Dyn;
    typedef Elf64_Word Word;
    typedef Elf64_Note Note;
    typedef Elf64_auxv_t auxv_t;
    typedef Elf64_Off Off;
};

template <typename ElfType> class ElfObject;

static inline size_t
roundup2(size_t val, size_t align)
{
    return val + (align - (val % align)) % align;
}

#endif

template <typename Elf> class ElfSymHash;
template <typename Elf> struct SymbolSection;

enum NoteIter {
    NOTE_CONTIN,
    NOTE_ERROR,
    NOTE_DONE
};

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template <typename Elf> struct ElfSection {
    const ElfObject<Elf> &obj;
    const typename Elf::Shdr *shdr;
    const typename Elf::Shdr *getLink() const;
    operator bool() const { return shdr != 0; }
    const typename Elf::Shdr *operator -> () const { return shdr; }
    const typename Elf::Shdr *operator = (const typename Elf::Shdr *shdr_) { shdr = shdr_; return shdr; }
    ElfSection(const ElfObject<Elf> &obj_, const typename Elf::Shdr *shdr_) : obj(obj_), shdr(shdr_) {}
};

template <typename Elf>
bool linearSymSearch(ElfSection<Elf> &hdr, const std::string &name, typename Elf::Sym &);

template <typename Elf> class ElfObject {
public:
    typedef std::vector<typename Elf::Phdr> ProgramHeaders;
    typedef std::vector<typename Elf::Shdr> SectionHeaders;
private:
    friend class ElfSection<Elf>;
    size_t fileSize;
    typename Elf::Ehdr elfHeader;
    ProgramHeaders programHeaders;
    void init(FILE *);
    std::unique_ptr<ElfSymHash<Elf>> hash;
    void init(const std::shared_ptr<Reader> &); // want constructor chaining
    std::map<std::string, typename Elf::Shdr *> namedSection;
    std::string name;
    bool debugLoaded;
    std::shared_ptr<ElfObject<Elf>> debugObject;
    std::shared_ptr<ElfObject<Elf>> getDebug();
public:
    const ElfSection<Elf> getSection(const std::string &name, int type);
    SymbolSection<Elf> getSymbols(const std::string &table);
    SectionHeaders sectionHeaders;
    std::shared_ptr<Reader> io; // IO for the ELF image.
    typename Elf::Off getBase() const; // lowest address of a PT_LOAD segment.
    std::string getInterpreter() const;
    std::string getName() const { return name; }
    const SectionHeaders &getSections() const { return sectionHeaders; }
    const ProgramHeaders &getSegments() const  { return programHeaders; }
    const ElfSection<Elf> getSection(const std::string &name, int type) const;
    const typename Elf::Ehdr &getElfHeader() const { return elfHeader; }
    bool findSymbolByAddress(typename Elf::Addr addr, int type, typename Elf::Sym &, std::string &);
    bool findSymbolByName(const std::string &name, typename Elf::Sym &sym);
    ElfObject(std::shared_ptr<Reader>);
    ElfObject(const std::string &name);
    ~ElfObject();
    template <typename Callable> void getNotes(Callable &callback) const;
    const typename Elf::Phdr *findHeaderForAddress(typename Elf::Off) const;
};

// Helpful for iterating over symbol sections.
template <typename Elf>
struct SymbolIterator {
    std::shared_ptr<Reader> io;
    off_t off;
    off_t stroff;
    SymbolIterator(std::shared_ptr<Reader> io_, off_t off_, off_t stroff_) : io(io_), off(off_), stroff(stroff_) {}
    bool operator != (const SymbolIterator &rhs) { return rhs.off != off; }
    SymbolIterator &operator++ () { off += sizeof (typename Elf::Sym); return *this; }
    std::pair<const typename Elf::Sym, const std::string> operator *();
};

template <typename Elf>
struct SymbolSection {
    const ElfSection<Elf> section;
    off_t stroff;
    SymbolIterator<Elf> begin() { return SymbolIterator<Elf>(section && section.shdr ? section.obj.io : std::shared_ptr<Reader>((Reader *)0), section ? section->sh_offset : 0, stroff); }
    SymbolIterator<Elf> end() { return SymbolIterator<Elf>(section && section.shdr ? section.obj.io : std::shared_ptr<Reader>((Reader *)0), section ? section->sh_offset + section->sh_size : 0, stroff); }
    SymbolSection(const ElfSection<Elf> &section_)
        : section(section_)
        , stroff(section.shdr ? section_.getLink()->sh_offset : -1)
    {}
};

template <typename Elf>
class ElfSymHash {
    ElfSection<Elf> hash;
    ElfSection<Elf> syms;
    off_t strings;
    typename Elf::Word nbucket;
    typename Elf::Word nchain;
    std::vector<typename Elf::Word> data;
    const typename Elf::Word *chains;
    const typename Elf::Word *buckets;
public:
    ElfSymHash(ElfSection<Elf> &);
    bool findSymbol(typename Elf::Sym &sym, const std::string &name);
};

const char *pad(size_t size);
#ifdef __PPC
typedef struct pt_regs CoreRegisters;
#else
typedef struct user_regs_struct CoreRegisters;
#endif

template <typename Elf>
std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject<Elf> *, const typename Elf::Sym &, const typename Elf::Sym &> &t);
template <typename Elf>
std::ostream& operator<< (std::ostream &os, const std::pair<const ElfObject<Elf> *, const typename Elf::Sym &> &p);
template <typename Elf>
std::ostream& operator<< (std::ostream &os, const typename Elf::Sym &h);
template <typename Elf>
std::ostream& operator<< (std::ostream &os, std::tuple<const ElfObject<Elf> *, const typename Elf::Sym &, const typename Elf::Sym &> &t);
template <typename Elf>
std::ostream& operator<< (std::ostream &os, const typename Elf::Sym &d);
template <typename Elf>
std::ostream& operator<< (std::ostream &os, const ElfObject<Elf> &obj);

template <typename Elf> template <typename Callable> void
ElfObject<Elf>::getNotes(Callable &callback) const
{
    for (auto hdri = programHeaders.begin(); hdri != programHeaders.end(); ++hdri) {
        auto &hdr = *hdri;
        if (hdr.p_type == PT_NOTE) {
            typename Elf::Note note;
            off_t off = hdr.p_offset;
            off_t e = off + hdr.p_filesz;
            while (off < e) {
                io->readObj(off, &note);
                off += sizeof note;
                char *name = new char[note.n_namesz + 1];
                io->readObj(off, name, note.n_namesz);
                name[note.n_namesz] = 0;
                off += note.n_namesz;
                off = roundup2(off, 4);
                char *data = new char[note.n_descsz];
                io->readObj(off, data, note.n_descsz);
                off += note.n_descsz;
                off = roundup2(off, 4);
                NoteIter iter = callback(name, note.n_type, data, note.n_descsz);
                delete[] data;
                delete[] name;
                switch (iter) {
                case NOTE_DONE:
                case NOTE_ERROR:
                    return;
                case NOTE_CONTIN:
                    break;
                }
            }
        }
    }
}


#endif /* Guard. */
