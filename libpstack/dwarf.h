#ifndef DWARF_H
#define DWARF_H

#include <libpstack/elf.h>
#include <map>
#include <list>
#include <vector>
#include <string>

#define DWARF_MAXREG 128

enum DwarfHasChildren { DW_CHILDREN_yes = 1, DW_CHILDREN_no = 0 };
struct DwarfCIE;
class DwarfInfo;
class DWARFReader;
struct DwarfLineInfo;
struct DwarfUnit;
struct DwarfFrameInfo;
struct DwarfEntry;
typedef std::map<off_t, std::shared_ptr<DwarfEntry>> DwarfEntries;

typedef struct {
    uintmax_t reg[DWARF_MAXREG];
} DwarfRegisters;

#define DWARF_TAG(a,b) a = b,
enum DwarfTag {
#include <libpstack/dwarf/tags.h>
    DW_TAG_none = 0x0
};
#undef DWARF_TAG

#define DWARF_FORM(a,b) a = b,
enum DwarfForm {
#include <libpstack/dwarf/forms.h>
    DW_FORM_none = 0x0
};
#undef DWARF_FORM

#define DWARF_ATTR(a,b) a = b,
enum DwarfAttrName {
#include <libpstack/dwarf/attr.h>
    DW_AT_none = 0x0
};
#undef DWARF_ATTR

#define DWARF_LINE_S(a,b) a = b,
enum DwarfLineSOpcode {
#include <libpstack/dwarf/line_s.h>
    DW_LNS_none = -1
};
#undef DWARF_LINE_S

#define DWARF_LINE_E(a,b) a = b,
enum DwarfLineEOpcode {
#include <libpstack/dwarf/line_e.h>
    DW_LNE_none = -1
};
#undef DWARF_LINE_E

struct DwarfAttributeSpec {
    enum DwarfAttrName name;
    enum DwarfForm form;
    DwarfAttributeSpec(DwarfAttrName name_, DwarfForm form_) : name(name_), form(form_) { }
};

struct DwarfAbbreviation {
    intmax_t code;
    DwarfTag tag;
    enum DwarfHasChildren hasChildren;
    std::list<DwarfAttributeSpec> specs;
    DwarfAbbreviation(DWARFReader &, intmax_t code);
    DwarfAbbreviation() {}
};

struct DwarfPubname {
    uint32_t offset;
    std::string name;
    DwarfPubname(DWARFReader &r, uint32_t offset);
};

struct DwarfARange {
    uintmax_t start;
    uintmax_t length;
    DwarfARange(uintmax_t start_, uintmax_t length_) : start(start_), length(length_) {}
};

struct DwarfARangeSet {
    uint32_t length;
    uint16_t version;
    uint32_t debugInfoOffset;
    uint8_t addrlen;
    uint8_t segdesclen;
    std::vector<DwarfARange> ranges;
    DwarfARangeSet(DWARFReader &r);
};

struct DwarfPubnameUnit {
    uint16_t length;
    uint16_t version;
    uint32_t infoOffset;
    uint32_t infoLength;
    std::list<DwarfPubname> pubnames;
    DwarfPubnameUnit(DWARFReader &r);
};

struct DwarfBlock {
    off_t offset;
    off_t length;
};

union DwarfValue {
    uintmax_t addr;
    uintmax_t udata;
    intmax_t sdata;
    uintmax_t ref;
    const char *string;
    DwarfBlock block;
    char flag;
};

struct DwarfAttribute {
    const DwarfAttributeSpec *spec; /* From abbrev table attached to type */
    const DwarfEntry *entry;
    DwarfValue value;
    DwarfAttribute(DWARFReader &, const DwarfEntry *, const DwarfAttributeSpec *spec);
    ~DwarfAttribute() {
        if (spec && spec->form == DW_FORM_string)
            free((void *)(const void *)value.string);
    }
    DwarfAttribute() : spec(0), entry(0) {}
    DwarfAttribute(const DwarfAttribute &rhs) : spec(rhs.spec), entry(rhs.entry) {
        if (spec && spec->form == DW_FORM_string)
            value.string = strdup(rhs.value.string);
        else
            value.udata = rhs.value.udata;
    }
    DwarfAttribute &operator = (const DwarfAttribute &rhs) {
        entry = rhs.entry;
        if (spec && spec->form == DW_FORM_string)
            value.string = strdup(rhs.value.string);
        spec = rhs.spec;
        if (spec && spec->form == DW_FORM_string)
            value.string = strdup(rhs.value.string);
        else
            value.udata = rhs.value.udata;
        return *this;
    }
    const DwarfEntry *getRef() const;
};

struct DwarfEntry {
    DwarfEntries children;
    const DwarfUnit *unit;
    const DwarfAbbreviation *type;
    intmax_t offset;
    std::map<DwarfAttrName, DwarfAttribute> attributes;

    DwarfEntry();

    bool attrForName(DwarfAttrName name, const DwarfAttribute **ent) const {
        auto attr = attributes.find(name);
        if (attr != attributes.end()) {
            if (ent)
               *ent = &attr->second;
            return true;
        }
        return false;
    }

    const DwarfAttribute &attrForName(DwarfAttrName name) const {
        const DwarfAttribute *ent;
        if (!attrForName(name, &ent))
           throw "no such attribute";
        return *ent;
    }

    DwarfEntry(DWARFReader &r, intmax_t, DwarfUnit *unit, intmax_t offset);
    const char *name() {
        const DwarfAttribute *ent;
        if (attrForName(DW_AT_name, &ent))
            return ent->value.string;
        return "anon";
    }
};

enum FIType {
    FI_DEBUG_FRAME,
    FI_EH_FRAME
};

struct DwarfFileEntry {
    std::string name;
    std::string directory;
    unsigned lastMod;
    unsigned length;
    DwarfFileEntry(const std::string &name_, std::string dir_, unsigned lastMod_, unsigned length_);
    DwarfFileEntry(DWARFReader &r, DwarfLineInfo *info);
    DwarfFileEntry() {}
};

struct DwarfLineState {
    uintmax_t addr;
    const DwarfFileEntry *file;
    unsigned line;
    unsigned column;
    unsigned is_stmt:1;
    unsigned basic_block:1;
    unsigned end_sequence:1;
    unsigned prologue_end:1;
    unsigned epilogue_begin:1;
    DwarfLineState(DwarfLineInfo *);
    void reset(DwarfLineInfo *);
};

class DwarfLineInfo {
public:
    int default_is_stmt;
    uint8_t opcode_base;
    std::vector<int> opcode_lengths;
    std::vector<std::string> directories;
    std::vector<DwarfFileEntry> files;
    std::vector<DwarfLineState> matrix;
    DwarfLineInfo() {}
    void build(DWARFReader &, const DwarfUnit *);
};

struct DwarfUnit {
    DwarfInfo *dwarf;
    off_t offset;
    void decodeEntries(DWARFReader &r, DwarfEntries &entries);
    uint32_t length;
    uint16_t version;
    std::map<DwarfTag, DwarfAbbreviation> abbreviations;
    uint8_t addrlen;
    const unsigned char *entryPtr;
    const unsigned char *lineInfo;
    DwarfEntries entries;
    DwarfLineInfo lines;
    DwarfUnit(DwarfInfo *, DWARFReader &);
    std::string name() const;
    DwarfUnit() : dwarf(0), offset(-1) {}
};

struct DwarfFDE {
    DwarfCIE *cie;
    uintmax_t iloc;
    uintmax_t irange;
    Elf_Off instructions;
    Elf_Off end;
    std::vector<unsigned char> aug;
    DwarfFDE(DwarfInfo *, DWARFReader &, DwarfCIE * , Elf_Off end);
};

#define MAXREG 128
enum DwarfRegisterType {
    UNDEF,
    SAME,
    OFFSET,
    VAL_OFFSET,
    EXPRESSION,
    VAL_EXPRESSION,
    REG,
    ARCH
};

struct DwarfRegisterUnwind {
    enum DwarfRegisterType type;
    union {
        uintmax_t same;
        uintmax_t offset;
        uintmax_t reg;
        DwarfBlock expression;
        uintmax_t arch;
    } u;
};

struct DwarfCallFrame {
    DwarfRegisterUnwind registers[MAXREG];
    int cfaReg;
    DwarfRegisterUnwind cfaValue;
    DwarfCallFrame();
    // default copy constructor is valid.
};

struct DwarfCIE {
    const DwarfInfo *info;
    uint8_t version;
    uint8_t addressEncoding;
    unsigned char lsdaEncoding;
    bool isSignalHandler;
    unsigned codeAlign;
    int dataAlign;
    int rar;
    Elf_Off instructions;
    Elf_Off end;
    uintmax_t personality;
    unsigned long augSize;
    std::string augmentation;
    DwarfCIE(const DwarfInfo *, DWARFReader &, Elf_Off);
    DwarfCIE() {}
    DwarfCallFrame execInsns(DWARFReader &r, int version, uintmax_t addr, uintmax_t wantAddr);
};

struct DwarfFrameInfo {
    const DwarfInfo *dwarf;
    FIType type;
    std::map<Elf_Addr, DwarfCIE> cies;
    std::list<DwarfFDE> fdeList;
    DwarfFrameInfo(DwarfInfo *, DWARFReader &, FIType type);
    Elf_Addr decodeCIEFDEHdr(int version, DWARFReader &, Elf_Addr &id, off_t start, DwarfCIE **);
    const DwarfFDE *findFDE(Elf_Addr) const;
    bool isCIE(Elf_Off id);
};

class DwarfInfo {
    std::list<DwarfPubnameUnit> pubnameUnits;
    std::list<DwarfARangeSet> aranges;
    std::map<Elf_Off, std::shared_ptr<DwarfUnit>> unitsm;
    int version;
    ElfSection info, debstr, pubnamesh, arangesh, debug_frame;
    std::shared_ptr<ElfObject> altImage;
    std::shared_ptr<DwarfInfo> altDwarf;
    bool altImageLoaded;

public:
    std::shared_ptr<ElfObject> getAltImage();
    std::shared_ptr<DwarfInfo> getAltDwarf();
    mutable DwarfEntries allEntries;
    std::map<Elf_Addr, DwarfCallFrame> callFrameForAddr;
    const ElfSection abbrev, lineshdr;
    // interesting shdrs from the exe.
    std::shared_ptr<ElfObject> elf;
    std::list<DwarfARangeSet> &ranges();
    std::list<DwarfPubnameUnit> &pubnames();
    std::map<Elf_Off, std::shared_ptr<DwarfUnit>> &units();
    char *debugStrings;
    off_t lines;
    std::unique_ptr<DwarfFrameInfo> debugFrame;
    std::unique_ptr<DwarfFrameInfo> ehFrame;
    DwarfInfo(std::shared_ptr<ElfObject> object);
    intmax_t decodeAddress(DWARFReader &, int encoding) const;
    std::vector<std::pair<const DwarfFileEntry *, int>> sourceFromAddr(uintmax_t addr);
    int getVersion() const { return version; }
    ~DwarfInfo();
};

const DwarfAbbreviation *dwarfUnitGetAbbrev(const DwarfUnit *unit, intmax_t code);
const char *dwarfSOpcodeName(enum DwarfLineSOpcode code);
const char *dwarfEOpcodeName(enum DwarfLineEOpcode code);

enum DwarfCFAInstruction {

    DW_CFA_advance_loc          = 0x40, // XXX: Lower 6 = delta
    DW_CFA_offset               = 0x80, // XXX: lower 6 = reg, (offset:uleb128)
    DW_CFA_restore              = 0xc0, // XXX: lower 6 = register
    DW_CFA_nop                  = 0,
    DW_CFA_set_loc              = 1,    // (address)
    DW_CFA_advance_loc1         = 0x02, // (1-byte delta)
    DW_CFA_advance_loc2         = 0x03, // (2-byte delta)
    DW_CFA_advance_loc4         = 0x04, // (4-byte delta)
    DW_CFA_offset_extended      = 0x05, // ULEB128 register ULEB128 offset
    DW_CFA_restore_extended     = 0x06, // ULEB128 register
    DW_CFA_undefined            = 0x07, // ULEB128 register
    DW_CFA_same_value           = 0x08, // ULEB128 register
    DW_CFA_register             = 0x09, // ULEB128 register ULEB128 register
    DW_CFA_remember_state       = 0x0a, //
    DW_CFA_restore_state        = 0x0b, //
    DW_CFA_def_cfa              = 0x0c, // ULEB128 register ULEB128 offset
    DW_CFA_def_cfa_register     = 0x0d, // ULEB128 register
    DW_CFA_def_cfa_offset       = 0x0e, // ULEB128 offset
    DW_CFA_def_cfa_expression   = 0x0f, // BLOCK

    // DWARF 3 only {
    DW_CFA_expression           = 0x10, // ULEB128 register BLOCK
    DW_CFA_offset_extended_sf   = 0x11, // ULEB128 register SLEB128 offset
    DW_CFA_def_cfa_sf           = 0x12, // ULEB128 register SLEB128 offset
    DW_CFA_def_cfa_offset_sf    = 0x13, // SLEB128 offset
    DW_CFA_val_offset           = 0x14, // ULEB128 ULEB128
    DW_CFA_val_offset_sf        = 0x15, // ULEB128 SLEB128
    DW_CFA_val_expression       = 0x16, // ULEB128 BLOCK
    // }

    DW_CFA_lo_user              = 0x1c,
    DW_CFA_GNU_window_size      = 0x2d,
    DW_CFA_GNU_args_size        = 0x2e,
    DW_CFA_GNU_negative_offset_extended = 0x2f,
    DW_CFA_hi_user              = 0x3f,

    /*
     * Value may be this high: ensure compiler generates enough
     * padding to represent this value
     */
    DW_CFA_PAD                  = 0xff
};

class DWARFReader {
    Elf_Off off;
    Elf_Off end;
    uintmax_t getuleb128shift(int *shift, bool &isSigned);
public:
    std::shared_ptr<Reader> io;
    unsigned addrLen;
    size_t dwarfLen; // 8 => 64-bit. 4 => 32-bit.
    int version;

    DWARFReader(std::shared_ptr<Reader> io_, int version_, Elf_Off off_, Elf_Word size_, size_t dwarfLen_)
        : off(off_)
        , end(off_ + size_)
        , io(io_)
        , addrLen(ELF_BITS / 8)
        , version(version_)
        , dwarfLen(dwarfLen_)
    {
    }

    DWARFReader(DWARFReader &rhs, Elf_Off off_, Elf_Word size_)
        : off(off_)
        , end(off_ + size_)
        , io(rhs.io)
        , addrLen(ELF_BITS / 8)
        , version(rhs.version)
        , dwarfLen(rhs.dwarfLen)
    {
    }


    DWARFReader(const ElfSection &section, int version_, Elf_Off off_, size_t dwarfLen_)
        : off(off_ + section->sh_offset)
        , end(section->sh_offset + section->sh_size)
        , io(section.obj.io)
        , addrLen(ELF_BITS / 8)
        , version(version_)
        , dwarfLen(dwarfLen_)
    {
    }

    uint32_t getu32();
    uint16_t getu16();
    uint8_t getu8();
    int8_t gets8();
    uintmax_t getuint(int size);
    uintmax_t getfmtuint() { return getuint(dwarfLen); }
    uintmax_t getfmtint() { return getint(dwarfLen); }
    intmax_t getint(int size);
    uintmax_t getuleb128();
    intmax_t getsleb128();
    std::string getstring();
    Elf_Off getOffset() { return off; }
    Elf_Off getLimit() { return end; }
    void setOffset(Elf_Off off_) { off = off_; }
    bool empty() { return off == end; }
    Elf_Off getlength(size_t *);
    void skip(Elf_Off amount) { off += amount; }
};

#define DWARF_OP(op, value, args) op = value,
enum DwarfExpressionOp {
#include <libpstack/dwarf/ops.h>
    LASTOP = 0x100
};
#undef DWARF_OP

#define DW_EH_PE_absptr 0x00
#define DW_EH_PE_uleb128        0x01
#define DW_EH_PE_udata2 0x02
#define DW_EH_PE_udata4 0x03
#define DW_EH_PE_udata8 0x04
#define DW_EH_PE_sleb128        0x09
#define DW_EH_PE_sdata2 0x0A
#define DW_EH_PE_sdata4 0x0B
#define DW_EH_PE_sdata8 0x0C
#define DW_EH_PE_pcrel  0x10
#define DW_EH_PE_textrel        0x20
#define DW_EH_PE_datarel        0x30
#define DW_EH_PE_funcrel        0x40
#define DW_EH_PE_aligned        0x50


#endif