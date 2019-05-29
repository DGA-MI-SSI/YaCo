#include "IArch.hpp"

#include "Helpers.h"
#include "ArchX86.hpp"
#include "ArchArm.hpp"
#include "ArchPpc.hpp"
#include "ArchMips.hpp"

#include <assert.h>
#include <memory>
#include <stdexcept>

const char* yadiff::InstTypeToString(yadiff::InstructionType_e inst_type) {
    switch(inst_type) {
        case yadiff::INST_TYPE_ANY:         return "ANY";
        case yadiff::INST_TYPE_READ:        return "READ";
        case yadiff::INST_TYPE_WRITE:       return "WRITE";
        case yadiff::INST_TYPE_MOV:         return "MOV";
        case yadiff::INST_TYPE_CALL:        return "CALL";
        case yadiff::INST_TYPE_STRING:      return "STRING";
        case yadiff::INST_TYPE_FLOAT:       return "FLOAT";
        case yadiff::INST_TYPE_CONDITIONAL: return "CONDITIONAL";
        case yadiff::INST_TYPE_TEST:        return "TEST";
        case yadiff::INST_TYPE_ARITHMETIC:  return "ARITHMETIC";
        case yadiff::INST_TYPE_LOGICAL:     return "LOGICAL";
        case yadiff::INST_TYPE_SHIFT:       return "SHIFT";
        case yadiff::INST_TYPE_CLEAR:       return "CLEAR";
        case yadiff::INST_TYPE_INDEX:       return "INDEX";
        case yadiff::INST_TYPE_REG_MOVE:    return "REG_MOVE";
        case yadiff::INST_TYPE_COUNT:       break;
    }
    throw std::runtime_error("unsupported instruction type");
}

std::shared_ptr<yadiff::IArch> yadiff::MakeArch(cs_arch architecture, cs_mode register_size) {
    UNUSED(register_size);
    switch (architecture) {
        case CS_ARCH_X86:      return MakeX86Arch();
        case CS_ARCH_ARM:      return MakeArmArch();
        case CS_ARCH_ARM64:    return MakeArmArch();
        case CS_ARCH_PPC:      return MakePpcArch();
        case CS_ARCH_MIPS:     return MakeMipsArch();
        default:               break;
    }
    throw std::runtime_error("unsupported arch");
}
