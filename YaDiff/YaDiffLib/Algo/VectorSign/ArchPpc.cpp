#include "ArchPpc.hpp"

#include "Helpers.h"
#include "IArch.hpp"
#include "VectorTypes.hpp"

#include <map>
#include <vector>
#include <memory>

// Must init

namespace {
struct PpcArch : public yadiff::IArch {
    PpcArch();
    bool IsInstructionType(const cs_insn&, yadiff::InstructionType_e) const override;
};
} // End of empty namespace


PpcArch::PpcArch() {
   
}


bool PpcArch::IsInstructionType(const cs_insn& instruction, yadiff::InstructionType_e type) const {
    const cs_detail* detail = instruction.detail;
    const ppc_insn insn_id = static_cast<ppc_insn>(instruction.id);
    UNUSED(detail);
    UNUSED(insn_id);


    switch (type) { 
    // OK
    case yadiff::INST_TYPE_ANY:
        return true;

    // NO
    case yadiff::INST_TYPE_READ:
        return true;

    // NO
    case yadiff::INST_TYPE_WRITE:
        return true;

    // NO
    case yadiff::INST_TYPE_MOV:
        return true;

    // NO
    case yadiff::INST_TYPE_CALL:
        return true;

    // NO
    case yadiff::INST_TYPE_STRING:
        return true;

    // NO
    case yadiff::INST_TYPE_FLOAT:
        return true;

    // NO
    case yadiff::INST_TYPE_CONDITIONAL:
        return true;

    // NO
    case yadiff::INST_TYPE_TEST:
        return true;

    // NO
    case yadiff::INST_TYPE_ARITHMETIC:
        return true;

    // NO
    case yadiff::INST_TYPE_LOGICAL:
        return true;

    // NO
    case yadiff::INST_TYPE_SHIFT:
        return true;

    // NO
    case yadiff::INST_TYPE_CLEAR:
        return true;

    // NO
    case yadiff::INST_TYPE_INDEX:
        return true;

    // NO
    case yadiff::INST_TYPE_REG_MOVE:
        return true;

    // NO
    case yadiff::INST_TYPE_COUNT:
        return true;

    break;
    }

    return false;
}

std::shared_ptr<yadiff::IArch> yadiff::MakePpcArch() {
    return std::make_shared<PpcArch>();
}

