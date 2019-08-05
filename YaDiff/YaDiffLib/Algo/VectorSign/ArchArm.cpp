#include "ArchArm.hpp"

#include "Helpers.h"
#include "IArch.hpp"
#include "VectorTypes.hpp"

#include <map>
#include <vector>
#include <memory>

// Must init

namespace {
typedef std::map<arm_insn, std::vector<yadiff::InstructionType_e>> InsMap_t;

struct ArmArch : public yadiff::IArch {
    ArmArch();

    bool IsInstructionType(const cs_insn&, yadiff::InstructionType_e) const override;

private:
    bool CheckMap(arm_insn instructionId, yadiff::InstructionType_e instructionTypeA) const;

    InsMap_t insmap;
};
}

ArmArch::ArmArch() {
   
}

#if 0
bool ArmArch::CheckMap(arm_insn instructionId, yadiff::InstructionType_e instructionTypeA) const {
    const auto it = insmap.find(instructionId);
    if (it == insmap.end()) {
        return false;
    }
    for (const auto instructionType : it->second) {
        if (instructionType == instructionTypeA) {
            return true;
        }
    }
    return false;
}
#endif 

bool ArmArch::IsInstructionType(const cs_insn& instruction, yadiff::InstructionType_e type) const {
    const cs_detail* detail = instruction.detail;
    const arm_insn insn_id = static_cast<arm_insn>(instruction.id);

    switch (type) { 
    // OK
    case yadiff::INST_TYPE_ANY:
        return true;

    // OK: LDR    R3,[R5, #8]
    case yadiff::INST_TYPE_READ:
        return detail->arm.op_count >= 2
            && detail->arm.operands[1].type == ARM_OP_MEM;

    // OK: STR    R3, [R4,#0x10]
    case yadiff::INST_TYPE_WRITE:
        return detail->arm.op_count >= 2
            && detail->arm.operands[0].type == ARM_OP_MEM;

    // NO
    case yadiff::INST_TYPE_MOV:
        return false;

    // OK 
    case yadiff::INST_TYPE_CALL:
        for (auto i : instruction.detail->groups) {
            if (i == CS_GRP_CALL) {
                return true;
            }
        }
        return false;

    // NO
    case yadiff::INST_TYPE_STRING:
        // TODO
        return false;

    // OK
    case yadiff::INST_TYPE_FLOAT:
        for (auto i : instruction.detail->groups) {
            if (i == ARM_GRP_VFP2
                || i == ARM_GRP_VFP3
                || i == ARM_GRP_VFP4)
                return true;
        }
        return false;

    // OK: Use the conditional field (upper 4 bits)
    case yadiff::INST_TYPE_CONDITIONAL:
        if (instruction.detail->arm.cc != ARM_CC_AL) {
            return true;
        }
        return false;

    // OK: Update flag details
    case yadiff::INST_TYPE_TEST:
        return instruction.detail->arm.update_flags;


    // NO
    case yadiff::INST_TYPE_ARITHMETIC:
        // TODO
        return false;

    // NO
    case yadiff::INST_TYPE_LOGICAL:
        // TODO
        return false;

    // NO
    case yadiff::INST_TYPE_SHIFT:
        // TODO
        return false;

    // NO
    case yadiff::INST_TYPE_CLEAR:
        // TODO
        return false;

    // NO: inc and dec
    case yadiff::INST_TYPE_INDEX:
        // ADDS Rx, Rx, #1; SUB Rx, Rx, #1
        if (insn_id == ARM_INS_SUB || insn_id == ARM_INS_ADD) {
            if (instruction.detail->arm.op_count == 3) {
                bool operand3 = instruction.detail->arm.operands[0].type == ARM_OP_REG
                    && instruction.detail->arm.operands[1].type == ARM_OP_REG
                    && instruction.detail->arm.operands[2].type == ARM_OP_IMM;
                operand3 &= instruction.detail->arm.operands[0].reg
                    == instruction.detail->arm.operands[1].reg;
                operand3 &= instruction.detail->arm.operands[2].imm == 1;
            }
        }
        return false;

    // OK: if MOV
    case yadiff::INST_TYPE_REG_MOVE:
        // Is mov with 2 operand regs
        if (!IsInstructionType(instruction, yadiff::INST_TYPE_MOV)) {
            return false;
        }
        return instruction.detail->arm.op_count == 2
            && instruction.detail->arm.operands[0].type == ARM_OP_REG
            && instruction.detail->arm.operands[1].type == ARM_OP_REG;

    case yadiff::INST_TYPE_COUNT:
    break;
    }

    return false;
}

std::shared_ptr<yadiff::IArch> yadiff::MakeArmArch() {
    return std::make_shared<ArmArch>();
}

