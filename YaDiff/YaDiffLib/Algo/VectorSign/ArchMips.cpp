#include "ArchMips.hpp"

#include "Helpers.h"
#include "IArch.hpp"
#include "VectorTypes.hpp"

#include <map>
#include <vector>
#include <memory>

// Must init

namespace
{

typedef std::map<mips_insn, std::vector<yadiff::InstructionType_e>> InsMap_t;


struct MipsArch : public yadiff::IArch {
    MipsArch();
    bool IsInstructionType(const cs_insn&, yadiff::InstructionType_e) const override;
    bool CheckMap(mips_insn instructionId, yadiff::InstructionType_e instructionTypeA) const;

    InsMap_t insmap;
};
} // End empty namespace


bool MipsArch::CheckMap(mips_insn instructionId, yadiff::InstructionType_e instructionTypeA) const {
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


MipsArch::MipsArch() {
    // Read
    static const mips_insn readList[] = {
        MIPS_INS_LB, MIPS_INS_LBU, MIPS_INS_LH, MIPS_INS_LHU, MIPS_INS_LL, MIPS_INS_LW, MIPS_INS_LWL, MIPS_INS_LWR,
    };
    for (mips_insn i : readList) {
        insmap[i].push_back(yadiff::INST_TYPE_READ);
    }

    // Write
    static const mips_insn writeList[] = {
        MIPS_INS_SB, MIPS_INS_SC, MIPS_INS_SH, MIPS_INS_SW, MIPS_INS_SWL, MIPS_INS_SWR,
    };
    for (mips_insn i : writeList) {
        insmap[i].push_back(yadiff::INST_TYPE_WRITE);
    }

    // Arithmetic
    static const mips_insn arithmeticList[] = {
        MIPS_INS_ADD, MIPS_INS_ADDI, MIPS_INS_ADDIU, MIPS_INS_ADDU, MIPS_INS_CLO, MIPS_INS_CLZ, MIPS_INS_DIV,
        MIPS_INS_DIVU, MIPS_INS_MADD, MIPS_INS_MADDU, MIPS_INS_MSUB, MIPS_INS_MSUBU, MIPS_INS_MUL, MIPS_INS_MULT,
        MIPS_INS_MULTU, MIPS_INS_SEB, MIPS_INS_SEH, MIPS_INS_SLT, MIPS_INS_SLTI, MIPS_INS_SLTIU, MIPS_INS_SLTU,
        MIPS_INS_SUB, MIPS_INS_SUBU,
    };
    for (mips_insn i : arithmeticList) {
        insmap[i].push_back(yadiff::INST_TYPE_ARITHMETIC);
    }

    // LOgical
    static const mips_insn logicalList[] = {
        MIPS_INS_AND, MIPS_INS_ANDI, MIPS_INS_LUI, MIPS_INS_NOR, MIPS_INS_OR, MIPS_INS_ORI, MIPS_INS_XOR, MIPS_INS_XORI,
    };
    for (mips_insn i : logicalList) {
        insmap[i].push_back(yadiff::INST_TYPE_LOGICAL);
    }

    // Shift
    static const mips_insn shiftList[] = {
        MIPS_INS_ROTR, MIPS_INS_ROTRV, MIPS_INS_SLL, MIPS_INS_SLLV, MIPS_INS_SRA, MIPS_INS_SRAV, MIPS_INS_SRL, MIPS_INS_SRLV,
    };
    for (mips_insn i : shiftList) {
        insmap[i].push_back(yadiff::INST_TYPE_SHIFT);
    }

    // Move (reg 2 reg)
    static const mips_insn movList[] = {
        MIPS_INS_MFHI, MIPS_INS_MFLO, MIPS_INS_MOVF, MIPS_INS_MOVN, MIPS_INS_MOVT, MIPS_INS_MOVZ, MIPS_INS_MTHI, MIPS_INS_MTLO,
    };
    for (mips_insn i : movList) {
        insmap[i].push_back(yadiff::INST_TYPE_MOV);
    }

    // FPU
    static const mips_insn fpuList[] = {
        // arith
        // MIPS_INS_REC, MIPS_INS_RSQRT,
        MIPS_INS_ABS, MIPS_INS_ADD, MIPS_INS_DIV, MIPS_INS_MADD, MIPS_INS_MSUB, MIPS_INS_MUL, MIPS_INS_NEG, MIPS_INS_NMADD,
        MIPS_INS_NMSUB, MIPS_INS_SQRT, MIPS_INS_SUB,
        // branch
        MIPS_INS_BC1F, MIPS_INS_BC1T,
        // compare
        MIPS_INS_C,
        // convert
        // MIPS_INS_ALNV, MIPS_INS_PLL, MIPS_INS_PLU, MIPS_INS_PUL, MIPS_INS_PUU,
         MIPS_INS_CEIL, MIPS_INS_CEIL, MIPS_INS_CVT, MIPS_INS_CVT, MIPS_INS_CVT, MIPS_INS_CVT, MIPS_INS_CVT,
        MIPS_INS_CVT, MIPS_INS_CVT, MIPS_INS_FLOOR, MIPS_INS_FLOOR,
        MIPS_INS_ROUND, MIPS_INS_ROUND, MIPS_INS_TRUNC,
        // memory
        // MIPS_INS_PREFX,
        MIPS_INS_LDC1, MIPS_INS_LDXC1, MIPS_INS_LUXC1, MIPS_INS_LWC1, MIPS_INS_LWXC1, 
        MIPS_INS_SDC1, MIPS_INS_SDXC1, MIPS_INS_SUXC1, MIPS_INS_SWC1, MIPS_INS_SWXC1,
        // move
        MIPS_INS_CFC1, MIPS_INS_CTC1, MIPS_INS_MFC1, MIPS_INS_MFHC1, MIPS_INS_MOV, MIPS_INS_MOVF, MIPS_INS_MOVN,
        MIPS_INS_MOVT, MIPS_INS_MOVZ, MIPS_INS_MTC1, MIPS_INS_MTHC1,
        // obsolete
        MIPS_INS_BC1FL, MIPS_INS_BC1TL,
    };
    for (mips_insn i : fpuList) {
        insmap[i].push_back(yadiff::INST_TYPE_FLOAT);
    }

    // Conditional
    static const mips_insn condList[] = {
        MIPS_INS_BEQ, MIPS_INS_BGEZ, MIPS_INS_BGEZAL, MIPS_INS_BGTZ, MIPS_INS_BLEZ, MIPS_INS_BLTZ,
        MIPS_INS_BLTZAL, MIPS_INS_BNE,
    };
    for (mips_insn i : condList) {
        insmap[i].push_back(yadiff::INST_TYPE_CONDITIONAL);
    }
}

bool MipsArch::IsInstructionType(const cs_insn& instruction, yadiff::InstructionType_e type) const {
    const cs_detail* detail = instruction.detail;
    const mips_insn insn_id = static_cast<mips_insn>(instruction.id);
    bool res;
    UNUSED(detail);
    UNUSED(insn_id);


    switch (type) { 
    // OK
    case yadiff::INST_TYPE_ANY:
        return true;

    // ..
    case yadiff::INST_TYPE_READ:
        return CheckMap(insn_id, yadiff::INST_TYPE_READ);

    // ..
    case yadiff::INST_TYPE_WRITE:
        return CheckMap(insn_id, yadiff::INST_TYPE_WRITE);

    // TODO: add the add instruction from MOV pseudo
    case yadiff::INST_TYPE_MOV:
        res = MipsArch::IsInstructionType(instruction, yadiff::INST_TYPE_WRITE);
        res |= MipsArch::IsInstructionType(instruction, yadiff::INST_TYPE_WRITE);
        res |= CheckMap(insn_id, yadiff::INST_TYPE_MOV);
        return res;

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
        return true;

    // TODO add instruction for double ?
    case yadiff::INST_TYPE_FLOAT:
        return CheckMap(insn_id, yadiff::INST_TYPE_FLOAT);

    // ..: Just branch coond
    case yadiff::INST_TYPE_CONDITIONAL:
        return CheckMap(insn_id, yadiff::INST_TYPE_CONDITIONAL);

    // NO
    case yadiff::INST_TYPE_TEST:
        return true;

    // OK
    case yadiff::INST_TYPE_ARITHMETIC:
        return CheckMap(insn_id, yadiff::INST_TYPE_ARITHMETIC);

    // OK
    case yadiff::INST_TYPE_LOGICAL:
        return CheckMap(insn_id, yadiff::INST_TYPE_LOGICAL);

    // OK
    case yadiff::INST_TYPE_SHIFT:
        return CheckMap(insn_id, yadiff::INST_TYPE_SHIFT);

    // OK: MOVE pseudo code -> ADDI reg, $zero, 0 
    case yadiff::INST_TYPE_CLEAR:
        res = (insn_id == MIPS_INS_ADDI);
        res &= (instruction.detail->mips.op_count == 3);
        res &= instruction.detail->mips.operands[0].type == MIPS_OP_REG;
        res &= instruction.detail->mips.operands[1].type == MIPS_OP_REG;
        res &= instruction.detail->mips.operands[1].reg == MIPS_REG_ZERO;
        res &= instruction.detail->mips.operands[2].type == MIPS_OP_IMM;
        res &= instruction.detail->mips.operands[2].imm == 0;
        return res;


    // NO
    case yadiff::INST_TYPE_INDEX:
        return true;

    // ..
    case yadiff::INST_TYPE_REG_MOVE:
        return CheckMap(insn_id, yadiff::INST_TYPE_MOV);

    // NO
    case yadiff::INST_TYPE_COUNT:
        return true;

    break;
    }

    return false;
}

std::shared_ptr<yadiff::IArch> yadiff::MakeMipsArch() {
    return std::make_shared<MipsArch>();
}

