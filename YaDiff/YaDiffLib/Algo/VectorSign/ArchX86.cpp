#include "ArchX86.hpp"

#include "Helpers.h"
#include "IArch.hpp"
#include "VectorTypes.hpp"

#include <map>
#include <vector>
#include <memory>

// Must init

namespace {
typedef std::map<x86_insn, std::vector<yadiff::InstructionType_e>> InsMap_t;

struct X86Arch : public yadiff::IArch {
    X86Arch();

    bool IsInstructionType(const cs_insn&, yadiff::InstructionType_e) const override;

private:
    bool CheckMap(x86_insn instructionId, yadiff::InstructionType_e instructionTypeA) const;

    InsMap_t insmap;
};
} // End of empty namespace

X86Arch::X86Arch() {
    static const x86_insn fpuList[] = {
        // Data Transfer
        X86_INS_FLD, X86_INS_FST, X86_INS_FSTP, X86_INS_FILD, X86_INS_FIST, X86_INS_FISTP, X86_INS_FISTTP, X86_INS_FBLD,
        X86_INS_FBSTP, X86_INS_FXCH, X86_INS_FCMOVE, X86_INS_FCMOVNE, X86_INS_FCMOVB, X86_INS_FCMOVBE, X86_INS_FCMOVNB,
        X86_INS_FCMOVNBE, X86_INS_FCMOVU, X86_INS_FCMOVNU,

        // Basic Arithmetic
        X86_INS_FADD, X86_INS_FADDP, X86_INS_FIADD, X86_INS_FSUB, X86_INS_FSUBP, X86_INS_FISUB, X86_INS_FSUBR, X86_INS_FSUBRP,
        X86_INS_FISUBR, X86_INS_FMUL, X86_INS_FMULP, X86_INS_FIMUL, X86_INS_FDIV, X86_INS_FDIVP, X86_INS_FIDIV, X86_INS_FDIVR,
        X86_INS_FDIVRP, X86_INS_FIDIVR, X86_INS_FPREM, X86_INS_FPREM1, X86_INS_FABS, X86_INS_FCHS, X86_INS_FRNDINT, X86_INS_FSCALE, X86_INS_FSQRT, X86_INS_FXTRACT,

        // Comparison (missing FUCOMIP)
        X86_INS_FCOM, X86_INS_FCOMP, X86_INS_FCOMPP, X86_INS_FUCOM, X86_INS_FUCOMP, X86_INS_FUCOMPP, X86_INS_FICOM, X86_INS_FICOMP, X86_INS_FCOMI, X86_INS_FUCOMI, X86_INS_FTST, X86_INS_FXAM,

        // Transcendental
        X86_INS_FSIN, X86_INS_FCOS, X86_INS_FSINCOS, X86_INS_FPTAN, X86_INS_FPATAN, X86_INS_F2XM1, X86_INS_FYL2X, X86_INS_FYL2XP1,

        // Load constant
        X86_INS_FLD1, X86_INS_FLDZ, X86_INS_FLDPI, X86_INS_FLDL2E, X86_INS_FLDLN2, X86_INS_FLDL2T, X86_INS_FLDLG2,

        // Control  (missing FINIT, FCLEX, FSTCW, FSTENV, FSAVE, FSTSW but I got them with N [for non check error])
        X86_INS_FINCSTP, X86_INS_FDECSTP, X86_INS_FFREE, X86_INS_FNINIT, X86_INS_FNCLEX, X86_INS_FNSTCW, X86_INS_FLDCW, X86_INS_FNSTENV,
        X86_INS_FLDENV, X86_INS_FNSAVE, X86_INS_FRSTOR, X86_INS_FNSTSW, X86_INS_WAIT, X86_INS_FNOP
    };
    for(x86_insn i : fpuList) {
        insmap[i].push_back(yadiff::INST_TYPE_SHIFT);
    }

    // Data transfer TODO remove push pop .. Spek with void.
    // TODO add the other instruction (after / in intel doc)
    static const x86_insn movList[] = {
        // Missing (CMOVC, CMOVNC, PUSHA, POPA);
        // I removed dataX86_INS_XCHG, X86_INS_BSWAP, X86_INS_XADD, X86_INS_CMPXCHG, X86_INS_CMPXCHG8B, X86_INS_PUSH, X86_INS_POP
        X86_INS_MOV, X86_INS_CMOVE, X86_INS_CMOVNE, X86_INS_CMOVA, X86_INS_CMOVAE, X86_INS_CMOVB, X86_INS_CMOVBE, X86_INS_CMOVG, X86_INS_CMOVGE,
        X86_INS_CMOVL, X86_INS_CMOVLE, X86_INS_CMOVO, X86_INS_CMOVNO, X86_INS_CMOVS, X86_INS_CMOVNS, X86_INS_CMOVP, X86_INS_CMOVNP
    };
    for(x86_insn i : movList) {
        insmap[i].push_back(yadiff::INST_TYPE_MOV);
    }

    static const x86_insn arithmeticList[] = {
        // Just removed CMP
        X86_INS_ADD, X86_INS_ADC, X86_INS_SUB, X86_INS_SBB, X86_INS_IMUL, X86_INS_MUL, X86_INS_IDIV, X86_INS_DIV, X86_INS_INC, X86_INS_DEC, X86_INS_NEG
    };
    for(x86_insn i : arithmeticList) {
        insmap[i].push_back(yadiff::INST_TYPE_ARITHMETIC);
    }

    static const x86_insn logicalList[] = {
        // Yes just 4 like Ninja Turtles.
        X86_INS_AND, X86_INS_OR, X86_INS_XOR, X86_INS_NOT
    };
    for(x86_insn i : logicalList) {
        insmap[i].push_back(yadiff::INST_TYPE_LOGICAL);
    }

    static const x86_insn shiftList[] = {
        X86_INS_SAR, X86_INS_SHR, X86_INS_SAL, X86_INS_SHL, X86_INS_SHRD, X86_INS_SHLD, X86_INS_ROR, X86_INS_ROL, X86_INS_RCR, X86_INS_RCL
    };
    for(x86_insn i : shiftList) {
        insmap[i].push_back(yadiff::INST_TYPE_SHIFT);
    }
}


bool X86Arch::CheckMap(x86_insn instructionId, yadiff::InstructionType_e instructionTypeA) const {
    const auto it = insmap.find(instructionId);
    if(it == insmap.end()) {
        return false;
    }
    for(const auto instructionType : it->second) {
        if(instructionType == instructionTypeA) {
            return true;
        }
    }
    return false;
}


bool X86Arch::IsInstructionType(const cs_insn& instruction, yadiff::InstructionType_e type) const {
    const cs_detail* detail = instruction.detail;
    const x86_insn insn_id = static_cast<x86_insn>(instruction.id);

    switch (type) {
    case yadiff::INST_TYPE_ANY:
        return true;


    case yadiff::INST_TYPE_READ:
        return detail->x86.op_count >= 2
            && detail->x86.operands[1].type == X86_OP_MEM;


    case yadiff::INST_TYPE_WRITE:
        return detail->x86.op_count >= 2
            && detail->x86.operands[0].type == X86_OP_MEM;


    case yadiff::INST_TYPE_MOV:
        return CheckMap(insn_id, yadiff::INST_TYPE_MOV);


    case yadiff::INST_TYPE_CALL:
        for (auto i : instruction.detail->groups) {
            if (i == CS_GRP_CALL) {
                return true;
            }
        }
        return false;


    case yadiff::INST_TYPE_STRING:
    {
        const auto prefix = (x86_prefix) instruction.detail->x86.prefix[0];
        return prefix == X86_PREFIX_REP
            || prefix == X86_PREFIX_REPE
            || prefix == X86_PREFIX_REPNE;
    }

    case yadiff::INST_TYPE_FLOAT:
        return CheckMap(insn_id, yadiff::INST_TYPE_FLOAT);


    case yadiff::INST_TYPE_CONDITIONAL:
        for (uint8_t i = 0; i < instruction.detail->regs_read_count; i++) {
            if (instruction.detail->regs_read[i] == X86_REG_EFLAGS) {
                return true;
            }
        }
        return false;


    case yadiff::INST_TYPE_TEST:
        return instruction.detail->x86.eflags != 0;


    case yadiff::INST_TYPE_ARITHMETIC:
        return CheckMap(insn_id, yadiff::INST_TYPE_ARITHMETIC);


    case yadiff::INST_TYPE_LOGICAL:
        return CheckMap(insn_id, yadiff::INST_TYPE_LOGICAL);


    case yadiff::INST_TYPE_SHIFT:
        return CheckMap(insn_id, yadiff::INST_TYPE_SHIFT);


    case yadiff::INST_TYPE_CLEAR:
        return insn_id == X86_INS_XOR
            && instruction.detail->x86.op_count == 2
            && instruction.detail->x86.operands[0].type == X86_OP_REG
            && instruction.detail->x86.operands[1].type == X86_OP_REG
            && instruction.detail->x86.operands[0].reg == instruction.detail->x86.operands[1].reg;
            // TODO mov reg, 0


    case yadiff::INST_TYPE_INDEX:
        return insn_id == X86_INS_INC
            || insn_id == X86_INS_DEC;


    case yadiff::INST_TYPE_REG_MOVE:
        // Is mov with 2 operand regs
        if (!IsInstructionType(instruction, yadiff::INST_TYPE_MOV)) {
            return false;
        }
        return instruction.detail->x86.op_count == 2
            && instruction.detail->x86.operands[0].type == X86_OP_REG
            && instruction.detail->x86.operands[1].type == X86_OP_REG;

    case yadiff::INST_TYPE_COUNT:
    break;
    }

    return false;
}

std::shared_ptr<yadiff::IArch> yadiff::MakeX86Arch() {
    return std::make_shared<X86Arch>();
}
