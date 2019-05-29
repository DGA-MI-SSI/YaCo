#pragma once

#include <capstone/capstone.h>
#include <functional>


namespace std { template<typename T> class shared_ptr; }

namespace yadiff {

// Instruction type enum
enum InstructionType_e {
    INST_TYPE_ANY,                      // Any instruction tyep (always returns true)
    INST_TYPE_READ,                     // Memory from RAM to CPU
    INST_TYPE_WRITE,                    // Memory from CPU to RAM
    INST_TYPE_MOV,                      // Any data movement
    INST_TYPE_CALL,                     // Calling a function
    INST_TYPE_STRING,                   // CString rep operations
    INST_TYPE_FLOAT,                    // FPU Operations
    INST_TYPE_CONDITIONAL,              // Like mov if equal
    INST_TYPE_TEST,                     // Change flags
    INST_TYPE_ARITHMETIC,               // Add, Mul
    INST_TYPE_LOGICAL,                  // Neg, And, Or
    INST_TYPE_SHIFT,                    // Bit shift, rotate
    INST_TYPE_CLEAR,                    // Xor eax, eax && mov eax, 0
    INST_TYPE_INDEX,                    // dec, add
    INST_TYPE_REG_MOVE,                 // mov eax, ebx
    INST_TYPE_COUNT,
};

const char* InstTypeToString(InstructionType_e inst_type);

struct IArch {
    virtual ~IArch() {}
    virtual bool IsInstructionType(const cs_insn&, InstructionType_e) const = 0;
};

std::shared_ptr<IArch> MakeArch(cs_arch architecture, cs_mode register_size);

} // end namespace yadiff
