/*
Using Capstone, I give a lib that gives some scalar according to the presence of certain instructions.
TODO : get the Arch and the mode in database.
*/
#include "InstructionVector.hpp"

#include "VectorTypes.hpp"
#include "VectorHelpers.hpp"
#include "IArch.hpp"
#include "../Algo.hpp"
#include "IModel.hpp"
#include "Helpers.h"
#include "HVersion.hpp"
#include "Yatools.hpp"

#include <capstone/capstone.h>

#include <numeric>
#include <sstream>
#include <iostream>
#include <functional>
#include <math.h>
#include <functional>
#include <memory>

namespace
{
// used locally to remember my work thourght all lopps.
struct FunctionDisassembled_T
{
    FunctionDisassembled_T(yadiff::InstructionType_e instructionType)
        : instruction_type(instructionType)
    {
    }

    void UpdateBBFields(const YaToolObjectId& bb_id, const std::vector<cs_insn>& bbInstructions, yadiff::IArch& iarch)
    {
        std::vector<bool> res;

        res.reserve(bbInstructions.size());

        for (const auto& insn : bbInstructions) {
            res.push_back(iarch.IsInstructionType(insn, instruction_type));
        }
        bbFields[bb_id] = res;
    }


    std::vector<bool> GetBBVect(const YaToolObjectId& bb_id) const
    {
        // TODO bug fix for function with man's spreading (function that are father than their "size"
        if (bbFields.find(bb_id) != bbFields.end())
            return bbFields.at(bb_id);
        else
            return std::vector<bool>();
    }


    yadiff::InstructionType_e                       instruction_type = yadiff::INST_TYPE_COUNT;
    yadiff::InstructionData_t                       instruction_data = {0, 0, 0, 0, 0, 0, 0};

    // bbFields, a map from of the <offset, bb_inst_type_vector>
    std::map<YaToolObjectId, std::vector<bool>>     bbFields
        = std::map<YaToolObjectId, std::vector<bool>>();
};


#if 0
std::string PrintPrettyInsn(const std::vector<cs_insn>& instructions)
{
    std::stringstream ss;
    for (cs_insn instruction : instructions)
    {
        // ADDR, Menmonic, operands,
        ss << "0x" << std::hex << instruction.address;
        ss << ":\t" << instruction.mnemonic;
        ss << "\t\t" << instruction.op_str << "\n";
    }
    return ss.str();
}
#endif //0


/*@brief :  Disassemble a array of byte
* @param :  <code_int_array> pointer to the buffer containing the executable bytes
*           <size>           size fo this buffer
*            <addr>             address of the first byte offset (like 400000 in IDA)
* @return:  insn_array : array of instruction
* @remark:  The uint8_t_array is a perfect input structure here
*/
std::vector<cs_insn> Disass(const uint8_t* data, size_t size, const yadiff::BinaryInfo_t& binary_info)
{
    if (binary_info.cs_error_val != CS_ERR_OK)
    {
        return  std::vector<cs_insn>();
    }

    // Disass: handle, code, size of code, start point , end point, insn : are the instruction output, the return is the number of instruction
    cs_insn* pointerOut;
    size_t count = cs_disasm(binary_info.h_capstone, data, (int) size, 0x1000, 0, &pointerOut);
    return std::vector<cs_insn>(pointerOut, pointerOut + count);
}




//
//
//
//                  _______________                                          _________________
//                  |             |                                          |                |
//                  |     BB1     |                                          |   B1           |
//                  |_____________|                                       -> |________________|   
//                   /         \                                                      |
//                ________      ________                                      _________________
//                | BB2  |      |  BB3  |                                     |   BB2 and BB3  |
//                |______|      |       |                                     |                |
//       |            |         |   end at last offset of the last            |                |
//                    |         |_______|                                     |________________|
//                    |                                                               |
//                    |                                                               |
//                _______                                                           BB4
//                | BB4 |                                                             
//                |_____|
//
//
//  So you flatten the CFG merging BB at the same distance from root. not SO easy..
//  
//
//
//typedef std::map<int, std::vector<YaToolObjectId>> Pouet_T;
std::vector<double> FlattenFuction(const std::map<int, std::vector<YaToolObjectId>>& equiLevelMap, const FunctionDisassembled_T& dis)
{
    std::vector<double> res;
    size_t last_index = 0; 

    // For all distance to root (in BB);
    for (const auto& it : equiLevelMap)
    {
        const auto& bbIds = it.second;
        for (const auto& bbId : bbIds)
        {
            const std::vector<bool>& bbBoolVect = dis.GetBBVect(bbId);
            for (size_t i = 0; i < bbBoolVect.size(); i++)
            {
                const double vd = (double) bbBoolVect[i];
                if (last_index + i >= res.size())
                {
                    res.insert(res.begin() + last_index + i, vd);
                }
                else
                {
                    res[last_index + i] += vd;
                }
            }
        }
        if(res.size() > 0)
        {
            last_index = res.size() - 1;
        }
    }

   return res;
}


} // End namespace null &&  begin of exported functions








// Entry point
void yadiff::SetDisassemblyFields(
    yadiff::FunctionData_t& function_data,
    const HVersion& fctVersion,
    const std::map<int, std::vector<YaToolObjectId>>& equiLevelMap,
    BinaryInfo_t& binary_info)
{
    std::map<YaToolObjectId, offset_t>      bbIdMap;


    std::vector<FunctionDisassembled_T> structVector;
    for (int i = 0; i < INST_TYPE_COUNT; i++)
    { 
        structVector.push_back(FunctionDisassembled_T((yadiff::InstructionType_e) i));
    }  

    // For all BB, fill the structures 
    fctVersion.walk_xrefs_from([&](offset_t /*offset2*/, operand_t /*operand2*/, const HVersion& bbVersion)
    {
        if (bbVersion.type() != OBJECT_TYPE_BASIC_BLOCK)
            return WALK_CONTINUE;

        // 1.1 Disassemble blob
        size_t bbAddr = static_cast<size_t>(bbVersion.address() - binary_info.text_address);
        size_t bbSize = static_cast<size_t>(bbVersion.size());
        const uint8_t* bbBlob = &(binary_info.blob[bbAddr]);
        const auto bbInstructions = Disass(bbBlob, bbSize, binary_info);

        // 1.15 Increment inst number
        function_data.cfg.inst_nb += static_cast<int>(bbInstructions.size());

        // 1.2 For all callback store bb is_instruction as a map
        for (FunctionDisassembled_T& disassStruct : structVector)
            disassStruct.UpdateBBFields(bbVersion.id(), bbInstructions, *(binary_info.iarch_ptr));
        return WALK_CONTINUE;
    }); // end for all bbVersion


    // For all inst type
    for (int i = 0; i < INST_TYPE_COUNT; i++)
    {
        std::vector<int> fctInstVect;
        auto& disassStruct = structVector[i];
        auto& instruction_data = function_data.insts[i];

        // Create vector on BB coordinates : for all BB 
        for (const auto& it : disassStruct.bbFields)
        {
            int number_of_inst = 0;
            auto& bbBoolVect = it.second;
            for (bool b : bbBoolVect)
            {
                if (b)
                {
                    number_of_inst++;
                }
            }
            fctInstVect.push_back(number_of_inst);
        }

        // Set the per BB statistic fieds.
        instruction_data.total = std::accumulate(fctInstVect.begin(), fctInstVect.end(), 0);
        instruction_data.mean_per_bb = instruction_data.total / function_data.cfg.bb_nb;
        instruction_data.variance_per_bb = GetVariance(fctInstVect, instruction_data.mean_per_bb);

        // Set the per (min) distance (in inst) to root statistic fields
        const auto flattenFunctionInst = FlattenFuction(equiLevelMap,  disassStruct);
        function_data.cfg.flat_len = static_cast<int>(flattenFunctionInst.size());

        // Set central moemnts
        const auto centralMoments = GetCentralMomentByte(flattenFunctionInst, 5);
        instruction_data.offset_mean_per_inst = centralMoments[1];
        instruction_data.offset_variance_per_inst = centralMoments[2];
        instruction_data.offset_skew_per_inst = centralMoments[3];
        instruction_data.offset_kurt_per_inst = centralMoments[4];
    }
}
