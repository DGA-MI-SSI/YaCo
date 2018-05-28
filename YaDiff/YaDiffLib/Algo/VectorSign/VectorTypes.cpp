#include <stddef.h>
#include "VectorTypes.hpp"

// To get Architecture
#include "IArch.hpp"
#include "IModel.hpp"
#include "HVersion.hpp"
#include "Helpers.h"


#include <assert.h>
#include <memory>

namespace yadiff
{

void TryPush(std::vector<std::string>* s_vector, std::string string)
{
    // TODO make it a macor : too slow
    if (s_vector != NULL)
    {
        s_vector->push_back(string);
    }
}

std::vector<double> FunctionData2Vector(const FunctionData_t& function_data,
    std::vector<std::string>* s_vector, std::string s_base)
{
    std::vector<double> res = std::vector<double>();


    // Control Flow Graph
    res.push_back(static_cast<double>(function_data.cfg.bb_nb));            // 1
    TryPush(s_vector, s_base + "bb_nb");
    res.push_back(static_cast<double>(function_data.cfg.edge_nb));          // 2
    TryPush(s_vector, s_base + "edge_nb");
    res.push_back(static_cast<double>(function_data.cfg.ret_nb));           // 3
    TryPush(s_vector, s_base + "ret_nb");
    res.push_back(static_cast<double>(function_data.cfg.inst_nb));          // 4
	TryPush(s_vector, s_base + "inst_nb");
    res.push_back(static_cast<double>(function_data.cfg.jcc_nb));           // 5
	TryPush(s_vector, s_base + "jcc_nb");
    res.push_back(static_cast<double>(function_data.cfg.back_edge_nb));     // 6
	TryPush(s_vector, s_base + "back_edge_nb");
    res.push_back(static_cast<double>(function_data.cfg.diamond_nb));       // 7
	TryPush(s_vector, s_base + "diamond_nb");
    res.push_back(static_cast<double>(function_data.cfg.size));             // 8
	TryPush(s_vector, s_base + "size");
    res.push_back(static_cast<double>(function_data.cfg.size_disp));        // 9
	TryPush(s_vector, s_base + "size_disp");
    res.push_back(static_cast<double>(function_data.cfg.height));           // 10
	TryPush(s_vector, s_base + "height");
    res.push_back(static_cast<double>(function_data.cfg.height_disp));      // 11
	TryPush(s_vector, s_base + "height_disp");
    res.push_back(static_cast<double>(function_data.cfg.width));            // 12
	TryPush(s_vector, s_base + "width");
    res.push_back(static_cast<double>(function_data.cfg.width_disp));       // 13
	TryPush(s_vector, s_base + "width_disp");
    res.push_back(static_cast<double>(function_data.cfg.flat_len));         // 14
	TryPush(s_vector, s_base + "flat_len");

    // Call Graph
    res.push_back(static_cast<double>(function_data.cg.in_degree));         // 1
	TryPush(s_vector, s_base + "in_degree");
    res.push_back(static_cast<double>(function_data.cg.out_degree));        // 2
	TryPush(s_vector, s_base + "out_degree");
    res.push_back(static_cast<double>(function_data.cg.dist_to_root));      // 3
	TryPush(s_vector, s_base + "dist_to_root");
    res.push_back(static_cast<double>(function_data.cg.dist_to_leave));     // 4
	TryPush(s_vector, s_base + "dist_to_leave");
    res.push_back(static_cast<double>(function_data.cg.arg_nb));            // 5
	TryPush(s_vector, s_base + "arg_nb");
    res.push_back(static_cast<double>(function_data.cg.lib_nb));            // 6
	TryPush(s_vector, s_base + "lib_nb");

    // Instruction Distribution
    for (int i = 0; i < INST_TYPE_COUNT; i++)
    {
        InstructionType_e inst_type = static_cast<InstructionType_e>(i);
        InstructionData_t instruction_data = function_data.insts[(InstructionType_e)i];
        res.push_back(static_cast<double>(instruction_data.total));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_total");
        res.push_back(static_cast<double>(instruction_data.mean_per_bb));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_mean_per_bb");
        res.push_back(static_cast<double>(instruction_data.variance_per_bb));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_variance_per_bb");
        res.push_back(static_cast<double>(instruction_data.offset_mean_per_inst));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_mean_per_inst");
        res.push_back(static_cast<double>(instruction_data.offset_variance_per_inst));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_variance_per_inst");
        res.push_back(static_cast<double>(instruction_data.offset_skew_per_inst));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_skew_per_inst");
        res.push_back(static_cast<double>(instruction_data.offset_kurt_per_inst));
		TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_kurt_per_inst");
    }


    // Check Size
    assert(res.size() == FunctionControlFlowGraphData_FIELD_COUNT
             + FunctionCallGraphData_FIELD_COUNT
             + INST_TYPE_COUNT * InstructionData_FIELD_COUNT);

    return res;
}


#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
DECLARE_REF(g_format, "format");



void SetBlobText(yadiff::BinaryInfo_t& binary_info, const IModel& db)
{
    std::vector<uint8_t> vector_1000;

    // Get the .text segment
    db.walk([&](const HVersion& segmentVersion)
    {
        if (segmentVersion.type() != OBJECT_TYPE_SEGMENT)
            return WALK_CONTINUE;

        std::string segmentName = make_string(segmentVersion.username());
        if (segmentName.find(".text") == std::string::npos)
            return WALK_CONTINUE;

        binary_info.text_address = segmentVersion.address();
        segmentVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& chunkVersion)
        {
            if (chunkVersion.type() != OBJECT_TYPE_SEGMENT_CHUNK)
                return WALK_CONTINUE;

            //res.reserve(chunkVersion.get_size());
            chunkVersion.walk_blobs([&](offset_t offset, const void* data, size_t len)
            {
                UNUSED(offset);
                const uint8_t* pi8Data = (const uint8_t*)data;
                vector_1000 = std::vector<uint8_t>(pi8Data, pi8Data + len);
                binary_info.blob.insert(binary_info.blob.end(), vector_1000.begin(), vector_1000.end());
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
}


/*@brief :  Init Capstone handle
*/
BinaryInfo_t::BinaryInfo_t(const IModel& db, const yadiff::AlgoCfg& /*config*/)
    : base_address(0)
    , text_address(0)
    , h_capstone(0)
    , cs_error_val(CS_ERR_OK)
    , cs_arch_val(CS_ARCH_MAX)
    , cs_mode_val(CS_MODE_LITTLE_ENDIAN)
{
    // 1: Get architecture, base_addr from database
    db.walk([&](const HVersion& binaryVersion)
    {
        if (binaryVersion.type() != OBJECT_TYPE_BINARY)
            return WALK_CONTINUE;

        base_address = binaryVersion.address();
        binaryVersion.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            if (!(key == g_format))
                return WALK_CONTINUE;
            strncpy(format, val.value, FORMAT_MAX_SIZE);
            format[sizeof(format)-1] = '\0';
            return WALK_STOP;
        });
        return WALK_CONTINUE;
    });

    // 1.2: Set blob text
    SetBlobText(*this, db);

    // 2: Branch on arch
    if (strstr(format, "80386") != NULL)
    {
        cs_arch_val = CS_ARCH_X86;
        cs_mode_val = CS_MODE_32;
    }
    else if (strstr(format, "AMD64") != NULL)
    {
        cs_arch_val = CS_ARCH_X86;
        cs_mode_val = CS_MODE_64;
    }
    else if (strstr(format, "ARM64") != NULL)
    {
        cs_arch_val = CS_ARCH_ARM64;
        cs_mode_val = CS_MODE_THUMB;
    }
    else if (strstr(format, "ARM") != NULL)
    {
        cs_arch_val = CS_ARCH_ARM;
        cs_mode_val = CS_MODE_THUMB;
    }
    else if (strstr(format, "PowerPC") != NULL)
    {
        cs_arch_val = CS_ARCH_PPC;
        cs_mode_val = CS_MODE_32;
    }
    else if (strstr(format, "MIPS") != NULL)
    {
        cs_arch_val = CS_ARCH_MIPS;
        cs_mode_val = CS_MODE_32;
    }


    // 3: instantiate IArch
    iarch_ptr = MakeArch(cs_arch_val, cs_mode_val);

    // 4: Initialize capstone, 3 arg : Hardware arch, hardware mode, pointer to handle which is the output
    cs_error_val = cs_open(cs_arch_val, cs_mode_val, &h_capstone);
    if (cs_error_val != CS_ERR_OK)
    {
        return;
    }
    cs_option(h_capstone, CS_OPT_DETAIL, CS_OPT_ON);
}



BinaryInfo_t::~BinaryInfo_t()
{
    cs_close(&h_capstone);
}



} // End namespace yadiff
