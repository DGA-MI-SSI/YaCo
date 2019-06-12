#include <stddef.h>
#include "VectorTypes.hpp"

// To get Architecture
#include "IArch.hpp"
#include "IModel.hpp"
#include "HVersion.hpp"
#include "Helpers.h"
#include "Yatools.hpp"


#include <assert.h>
#include <memory>
#include <vector>


namespace yadiff {

// Utility function
void TryPush(std::vector<std::string>* s_vector, std::string string) {
    // TODO make it a macro : too slow
    if (s_vector != NULL) {
        s_vector->push_back(string);
    }
}


// Convert internal functio data -> vector
yadiff::Vector FunctionData2Vector(const FunctionData_t& function_data,
    std::vector<std::string>* s_vector, std::string s_base) {

    // Create response vector
    yadiff::Vector res = yadiff::Vector();

    // Control Flow Graph
    res.push_back(static_cast<vector_value>(function_data.cfg.bb_nb));            // 1
    TryPush(s_vector, s_base + "bb_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.edge_nb));          // 2
    TryPush(s_vector, s_base + "edge_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.ret_nb));           // 3
    TryPush(s_vector, s_base + "ret_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.inst_nb));          // 4
    TryPush(s_vector, s_base + "inst_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.jcc_nb));           // 5
    TryPush(s_vector, s_base + "jcc_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.back_edge_nb));     // 6
    TryPush(s_vector, s_base + "back_edge_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.diamond_nb));       // 7
    TryPush(s_vector, s_base + "diamond_nb");
    res.push_back(static_cast<vector_value>(function_data.cfg.size));             // 8
    TryPush(s_vector, s_base + "size");
    res.push_back(static_cast<vector_value>(function_data.cfg.size_disp));        // 9
    TryPush(s_vector, s_base + "size_disp");
    res.push_back(static_cast<vector_value>(function_data.cfg.height));           // 10
    TryPush(s_vector, s_base + "height");
    res.push_back(static_cast<vector_value>(function_data.cfg.height_disp));      // 11
    TryPush(s_vector, s_base + "height_disp");
    res.push_back(static_cast<vector_value>(function_data.cfg.width));            // 12
    TryPush(s_vector, s_base + "width");
    res.push_back(static_cast<vector_value>(function_data.cfg.width_disp));       // 13
    TryPush(s_vector, s_base + "width_disp");
    res.push_back(static_cast<vector_value>(function_data.cfg.flat_len));         // 14
    TryPush(s_vector, s_base + "flat_len");
    res.push_back(static_cast<vector_value>(function_data.cfg.first_bloc_size));  // 15
    TryPush(s_vector, s_base + "first_bloc_size");

    // Call Graph
    res.push_back(static_cast<vector_value>(function_data.cg.in_degree));         // 1
    TryPush(s_vector, s_base + "in_degree");
    res.push_back(static_cast<vector_value>(function_data.cg.out_degree));        // 2
    TryPush(s_vector, s_base + "out_degree");
    res.push_back(static_cast<vector_value>(function_data.cg.dist_to_root));      // 3
    TryPush(s_vector, s_base + "dist_to_root");
    res.push_back(static_cast<vector_value>(function_data.cg.dist_to_leave));     // 4
    TryPush(s_vector, s_base + "dist_to_leave");
    res.push_back(static_cast<vector_value>(function_data.cg.arg_nb));            // 5
    TryPush(s_vector, s_base + "arg_nb");
    res.push_back(static_cast<vector_value>(function_data.cg.lib_nb));            // 6
    TryPush(s_vector, s_base + "lib_nb");

    // Character histogram
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[0]));            // 1
    TryPush(s_vector, s_base + "char_hist_a");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[1]));            // 2
    TryPush(s_vector, s_base + "char_hist_b");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[2]));            // 3
    TryPush(s_vector, s_base + "char_hist_c");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[3]));            // 4
    TryPush(s_vector, s_base + "char_hist_d");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[4]));            // 5
    TryPush(s_vector, s_base + "char_hist_e");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[5]));            // 6
    TryPush(s_vector, s_base + "char_hist_f");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[6]));            // 7
    TryPush(s_vector, s_base + "char_hist_g");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[7]));            // 8
    TryPush(s_vector, s_base + "char_hist_h");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[8]));            // 9
    TryPush(s_vector, s_base + "char_hist_i");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[9]));            // 10
    TryPush(s_vector, s_base + "char_hist_j");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[10]));           // 11
    TryPush(s_vector, s_base + "char_hist_k");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[11]));           // 12
    TryPush(s_vector, s_base + "char_hist_l");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[12]));           // 13
    TryPush(s_vector, s_base + "char_hist_m");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[13]));           // 14
    TryPush(s_vector, s_base + "char_hist_n");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[14]));           // 15
    TryPush(s_vector, s_base + "char_hist_o");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[15]));           // 16
    TryPush(s_vector, s_base + "char_hist_p");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[16]));           // 17
    TryPush(s_vector, s_base + "char_hist_q");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[17]));           // 18
    TryPush(s_vector, s_base + "char_hist_r");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[18]));           // 19
    TryPush(s_vector, s_base + "char_hist_s");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[19]));           // 20
    TryPush(s_vector, s_base + "char_hist_t");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[20]));           // 21
    TryPush(s_vector, s_base + "char_hist_u");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[21]));           // 22
    TryPush(s_vector, s_base + "char_hist_v");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[22]));           // 23
    TryPush(s_vector, s_base + "char_hist_w");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[23]));           // 24
    TryPush(s_vector, s_base + "char_hist_x");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[24]));           // 25
    TryPush(s_vector, s_base + "char_hist_y");
    res.push_back(static_cast<vector_value>(function_data.char_hist.alphabet[25]));           // 26
    TryPush(s_vector, s_base + "char_hist_z");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[0]));               // 27
    TryPush(s_vector, s_base + "char_hist_0");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[1]));               // 28
    TryPush(s_vector, s_base + "char_hist_1");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[2]));               // 29
    TryPush(s_vector, s_base + "char_hist_2");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[3]));               // 30
    TryPush(s_vector, s_base + "char_hist_3");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[4]));               // 31
    TryPush(s_vector, s_base + "char_hist_4");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[5]));               // 32
    TryPush(s_vector, s_base + "char_hist_5");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[6]));               // 33
    TryPush(s_vector, s_base + "char_hist_6");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[7]));               // 34
    TryPush(s_vector, s_base + "char_hist_7");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[8]));               // 35
    TryPush(s_vector, s_base + "char_hist_8");
    res.push_back(static_cast<vector_value>(function_data.char_hist.digit[9]));               // 36
    TryPush(s_vector, s_base + "char_hist_9");
    res.push_back(static_cast<vector_value>(function_data.char_hist.slash));                  // 37
    TryPush(s_vector, s_base + "char_hist_slash");
    res.push_back(static_cast<vector_value>(function_data.char_hist.percent));                // 38
    TryPush(s_vector, s_base + "char_hist_precent");
    res.push_back(static_cast<vector_value>(function_data.char_hist.plus));                   // 39
    TryPush(s_vector, s_base + "char_hist_plus");
    res.push_back(static_cast<vector_value>(function_data.char_hist.minus));                  // 40
    TryPush(s_vector, s_base + "char_hist_minus");
    res.push_back(static_cast<vector_value>(function_data.char_hist.equal));                  // 41
    TryPush(s_vector, s_base + "char_hist_equal");
    res.push_back(static_cast<vector_value>(function_data.char_hist.null));                   // 42
    TryPush(s_vector, s_base + "char_hist_null");

    // Instruction Distribution :
    //     For all instruction type: Get ...
    for (int i = 0; i < INST_TYPE_COUNT; i++) {
        // Name
        InstructionType_e inst_type = static_cast<InstructionType_e>(i);
        InstructionData_t instruction_data = function_data.insts[(InstructionType_e)i];
        // Count
        res.push_back(static_cast<vector_value>(instruction_data.total));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_total");
        // Mean
        res.push_back(static_cast<vector_value>(instruction_data.mean_per_bb));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_mean_per_bb");
        // Variance
        res.push_back(static_cast<vector_value>(instruction_data.variance_per_bb));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_variance_per_bb");
        // Mean/inst
        res.push_back(static_cast<vector_value>(instruction_data.offset_mean_per_inst));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_mean_per_inst");
        // Variance/inst
        res.push_back(static_cast<vector_value>(instruction_data.offset_variance_per_inst));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_variance_per_inst");
        // Skewness
        res.push_back(static_cast<vector_value>(instruction_data.offset_skew_per_inst));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_skew_per_inst");
        // Kurtosis
        res.push_back(static_cast<vector_value>(instruction_data.offset_kurt_per_inst));
        TryPush(s_vector, s_base + "inst_" + InstTypeToString(inst_type) + "_offset_kurt_per_inst");
    }

    // Check Size or Die
    assert(res.size() == FunctionControlFlowGraphData_FIELD_COUNT
             + FunctionCallGraphData_FIELD_COUNT
             + CharacterHistogramData_FIELD_COUNT
             + INST_TYPE_COUNT * InstructionData_FIELD_COUNT);

    return res;
}



// TODO reseve : not used
inline yadiff::Vector StatFunction2Vector(const StatFunction_t& stat_function) {
    // Create response vector
    yadiff::Vector res = yadiff::Vector();

    // TODO remove that 
    yadiff::Vector a = FunctionData2Vector(stat_function.mean, NULL, "");
    yadiff::Vector b = FunctionData2Vector(stat_function.median, NULL, "");
    yadiff::Vector c = FunctionData2Vector(stat_function.disp, NULL, "");
    
    res.insert(res.begin(), a.begin(), a.end());
    res.insert(res.begin(), b.begin(), b.end());
    res.insert(res.begin(), c.begin(), c.end());
    return res;
}


// TODO reseve : not used
inline yadiff::Vector TypeStat2Vector(const TypeStat_t& type_stat) {
    // Create response vector
    yadiff::Vector res = yadiff::Vector();

    yadiff::Vector a = StatFunction2Vector(type_stat.not_ponderated);
    yadiff::Vector b = StatFunction2Vector(type_stat.ponderated);

    res.insert(res.begin(), a.begin(), a.end());
    res.insert(res.begin(), b.begin(), b.end());
    
    return res;
}


yadiff::Vector Concatenated2Vector(const Concatenated_t& concatenated) {
    // Create response vector
    yadiff::Vector res = yadiff::Vector();

    // TODO remove that too
    yadiff::Vector me = FunctionData2Vector(concatenated.me, NULL, "");
    yadiff::Vector a = TypeStat2Vector(concatenated.father);
    yadiff::Vector b = TypeStat2Vector(concatenated.child);
    
    res.insert(res.begin(), me.begin(), me.end());
    res.insert(res.begin(), a.begin(), a.end());
    res.insert(res.begin(), b.begin(), b.end());
    
    return res;
}


// Helper : TODO put me at my place
std::vector<uint8_t> GetBlob(size_t data_begin, size_t data_len, yadiff::BinaryInfo_t& binary_info, const IModel& db) {
    std::vector<uint8_t> res;

    UNUSED(binary_info);

    // Foreach Xref
    db.walk([&](const HVersion& segmentVersion) {
        // Check if it is the good segment
        if (segmentVersion.type() != OBJECT_TYPE_SEGMENT
            || segmentVersion.address() > data_begin
            || segmentVersion.address() + segmentVersion.size() < data_begin + data_len) {
            return WALK_CONTINUE;
        }

        // Foreach chunk (of 0x10.000 bytes)
        segmentVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& chunkVersion) {
            // Check if good chunk
            if (chunkVersion.type() != OBJECT_TYPE_SEGMENT_CHUNK
                // Start of chunk > end_of_string
                || chunkVersion.address() > data_begin + data_len
                // End of chunk < start_of_string
                ||  chunkVersion.address() + chunkVersion.size() < data_begin ) {
                return WALK_CONTINUE;
            }
            

            // For each blob (ox 0x1.000 bytes)
            chunkVersion.walk_blobs([&](offset_t offset, const void* data, size_t len) {
                UNUSED(offset);
                // Check if good blob
                size_t blob_addr = chunkVersion.address() + offset;
                // Next if blob_addr + len < start_of_string
                if (blob_addr + len < data_begin) { return WALK_CONTINUE; }
                // Last if blob_addr > end_of_string
                if (blob_addr > data_begin + data_len) { return WALK_STOP; }

                // Calculate offset of string to retrieve
                size_t o_start = data_begin - blob_addr;
                if (data_begin < blob_addr) { o_start = 0; }
                size_t o_stop = data_begin + data_len - blob_addr;
                if (o_stop > len) { o_stop = len; }

                // Append good slice fo blob
                const uint8_t* pi8Data = (const uint8_t*) data;
                std::vector<uint8_t> vector_to_append = std::vector<uint8_t>(pi8Data + o_start, pi8Data + o_stop);
                res.insert(res.end(), vector_to_append.begin(), vector_to_append.end());

                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });

    return res;
}


//
void SetBlobText(yadiff::BinaryInfo_t& binary_info, const IModel& db) {
    // Create response vector
    std::vector<uint8_t> vector_1000;

    // Get the .text segment
    db.walk([&](const HVersion& segmentVersion) {
        if (segmentVersion.type() != OBJECT_TYPE_SEGMENT) {
            return WALK_CONTINUE;
        }

        std::string segmentName = make_string(segmentVersion.username());
        if (segmentName != std::string(".text")) {
            return WALK_CONTINUE;
        }

        binary_info.text_address = segmentVersion.address();
        segmentVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& chunkVersion) {
            if (chunkVersion.type() != OBJECT_TYPE_SEGMENT_CHUNK) {
                return WALK_CONTINUE;
            }
            chunkVersion.walk_blobs([&](offset_t offset, const void* data, size_t len) {
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

    // Return: blob text has been setted
    return;
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
    db.walk([&](const HVersion& binaryVersion) {
        // Check if binary
        if (binaryVersion.type() != OBJECT_TYPE_BINARY) {
            return WALK_CONTINUE;
        }

        base_address = binaryVersion.address();
        binaryVersion.walk_attributes([&](const const_string_ref& key, const const_string_ref& val) {
            DECLARE_REF(g_format, "format");
            if (!(key == g_format)) {
                return WALK_CONTINUE;
            }
            strncpy(format, val.value, FORMAT_MAX_SIZE);
            format[sizeof(format)-1] = '\0';
            return WALK_STOP;
        });
        return WALK_CONTINUE;
    });

    // 1.2: Set blob text
    SetBlobText(*this, db);
    
    LOG(DEBUG, "parsing architecture : %s\n", format);

    // 2: Branch on arch
    if (strstr(format, "80386") != NULL ||
            (
                strstr(format, "Intel") != NULL && strstr(format, "386") != NULL
            )
        ) {
        cs_arch_val = CS_ARCH_X86;
        cs_mode_val = CS_MODE_32;
    }
    else if (strstr(format, "AMD64") != NULL || strstr(format, "x64") != NULL || strstr(format, "x86-64") != NULL) {
        cs_arch_val = CS_ARCH_X86;
        cs_mode_val = CS_MODE_64;
    }
    else if (strstr(format, "ARM64") != NULL) {
        cs_arch_val = CS_ARCH_ARM64;
        cs_mode_val = CS_MODE_THUMB;
    }
    else if (strstr(format, "ARM") != NULL) {
        cs_arch_val = CS_ARCH_ARM;
        cs_mode_val = CS_MODE_THUMB;
    }
    else if (strstr(format, "PowerPC") != NULL || strstr(format, "ppc") != NULL) {
        cs_arch_val = CS_ARCH_PPC;
        cs_mode_val = CS_MODE_32;
    }
    else if (strstr(format, "MIPS") != NULL) {
        cs_arch_val = CS_ARCH_MIPS;
        cs_mode_val = CS_MODE_32;
    }
    

    // 3: instantiate IArch
    iarch_ptr = MakeArch(cs_arch_val, cs_mode_val);

    // 4: Initialize capstone, 3 arg : Hardware arch, hardware mode, pointer to handle which is the output
    cs_error_val = cs_open(cs_arch_val, cs_mode_val, &h_capstone);
    if (cs_error_val != CS_ERR_OK) {
        return;
    }
    cs_option(h_capstone, CS_OPT_DETAIL, CS_OPT_ON);
}



BinaryInfo_t::~BinaryInfo_t() {
    cs_close(&h_capstone);
}



} // End yadiff::
