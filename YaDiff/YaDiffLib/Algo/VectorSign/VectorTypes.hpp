#pragma once

#include "YaTypes.hpp"

// Get IArch callback
#include "IArch.hpp"

// Config, logger
#include "../Algo.hpp"

#include <capstone/capstone.h>
#include <memory>

#include <vector>
#include <string>

namespace yadiff
{

typedef float vector_value;

#define DEFAULT_DOUBLE -1

typedef std::vector<vector_value> Vector;
typedef std::vector<Vector> Matrix;


//
struct FunctionControlFlowGraphData_t
{
    int bb_nb;                          // 1 Number of Basic Blocks -1 for undefined (do not forget to increase that)
    int edge_nb;                        // 2 Number of edges
    int ret_nb;                         // 3 Number of return BB (or exit points)
    int inst_nb;                        // 4 TODO Number of instructions
    int jcc_nb;                         // 5 Number of BB with 2 BB Sons
    int back_edge_nb;                   // 6 Number of edges visiting a yet visited location in the horizontal walk
    int diamond_nb;                     // 7 Number of edges going to bb visited at this same horizontal level (distance to root). Like hybridization in bio.
    int size;                           // 8 Size of the function (in bytes)
    vector_value size_disp;                   // 9 Size dispersion = Variance of the size distribution of my BB in byte (it is a square)
    int height;                         // 10 Number (maximum without going back) of BB to cross from fct entry to fct ret.
    vector_value height_disp;                 // 11 Height dispersion, Variance of the distance to ret of my BB set (not a square)
    int width;                          // 12 Number (maximum) of BB at the same distance from the BB entry.
    vector_value width_disp;                  // 13 Variance of the graph width, average on all dist_to_root levels.*
    int flat_len;                       // 14 TODO Len (in instruction number) of the flatten vector (~ Min inst number from top to bottom)
};
#define FunctionControlFlowGraphData_FIELD_COUNT 14

//
struct FunctionCallGraphData_t
{
    int in_degree;                      // 1 The number of functions calling this one (if a function calls me twice, i count it twice)
    int out_degree;                     // 2 The number of functions called by me (one function can be counted twice also)
    int dist_to_root;                   // 3 The shortest distance from an entry point = a function without parents (a god function)
    int dist_to_leave;                  // 4 The shortest distance to the leave = a function without children
                                        // TODO Get the longest ??
    int arg_nb;                         // 5 The number of arguments the function receives. Hopefully I get the from IDA.
    int lib_nb;                         // 6 Number of calls to a library
};
#define FunctionCallGraphData_FIELD_COUNT 6


//
struct InstructionData_t
{
    // TODO get the main frequencies (fft) per inst.
    int    total;                             // 1 Total number of inst
    vector_value mean_per_bb;                 // 2 The mean number of instruction
    vector_value variance_per_bb;             // 3 The dispersion around the mean number of instruction per bb
    vector_value offset_mean_per_inst;        // 4 The mean offset of inst
    vector_value offset_variance_per_inst;    // 5 The mean disp of inst
    vector_value offset_skew_per_inst;        // 6
    vector_value offset_kurt_per_inst;        // 7
};
#define InstructionData_FIELD_COUNT 7


// 0: The function scalars
struct FunctionData_t
{
    FunctionControlFlowGraphData_t      cfg;
    FunctionCallGraphData_t             cg;
    InstructionData_t                   insts[INST_TYPE_COUNT];
};

// 1: The statistics on neighbourgs on the call graph
struct StatFunction_t
{
    FunctionData_t                      mean;
    FunctionData_t                      median;
    FunctionData_t                      disp;
};

// 2: The type of statistc makking
struct TypeStat_t
{
    StatFunction_t                      not_ponderated;
    StatFunction_t                      ponderated;
};

// ~: Full vector input 
struct Concatenated_t
{
    FunctionData_t                      me;
    TypeStat_t                          father;
    TypeStat_t                          child;
};

	
#define FORMAT_MAX_SIZE   256
class BinaryInfo_t
{
public:
    offset_t                                        base_address;
    offset_t                                        text_address;
    char                                            format[FORMAT_MAX_SIZE+1];
    std::vector<uint8_t>                            blob;
    csh                                             h_capstone;
    cs_err                                          cs_error_val;
    cs_arch                                         cs_arch_val;
    cs_mode                                         cs_mode_val;
    std::shared_ptr<IArch>                          iarch_ptr;

     BinaryInfo_t(const IModel& db, const yadiff::AlgoCfg& config);
    ~BinaryInfo_t();
};




yadiff::Vector FunctionData2Vector(const FunctionData_t& function_data,
    std::vector<std::string>* s_vector, std::string s_base);


} // End of namespace yadiff
