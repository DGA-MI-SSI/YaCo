/*
    Signature comparing aims to match functions based on some quantificables data on these functions. Those data are gathered in a structure that we call a signature YaDiffVectorSign::FunctionSignature_T defined in YaDiffVectorSign.hpp
    .....
*/

#include "VectorSign.hpp"

#include "VectorSign/VectorHelpers.hpp"
#include "VectorSign/VectorTypes.hpp"
#include "VectorSign/VectorDistance.hpp"
#include "VectorSign/InstructionVector.hpp"
#include "VectorSign/IArch.hpp"
#include "Algo.hpp"
#include "HVersion.hpp"
#include "VersionRelation.hpp"
#include "Helpers.h"
#include "Yatools.hpp"

#include <algorithm> // for max, transform (ie:add 2 vectors)
#include <sstream>
#include <limits.h>
#include <cstdlib>
#include <cmath>
#include <queue>
#include <fstream>
#include <memory>


#ifdef UGLY_INCLUDE_IDA
#include "Ida.h"    // for FUNC_LIB
#else
#define FUNC_LIB        0x00000004     ///< Library function
#endif

namespace {

/* BB SIGN,
    The minimum info I need to store for each BB to be able to get new data
    for the fct CFG
*/
struct BasicBlockSignature_t
{
    BasicBlockSignature_t()
        : dist_to_root (INT_MAX)
        , dist_to_leave(0)
        , size         (0)
        , addr         (0)
    {
    }
    int        dist_to_root;    // Shortest distance to the fct first BB (0 for the first BB)
    int        dist_to_leave;   // Shortest distance to the closest ret (0 for a ret BB).
    int        size;            // Size in byte, to calculate size dispersion.
    int        addr;            // The offset in the function for one matching system (the default for now)
};


/* FUNCTION SIGNATURE
    Is a pool of quantifiable data on a function.
*/
struct FunctionSignature_t
{
    const_string_ref                            name;           // The user defined name
    YaToolObjectId                              firstBBId;      // The ID of its first basic block, to begin the horizontal walk.
    YaToolObjectId                              fctId;          // The ID of this function, to enable easy lookup
    offset_t                                    addr;           // Addr (or offset) of the function in the binary as int (unsigned)
    std::vector <YaToolObjectId>                parents;        // The pointers to the parents functions
    std::vector <YaToolObjectId>                children;       // The pointers to the children functions
    std::map<int, std::vector<YaToolObjectId>>  equiLevelMap;   // for joining BBs
    yadiff::FunctionData_t                      function_data;
    yadiff::Vector                              vector;
    yadiff::Vector                              concatenated_vector;
};

// Basic Block Map
typedef std::map<YaToolObjectId, BasicBlockSignature_t>  BasicBlockSignatureMap_t;

// Function Map : between a function ID and its signature
typedef std::map<YaToolObjectId, FunctionSignature_t>  FunctionSignatureMap_t;

// TODO must be used uin vectordistance -> VectorDeterministicDistance
// Database stored info
struct VectorSignDatabase
{
    FunctionSignatureMap_t                        functionSignatureMap;
    yadiff::VectorTree_t                          idTree;                // Used as a tree, same vector = same group
    yadiff::VectorSignatureSet_t                  vectSet;
    yadiff::VectorGroups_t                        vectorGroups;
    const IModel*                                 pDb;
};



struct VectorSignAlgo : public yadiff::IVectorSigner
{
    VectorSignAlgo(const yadiff::AlgoCfg& config);

    bool Prepare(const IModel& db1, const IModel& db2) override;
    bool Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input) override;
    const char* GetName() const override;
    void BuildVectors(const IModel& db1, const yadiff::OnVectorFn& output) override;

    // Get width and height of the fctVersion, store in the map
    bool ControlFlowGraphHorizontalWalk(const HVersion& fctVersion, const HVersion& firstBBVersion, FunctionSignatureMap_t& functionSignatureMap);


    // Calculate the function parameters, used for signing it (BB nb, edge nb, call nb, ret nb ..)
    void SetFunctionFields(const HVersion& fctVersion, FunctionSignatureMap_t& fsMap, yadiff::BinaryInfo_t& binary_info, const IModel& db);

    // The Main prepare function, create a signature for all function and store it in a map (now global)
    void CreateFunctionSignatureMap(FunctionSignatureMap_t& functionSignatureMap, const IModel& db, const yadiff::AlgoCfg& config);

    void CreateConcatenatedString(std::vector<std::string>* concatenated_string);
    void CreateConcatenatedVector(FunctionSignatureMap_t& functionSignatureMap);
    // TODO
    // void MakeGroups(FunctionSignatureMap_t fsMap, VectorTree_t fctGroup);

    // Calculate the distance to root or leave in the call Graph for all fcts.
    void CalculateAllFunctionDistanceToLeave(FunctionSignatureMap_t& functionSignatureMap);
    void CalculateAllFunctionDistanceToRoot(FunctionSignatureMap_t& functionSignatureMap, const IModel& db1);

    // Print some data of the FunctionSIgnature or just the name of these data if bIsFirstLine
    void PrintFunctionSignature(std::ostream& dst, const FunctionSignature_t& functionSignature, bool is_first_line, std::vector<std::string>* pconcatenated_string);

    // Print the map, recursively calling PrintFunctionSign
    void PrintFunctionSignatureMap(const FunctionSignatureMap_t& functionSignatureMap);

    // TODO must return something, see YaDiff relations currently, just printing them
    void GetAllFunctionRelation(const yadiff::OnAddRelationFn& output, const yadiff::VectorGroups_t& vectorGroups1, const yadiff::VectorTree_t& fctGroup2);

    void LookupVersionFormId(HVersion& hObjectVersion, const YaToolObjectId& yaToolObjectId, const IModel& db);

private:
    VectorSignDatabase             vectorSignDatabase1;
    VectorSignDatabase             vectorSignDatabase2;
    const yadiff::AlgoCfg&         config_;
};
} // End ::

std::shared_ptr<yadiff::IDiffAlgo> yadiff::MakeVectorSignAlgo(const yadiff::AlgoCfg& config)
{
    return std::make_shared<VectorSignAlgo>(config);
}

std::shared_ptr<yadiff::IVectorSigner> yadiff::MakeVectorBuilder(const yadiff::AlgoCfg& config)
{
    return std::make_shared<VectorSignAlgo>(config);
}

const char* VectorSignAlgo::GetName() const{
    return "VectorSignAlgo";
}


VectorSignAlgo::VectorSignAlgo(const yadiff::AlgoCfg& config)
    : config_(config)
{
}

// Entry Point 0
bool VectorSignAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    LOG(INFO, "Prepare : matching %zd objects version to %zd objects version\n", db1.size(), db2.size());

    // Init class databases
    vectorSignDatabase1.pDb = &db1;
    vectorSignDatabase2.pDb = &db2;

    LOG(INFO, "Treat First database\n");
    CreateFunctionSignatureMap(vectorSignDatabase1.functionSignatureMap, db1, config_);

    // Log when wait
    if (config_.VectorSign.mapDestination != NULL)
    {
        LOG(INFO, "MaxLow then Min Hight \n");
        PrintFunctionSignatureMap(vectorSignDatabase1.functionSignatureMap);
    }

    return true;
}


bool VectorSignAlgo::Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input)
{
    UNUSED(input);
    LOG(INFO, "Analyse\n");

    GetAllFunctionRelation(output, vectorSignDatabase1.vectorGroups, vectorSignDatabase1.idTree);

    return true;
}

void VectorSignAlgo::BuildVectors(const IModel& db1, const yadiff::OnVectorFn& output)
{
    UNUSED(db1);
    UNUSED(output);
    vectorSignDatabase1.pDb = &db1;
    CreateFunctionSignatureMap(vectorSignDatabase1.functionSignatureMap, db1, config_);
    for (const auto& it : vectorSignDatabase1.functionSignatureMap)
    {
        if (it.second.name.value != nullptr)
        {
            yadiff::FunctionVector vect = {db1.get(it.second.fctId), it.second.concatenated_vector};
            output(vect);
        }
    }
}


// Retieve hVersion <- oId
void VectorSignAlgo::LookupVersionFormId(HVersion& hObjectVersion, const YaToolObjectId& yaToolObjectId, const IModel& db)
{
    hObjectVersion = db.get(yaToolObjectId);
}

// Currently just print, with one database.
void VectorSignAlgo::GetAllFunctionRelation(const yadiff::OnAddRelationFn& output, const yadiff::VectorGroups_t& vectorGroups1, const yadiff::VectorTree_t& fctGroup2)
{
    Relation relation;
    memset(&relation, 0, sizeof relation);
    relation.type_       = RELATION_TYPE_VECTOR_SIGN;


    // For all vectors in db1
    for (const auto& it : vectorGroups1)
    {
        // distance to closest
        yadiff::vector_value          closestDistance = std::numeric_limits<yadiff::vector_value>::max();
        YaToolObjectId  closestId       = 0;
        auto&           fctSign         = vectorSignDatabase1.functionSignatureMap[it.first];


        // For all groups in db2 containing this vector
        for (const auto& groupId : it.second)
        {
            auto it2 = fctGroup2.find(groupId);

            // If nobody in db2 group, forget it
            if (it2 == fctGroup2.end()) { continue; }

            // TODO vectorSign not existing so I commented. Put all that in distance.
            // TODO get IA: Me -> filemapping
            // yadiff::GetClosestVectorIdNaive(closestId, closestDistance, fctSign.vectorSign, it2->second, vectorSignDatabase1.vectSet);
        }

        if (closestId == 0) { continue; }
        UNUSED(closestDistance);

        LookupVersionFormId(relation.version1_, fctSign.fctId, *vectorSignDatabase1.pDb);
        LookupVersionFormId(relation.version2_, closestId    , *vectorSignDatabase2.pDb);
        output(relation, false);

    } // End for all vectors in db1
}

#include <iostream>
// I create a equilevelMap, now I must use it. // Todo (Out, In)
bool VectorSignAlgo::ControlFlowGraphHorizontalWalk(const HVersion& fctVersion, const HVersion& firstBBVersion, FunctionSignatureMap_t& functionSignatureMap)
{
    std::queue<HVersion>                     bb_to_visit_now;
    std::map<int, std::vector<YaToolObjectId>>     equiLevelMap;
    std::vector<int>                               height_vector;                // the dist_to_root of all leaves
    std::vector<int>                               size_vector;                  // TODO not used : the size of all bb
    BasicBlockSignatureMap_t                       bbsMap;
    auto&                                          fctSign = functionSignatureMap[fctVersion.id()];
    auto&                                          function_data = fctSign.function_data;

    // 1/ Init basicBlocksMap for all BB set dist to root = infinity
    fctVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& fctSonVersion)
    {
        if (fctSonVersion.type() == OBJECT_TYPE_BASIC_BLOCK) {
            bbsMap[fctSonVersion.id()].dist_to_root = std::numeric_limits<int>::max();
        }
        return WALK_CONTINUE;
    });


    // 2/ Init the queue
    bbsMap[firstBBVersion.id()].dist_to_root = 0;
    bb_to_visit_now.push(firstBBVersion);


    // 3/ Recursively mark all BB (just onces)
    // While there is no edge to visit:
    while (!bb_to_visit_now.empty())
    {
        // Retrieve the bbVersion
        const auto bbVersion = bb_to_visit_now.front();
        bb_to_visit_now.pop();

        const auto bbId = bbVersion.id();
        int& iFatherDistToRoot = bbsMap[bbId].dist_to_root;

        // Distribution information gathering
        bool bDoBBRet  = true;
        size_vector.push_back((int) bbVersion.size());
        equiLevelMap[iFatherDistToRoot].push_back(bbId);

        // For all called (children) Basic_block
        bbVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& bbSonVersion)
        {
            if (bbSonVersion.type() != OBJECT_TYPE_BASIC_BLOCK) {
                return WALK_CONTINUE;
            }

            // Forget far jumpers.
            if (bbSonVersion.address() < fctVersion.address()
             || bbSonVersion.address() > fctVersion.address() + fctVersion.size()) {
                return WALK_CONTINUE;
            }

            int& iSonDistToRoot = bbsMap[bbSonVersion.id()].dist_to_root;
            if (iSonDistToRoot != std::numeric_limits<int>::max())
            {
                if (iSonDistToRoot == iFatherDistToRoot + 1) {
                    function_data.cfg.diamond_nb++;
                } else {
                    function_data.cfg.back_edge_nb++;
                }
                return WALK_CONTINUE;
            }

            bDoBBRet = false;
            iSonDistToRoot = iFatherDistToRoot + 1;
            bb_to_visit_now.push(bbSonVersion);
            return WALK_CONTINUE;
        });

        // Push heigh if return node
        if (bDoBBRet) { height_vector.push_back(iFatherDistToRoot); }
    }


    // TODO Get height min
    function_data.cfg.height = *std::max_element(height_vector.begin(), height_vector.end()) + 1;
    yadiff::vector_value height_mean = static_cast<yadiff::vector_value>(function_data.cfg.height) / height_vector.size();
    function_data.cfg.height_disp =  yadiff::GetVariance_Int(height_vector, height_mean);


    // Get the max width  and the mean width
    int summedWidth = 0;
    for (const auto& it : equiLevelMap)
    {
        int crWidth      = static_cast<int>(it.second.size());
        summedWidth += crWidth;
        function_data.cfg.width = std::max(function_data.cfg.width, crWidth);
    }

    // Get the width dispersion
    yadiff::vector_value meanWidth        = static_cast<yadiff::vector_value>(summedWidth) / equiLevelMap.size();
    yadiff::vector_value summedWidthDisp = 0;
    for (const auto& it : equiLevelMap )
    {
        summedWidthDisp += std::pow(it.second.size() - meanWidth, 2);
    }
    summedWidthDisp = std::sqrt(summedWidthDisp);
    summedWidthDisp /= equiLevelMap.size();
    function_data.cfg.width_disp = summedWidthDisp;

    fctSign.equiLevelMap = equiLevelMap;

    return true;
}


/*
:brief:   Set all the function fields (for one given function)
:param:   :fctVersion:  Version of the function to mesure
          :fsMap:       Map containing all the function signatures
:return:  update fsMap
:remark:  TODO shouldn't I be the only one here ?
*/
void VectorSignAlgo::SetFunctionFields(const HVersion& fctVersion, FunctionSignatureMap_t& fsMap, yadiff::BinaryInfo_t& binary_info, const IModel& db)
{
    const auto           functionId                = fctVersion.id();
    auto&                functionSignature         = fsMap[functionId];
    auto&                function_data             = functionSignature.function_data;
    std::vector<int>     bbSizeVector;

    // Init some (easy) parameters, the rest was null initiated before by my caller
    functionSignature.addr                          = fctVersion.address();
    functionSignature.fctId                         = functionId;
    function_data.cfg.size                          = static_cast<int>(fctVersion.size());
    function_data.cfg.bb_nb                         = 0;

    // Init Argument number
    std::string prototype(fctVersion.prototype().value, fctVersion.prototype().size);
    if (prototype == "") {
        function_data.cg.arg_nb = DEFAULT_DOUBLE;
    } else {
        function_data.cg.arg_nb = 1;
        size_t npos = prototype.find(',', 0);
        while (npos != prototype.npos)
        {
            function_data.cg.arg_nb++;
            npos = prototype.find(',', npos+1);
        }
    }

    LOG(INFO, "TOREM : setFunctionFields\n");

    // For all function xref (BB string)
    fctVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& fctSonVersion)
    {
        // If string
        if (fctSonVersion.type() == OBJECT_TYPE_DATA)
        {
            LOG(INFO, "TOREM : I am set functio nchar hist");
            // Get string address and size
            size_t data_address = static_cast<size_t>(fctSonVersion.address());
            size_t data_size = static_cast<size_t>(fctSonVersion.size());

            std::vector<uint8_t> v_stg = GetBlob(data_address, data_size, binary_info, db);
            // TOREM log
            char TODO[0X100];
            int i = 0;
            for (uint8_t i_char : v_stg) {
                TODO[i++] = i_char;
                if (i == 0x100) { break; }
            }
            LOG(INFO, "Vector is %s", TODO);


            
            // TODO string characters histogram
            return WALK_CONTINUE;
        }

        // Check in : return if not BB
        if (fctSonVersion.type() != OBJECT_TYPE_BASIC_BLOCK) { return WALK_CONTINUE; }

        // If first BB
        if (fctVersion.address() == fctSonVersion.address())
        {
            // Set the first BB
            functionSignature.firstBBId       = fctSonVersion.id();
            // Set function Name that is written in its first BB
            functionSignature.name            = fctSonVersion.username();
            // Give noName if no name (logical no ?)
            if (functionSignature.name.size == 0 || functionSignature.name.value == NULL)
            {
                functionSignature.name.size   = 7;
                functionSignature.name.value  = "noName";
            }
            // Store the first BB size (used for comparing)
            function_data.cfg.first_bloc_size = (int) fctSonVersion.size();
        }

        // Increase BB number
        function_data.cfg.bb_nb++;

        // Add the size of current BB for the size dispersion
        bbSizeVector.push_back((int) fctSonVersion.size());

        // We suppose that this is a return BB, if we find him a son, we will set that to false
        // We also suppose that it has no son. If it has one and I found an other, it will be a jcc block.
        bool bDoBBRet       = true;
        bool bHasBBOneBBSon = false;


        // For all son of BB
        fctSonVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& bbSonVersion)
        {
            // This basic block calls
            if (bbSonVersion.type() == OBJECT_TYPE_FUNCTION)
            {
                const auto  childId             = bbSonVersion.id();
                auto&       childFunctionSign   = fsMap[childId];

                // Add 1 to the out degree of current function
                function_data.cg.out_degree++;
                functionSignature.children.push_back(childId);

                // Add 1 to the in degree of the called function
                // And add current function to the parents of the called function
                childFunctionSign.function_data.cg.in_degree++;
                childFunctionSign.parents.push_back(functionId);

                // Check if it is a library function (imported)
                if (bbSonVersion.flags() & FUNC_LIB) {
                    function_data.cg.lib_nb++;
                }
            }
            // This basic block Jmp or Jcc to an other.
            else if (bbSonVersion.type() == OBJECT_TYPE_BASIC_BLOCK)
            {
                // One more edge in a CFG
                function_data.cfg.edge_nb++;

                // This BB has a son, so it is not a ret BB
                bDoBBRet = false;

                // If it has one son yet, it is a JCC.
                if (bHasBBOneBBSon) {
                    function_data.cfg.jcc_nb++;
                } else {
                    bHasBBOneBBSon = true;
                }
            }
            return WALK_CONTINUE;
        }); // End of BB son xRef
        // If it is a return bb (leaf), inc ret_nb
        if (bDoBBRet) {
            function_data.cfg.ret_nb++;
        }
        return WALK_CONTINUE;
    }); // End crfunction xRefs loop

    // Calculate size_disp
    yadiff::vector_value mean_size = static_cast<yadiff::vector_value>(function_data.cfg.size) / function_data.cfg.bb_nb;
    for (int i : bbSizeVector) {
        function_data.cfg.size_disp += std::pow(i - mean_size, 2);
    }
    function_data.cfg.size_disp /= function_data.cfg.bb_nb;

    return;
}


void VectorSignAlgo::CalculateAllFunctionDistanceToLeave(FunctionSignatureMap_t& functionSignatureMap)
{
    std::vector<YaToolObjectId>        fcts_to_visit_parent_now;
    std::vector<YaToolObjectId>        fcts_to_visit_parent_later;

    // INIT: set 0 to leaves and infinity to the rest (infinity is supp to everything
    for (auto& it : functionSignatureMap)
    {
        auto& crFunctionSign = it.second;
        if (0 == crFunctionSign.function_data.cg.out_degree)
        {
            crFunctionSign.function_data.cg.dist_to_leave = 0;
            fcts_to_visit_parent_now.push_back(crFunctionSign.fctId);
        }
        else
        {
            crFunctionSign.function_data.cg.dist_to_leave = 0xFFFF;
        }
    }


    // LOOP
    while (!fcts_to_visit_parent_now.empty())
    {
        const auto crFunctionId = fcts_to_visit_parent_now.back();
        fcts_to_visit_parent_now.pop_back();

        auto& crFunctionSign = functionSignatureMap[crFunctionId];

        // for all parents
        for (const auto parent_id : crFunctionSign.parents)
        {
            auto& parentFunctionSign = functionSignatureMap[parent_id];

            if (parentFunctionSign.function_data.cg.dist_to_leave > crFunctionSign.function_data.cg.dist_to_leave + 1)
            {
                parentFunctionSign.function_data.cg.dist_to_leave = crFunctionSign.function_data.cg.dist_to_leave + 1;
                fcts_to_visit_parent_later.push_back(parent_id);
            }
        } // End for all parents

        if (fcts_to_visit_parent_now.empty())
        {
            fcts_to_visit_parent_now = fcts_to_visit_parent_later;
            fcts_to_visit_parent_later.clear();
        }
    } // End while the known_vector is not null
}


void VectorSignAlgo::CalculateAllFunctionDistanceToRoot(FunctionSignatureMap_t& functionSignatureMap, const IModel& db1)
{
    std::vector<YaToolObjectId>        fcts_to_visit_children_now      = {};
    std::vector<YaToolObjectId>        fcts_to_visit_children_later    = {};


    // INIT:  Give the roots a dist_to_root = 0 and infinity to the rest
    for (auto& it : functionSignatureMap)
    {
        auto& crFunctionSign = it.second;
        if (0 == crFunctionSign.function_data.cg.in_degree)
        {
            crFunctionSign.function_data.cg.dist_to_root = 0;
            fcts_to_visit_children_now.push_back(crFunctionSign.fctId);
        }
        else
        {
            crFunctionSign.function_data.cg.dist_to_root = 0xFFFF;
        }
    }


    // LOOP
    while (!fcts_to_visit_children_now.empty())
    {
        const auto crFunctionId = fcts_to_visit_children_now.back();
        fcts_to_visit_children_now.pop_back();

        auto & crFunctionSign2  = functionSignatureMap[crFunctionId];
        const auto crFctVersion = db1.get(crFunctionId);

        // For all BB
        crFctVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& fctSonVersion)
        {
            if (fctSonVersion.type() != OBJECT_TYPE_BASIC_BLOCK) {
                return WALK_CONTINUE;
            }

            // For all called (children) function
            fctSonVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& bbSonVersion)
            {
                if (bbSonVersion.type() != OBJECT_TYPE_FUNCTION) {
                    return WALK_CONTINUE;
                }

                const auto  child_id            = bbSonVersion.id();
                auto&       childFunctionSign   = functionSignatureMap[child_id];

                // Change the dist_to_root (to lower)
                if (childFunctionSign.function_data.cg.dist_to_root > crFunctionSign2.function_data.cg.dist_to_root + 1)
                {
                    childFunctionSign.function_data.cg.dist_to_root = crFunctionSign2.function_data.cg.dist_to_root + 1;
                    fcts_to_visit_children_later.push_back(child_id);
                }
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });

        // Set the fcts to visit to the next level
        if (fcts_to_visit_children_now.empty())
        {
            fcts_to_visit_children_now = fcts_to_visit_children_later;
            fcts_to_visit_children_later.clear();
        }
    } // End while the known_vector is not null

    // Correct default value
    for (auto& it : functionSignatureMap)
    {
        auto& crFunctionSign = it.second;
        if (crFunctionSign.function_data.cg.dist_to_root == 0xFFFF)
            crFunctionSign.function_data.cg.dist_to_root = DEFAULT_DOUBLE;
    }
}


void VectorSignAlgo::PrintFunctionSignature(std::ostream& dst, const FunctionSignature_t& functionSignature, bool is_first_line, std::vector<std::string>* pconcatenated_string)
{

    // 0: Name of the function
    if (is_first_line) {
        dst << "#Name: ";
    } else {
        dst << functionSignature.name.value << ": ";
    }

    // 0.1 Addr of the function
    if (is_first_line) {
        dst << "addr, ";
    } else {
        dst << "0x" << std::hex << functionSignature.addr << ", ";
    }

    // 2: Global Scalars
    if (is_first_line)
    {
        for (std::string s : *pconcatenated_string)
        {
            dst << s << ",";
        }
    }
    else
    {
        for (yadiff::vector_value d : functionSignature.concatenated_vector)
        {
            dst << d << ",";
        }
    }

    dst << std::endl;
}

void CreateConcatenatedString(std::vector<std::string>* concatenated_string);
void VectorSignAlgo::PrintFunctionSignatureMap(const FunctionSignatureMap_t& functionSignatureMap)
{
    std::ofstream output;
    FunctionSignature_t function_signature;
    std::vector<std::string> concatenated_string;

    CreateConcatenatedString(&concatenated_string);

    output.open(config_.VectorSign.mapDestination);

    PrintFunctionSignature(output, function_signature, true, &concatenated_string);

    for (const auto& it : functionSignatureMap)
    {
        if (it.second.name.value != nullptr)
        {
            PrintFunctionSignature(output, it.second, false, NULL);
        }
    }
}

// return matrix_col[col][line] = matrix_line[line][col]
yadiff::Matrix InvertMatrix(yadiff::Matrix matrix_line)
{
    yadiff::Matrix matrix_col = yadiff::Matrix();
    // TODO escape if null

    // Create a vector for each col
    int line_size = static_cast<int>(matrix_line[0].size());
    int col_size = static_cast<int>(matrix_line.size());
    for (auto& coord1 : matrix_line[0])
    {
        UNUSED(coord1);
        matrix_col.push_back(yadiff::Vector(col_size, 0));
    }

    // Fill
    for (int line = 0; line < line_size; line++)
    {
        for (int col = 0; col < col_size; col++)
        {
            matrix_col[line][col] = matrix_line[col][line];
        }
    }

    return matrix_col;
}


/*
:brief:   Append to function_signature the central moments of matrix columns
:param:
:return:  in function_signature.concatenated_vector (push)
*/
void ConcatenateFamilly(FunctionSignature_t& function_signature,
    yadiff::Matrix& matrix_line)
{
    int size = static_cast<int>(function_signature.vector.size());

    // 1.15: If I have no parents make a null
    // TODO make an other branch ?,
    if (matrix_line.size() == 0)
    {
        matrix_line.push_back(yadiff::Vector(size, 0));
    }

    yadiff::Vector mean = yadiff::Vector();
    mean.reserve(size);
    yadiff::Vector median = yadiff::Vector();
    median.reserve(size);
    yadiff::Vector disp = yadiff::Vector();
    disp.reserve(size);

    // 1.2: Invert matrix
    yadiff::Matrix matrix_col = InvertMatrix(matrix_line);

    // 1.3: Fill median mean, disp vectors
    for (const yadiff::Vector col_vector : matrix_col)
    {
        median.push_back(yadiff::GetMedian(col_vector));
        yadiff::vector_value coordinate_mean = yadiff::GetMean(col_vector);
        mean.push_back(coordinate_mean);
        disp.push_back(yadiff::GetVariance(col_vector, coordinate_mean));
    }

    // 1.4 Concatenate
    function_signature.concatenated_vector.insert(function_signature.concatenated_vector.end(),
        median.begin(), median.end());
    function_signature.concatenated_vector.insert(function_signature.concatenated_vector.end(),
        mean.begin(), mean.end());
    function_signature.concatenated_vector.insert(function_signature.concatenated_vector.end(),
        disp.begin(), disp.end());
}


/*
:brief:   Concatenate me, caller, called internal vectors to the representation vector
              for all functions
:param:   functionSignatureMap : a map with all the function signature structures
:return:  concatenated vector in functionSignatureMap
:remark:  Calls ConcatenateFamilly
*/
void VectorSignAlgo::CreateConcatenatedVector(FunctionSignatureMap_t& functionSignatureMap)
{
    // Get all vector
    for (auto& it : functionSignatureMap)
    {
        FunctionSignature_t& function_signature = it.second;
        function_signature.vector = FunctionData2Vector(function_signature.function_data, NULL, "");
    }
    LOG(INFO, "Creating concatenated vector for all functions\n");

    //TODO : replace these with a "simple" matricial product
    /*
     * We have 6 products to do : childer, parents, children of parents, children of children, parents of parents, parents of children
     *
     * Input :
     *   -NxM matrice of M coordinates for N function
     *   -6xNxN vector : weights for each functions : loop over the 6 above categories, and
     *                    increment the weights
     * output :
     *   -MxNx6 : additionnal coordinates, we just have to divide the result by the sum of the weights in order to get the mean
     *
     */


    // For all function
    for (auto& it: functionSignatureMap)
    {
        FunctionSignature_t& function_signature = it.second;

        LOG(INFO, "Creating concatenated vector for function %s with %zu children and %zu parents\n", function_signature.name.value, function_signature.children.size(), function_signature.parents.size());

        // 0: Me
        function_signature.concatenated_vector = function_signature.vector;

        if(config_.VectorSign.concatenate_parents)
        {
            // 1: Father
            // 1.1: Get matrix
            yadiff::Matrix matrix_line = std::vector<yadiff::Vector>();
            for (auto& parent_id : function_signature.parents)
            {
                yadiff::Vector parent_vector = functionSignatureMap[parent_id].vector;
                matrix_line.push_back(parent_vector);
            }
            // 1.2 Conc
            ConcatenateFamilly(function_signature, matrix_line);
        }
        if(config_.VectorSign.concatenate_children)
        {
            // 2: Child
            // 2.1: Get matrix
            yadiff::Matrix matrix_line = std::vector<yadiff::Vector>();
            for (auto& child_id : function_signature.children)
            {
                yadiff::Vector child_vector = functionSignatureMap[child_id].vector;
                matrix_line.push_back(child_vector);
            }
            // 2.2 Conc
            ConcatenateFamilly(function_signature, matrix_line);
        }
    }
}


/*
:brief:   Create the header string with the column names
*/
void VectorSignAlgo::CreateConcatenatedString(std::vector<std::string>* concatenated_string)
{
    yadiff::FunctionData_t null_function_data;

    FunctionData2Vector(null_function_data, concatenated_string, "");
    if(config_.VectorSign.concatenate_parents)
    {
        FunctionData2Vector(null_function_data, concatenated_string, "father_median_");
        FunctionData2Vector(null_function_data, concatenated_string, "father_mean_");
        FunctionData2Vector(null_function_data, concatenated_string, "father_disp_");
    }
    if(config_.VectorSign.concatenate_children)
    {
        FunctionData2Vector(null_function_data, concatenated_string, "child_median_");
        FunctionData2Vector(null_function_data, concatenated_string, "child_mean_");
        FunctionData2Vector(null_function_data, concatenated_string, "child_disp_");
    }
}


/*
:brief:  Sign all function
:return: functionSignatureMap : map : id -> vector_sign 
*/
void VectorSignAlgo::CreateFunctionSignatureMap(FunctionSignatureMap_t& functionSignatureMap, const IModel& db, const yadiff::AlgoCfg& config)
{
    yadiff::BinaryInfo_t binary_info = yadiff::BinaryInfo_t(db, config);

    // 1/ Create : For all functions : Create an entry in the signatureMap
    db.walk([&](const HVersion& fctVersion)
    {
        // Add entry
        if (fctVersion.type() == OBJECT_TYPE_FUNCTION) {
            functionSignatureMap[fctVersion.id()] = FunctionSignature_t();
        }
        // Next function
        return WALK_CONTINUE;
    });

    // 2/ Fill : For all function : Work
    db.walk([&](const HVersion& fctVersion)
    {
        if (fctVersion.type() != OBJECT_TYPE_FUNCTION) {
            return WALK_CONTINUE;
        }

        // TODO Log function
        // 2.1/ Set the internal fields (global)
        SetFunctionFields(fctVersion, functionSignatureMap, binary_info, db);

        // 2.2/ Walk horizontally the control flow.
        const YaToolObjectId firstBBId  = functionSignatureMap[fctVersion.id()].firstBBId;
        if (firstBBId == 0x0) {
            LOG(WARNING, "WARN addr: %zx\n", fctVersion.address());
            return WALK_CONTINUE;
        }
        const HVersion& firstBBVersion = db.get(firstBBId);
        ControlFlowGraphHorizontalWalk(fctVersion, firstBBVersion, functionSignatureMap);

        // 2.3/ Set the disassembly fields (semantic)
        // TODO remove functionSignature from here
        auto& functionSignature = functionSignatureMap[fctVersion.id()];
        LOG(INFO, "Treating function : %08x called: %s\n",
            static_cast<unsigned int>(functionSignature.addr), functionSignature.name.value);
        SetDisassemblyFields(functionSignature.function_data, fctVersion, functionSignature.equiLevelMap, binary_info);

        return WALK_CONTINUE;
    });

    // 3/ Call graph
    CalculateAllFunctionDistanceToLeave(functionSignatureMap);
    CalculateAllFunctionDistanceToRoot(functionSignatureMap, db);

    // 4/ Father and Son
    CreateConcatenatedVector(functionSignatureMap);
}
