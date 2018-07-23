#pragma once

#include "VectorTypes.hpp"

#include <stdint.h>
#include <vector>
#include <map>

struct IModel;
struct HVersion;

namespace yadiff
{

/*@brief :  Get the blob of the .text segment of the executable file mapped in memory
* @param :  <db1> The database containing relevant informations on the executable file
* @return:  std::vector containg the bytes of the text blob
* @remark:  To be called just onces for a full database
*/
std::vector<uint8_t> GetBlobText(const IModel& db);

/*@brief :  Get the disassembly Signature of the function
* @param :  <objVersion>    the function object version from yatools
            <equiLevelMap>  map:dist_to_root -> BB
            <blob>          byte blob of code (full segment)
            <flatlen>       some easy output.
* @return:  std::vector with the characteristics, depending on the callbacks used (instruciton types).
* @remark:  To be called for onces for each function version. The the output must be concatenated to get full function signature
*/
void SetDisassemblyFields(
    yadiff::FunctionData_t& function_data,
    const HVersion& fctVersion,
    const std::map<int, std::vector<YaToolObjectId>>& equiLevelMap,
    BinaryInfo_t& binary_info);
}