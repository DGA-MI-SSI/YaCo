/*
    Math lib for Nearest Neighbor Search in a space of double
    All functions are exported 
*/
#pragma once
#include <vector>
#include <map>
#include <cstdlib>

#include "VectorTypes.hpp"


namespace yadiff
{

// TODO change in tto a bitField. 
typedef int                                                        Key_t;
typedef std::map<Key_t, std::vector<uint64_t>>                     VectorTree_t;
typedef std::map< uint64_t, Vector>                              VectorSignatureSet_t;
typedef std::map< uint64_t, std::vector< Key_t > >                 VectorGroups_t;


void SetDichotomicBorder(const VectorSignatureSet_t& vectSet);

void PutVectorInTree(VectorTree_t& vectorTree, VectorGroups_t& vectorGroups, const VectorSignatureSet_t& vectSet);

double GetVectorDistance(const Vector& v1, const Vector& v2);

void GetClosestVectorIdNaive(uint64_t& idOut, double& closestDistanceOut, const Vector& vectToLocalize, const std::vector<uint64_t>& idInDatabase,  VectorSignatureSet_t& vectSet);

void SetUnityVector(const Vector& vectUnity);

}
