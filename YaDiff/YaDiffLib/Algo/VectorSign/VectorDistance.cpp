/*
    Inputs : Set of vectors   // Representing the function characteristics
             Unity ball       // Representing the maximum allowed distance between 2 functions.

    Outputs : Distance between each vector that is closer to the unity ball 

    Important : Currently I use the norm 1 : d(x,y) = |x1-y1| + |x2-y2|
                With time and wisdom, I may include a more "tolerant" "distance".


    Math lib for Nearest Neighbor Search in a space of double 
    Currently I use a dichotomic fragmentation of space. That is fine to begin with. 
    I may go on with a Voronoi diagram in the fragments or divide the space in an array , at least divide some dimension in more than 2 fragments.
    The end of the algo is a peer to peer comparing. Hopefully not too many vectors are in the same case.
    Maybe this will be replaced with an external library such as spotify/annoy@github (Approximate Nearest Neighbors Oh Yeah)   
*/

#include "VectorDistance.hpp"

#include <cmath>

namespace yadiff 
{
Vector gUnityVector;
Vector gVectorMean;
Vector gVectorMaxLow;
Vector gVectorMinHight;


void SetUnityVector(const Vector& vectUnity)
{
    gUnityVector = vectUnity;
}


void SetDichotomicBorder(const VectorSignatureSet_t& vectSet) {
    // 0/ Allocate
    gVectorMean.resize(gUnityVector.size());
    gVectorMinHight.resize(gUnityVector.size());
    gVectorMaxLow.resize(gUnityVector.size());

    // 1/ Accumulate
    for (const auto& it : vectSet) {
        const auto& crVect = it.second;
        for (size_t i = 0; i < crVect.size(); i++) {
            gVectorMean[i] += crVect[i];
        }
    }

    // 2/ Normalize
    for (size_t i = 0; i < gVectorMean.size(); i++) {
        gVectorMean[i] /= vectSet.size();
    }

    // 3/ MinLow MaxHigh
    for (size_t i = 0; i < gUnityVector.size(); i++) {
        gVectorMaxLow[i]   = gVectorMean[i] + gUnityVector[i] / 2;
        gVectorMinHight[i] = gVectorMean[i] - gUnityVector[i] / 2;
    }
}


void PutVectorInTree(VectorTree_t& vectorTree, VectorGroups_t& vectorGroups, const VectorSignatureSet_t& vectSet)
{
    std::vector<Key_t>    keys;
    std::vector<Key_t>    newKeys;

    // For All vectors in db
    for (const auto& it : vectSet)
    {
        const auto& crVect = it.second;
        keys.clear();
        keys.push_back(0);

        for (size_t i = 0; i < crVect.size(); i++)
        {
            // check if I copy the keys
            bool doCopy = false;

            // insert in the low group (flag not setted) so just make a copy : one wit 0 and the other with 1
            if (crVect[i] < gVectorMaxLow[i])
            {
                doCopy = true;
            }


            // insert in the high component group (flag setted)
            if (crVect[i] > gVectorMinHight[i])
            {
                // If no copy, just add the flag to all keys
                if (!doCopy)
                {
                    for (int& j : keys)
                    {
                        j += (1 << i);
                    }
                }

                // If copy : add the flag to all copied fields
                else
                {
                    newKeys.clear();
                    for (int j : keys)
                    {
                        newKeys.push_back(j + (1 << i));
                    }

                    keys.insert(keys.end(), newKeys.begin(), newKeys.end());
                }
            }
        }
        for (int key : keys)
        {
            vectorTree[key].push_back(it.first);
            vectorGroups[it.first].push_back(key);
        }
    }
}


double GetVectorDistance(const Vector& v1, const Vector& v2) {
    double distance = 0;

    // Get Sum(abs(p2 - p1))
    for (size_t i = 0; i < v1.size(); i++) {
        distance += std::abs(v2[i] - v1[i]) / gUnityVector[i];
    }

    return distance;
}


// TODO return the distance too 
void GetClosestVectorIdNaive(uint64_t& idOut, double& closestDistanceOut, const Vector& vectToLocalize, const std::vector<uint64_t>& idInGroup, VectorSignatureSet_t& vectSet) {
    for (const uint64_t& id : idInGroup) {
        auto& crVect = vectSet[id];

        double fctDist = GetVectorDistance(crVect, vectToLocalize);
        if (fctDist < closestDistanceOut) {
            closestDistanceOut = fctDist;
            idOut = id;
        }
    }
}



} // End namespace yadiff
