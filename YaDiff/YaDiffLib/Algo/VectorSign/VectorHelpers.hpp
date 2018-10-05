/*

    Some (math) utils

*/
#pragma once
#include <stddef.h>
#include <vector>
#include "VectorTypes.hpp"


namespace yadiff

{

Vector GetCentralMomentByte(const Vector& byteVector, size_t size);
vector_value GetMedian(const Vector& doubleVector);
vector_value GetMean(const Vector& doubleVector);
vector_value GetVariance(const Vector& doubleVector, vector_value mean);
vector_value GetVariance_Int(const std::vector<int>& doubleVector, vector_value mean);


} // End namespace yadiff