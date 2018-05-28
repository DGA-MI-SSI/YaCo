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
double GetMedian(const Vector& doubleVector);
double GetMean(const Vector& doubleVector);
double GetVariance(const Vector& doubleVector, double mean);
double GetVariance(const std::vector<int>& doubleVector, double mean);


} // End namespace yadiff