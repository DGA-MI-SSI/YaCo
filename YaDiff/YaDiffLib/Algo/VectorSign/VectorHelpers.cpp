
#include "VectorHelpers.hpp"

#include <math.h>
#include <algorithm>
#include <numeric>                  // accumulate

namespace yadiff
{

/*@brief :  Get a distribution central moment (like in physics)
* @param :  <ByteVector>     Ordered vector : the weight (number of instruction) at each instruction offset.
*           <size>           Size of the output.
* @return:  Central moment list
* @remark:  Mean is the instruction offset, starts at 0
*/
Vector GetCentralMomentByte(const Vector& byteVector, size_t size)
{
    Vector res = Vector(size);
    vector_value f_half = static_cast<vector_value>(0.5);

    // -1: Check input
    if (byteVector.empty())
    {
        return res;
    }

    // 0: Get Weight
    res[0] = 0;
    for (size_t i = 0; i < byteVector.size(); i++)
    {
        res[0] += byteVector[i];
    }
    if (res[0] == 0)
    {
        return res;
    }

    // 1: Get Mean
    for (size_t i = 0; i < byteVector.size(); i++)
    {
        res[1] += byteVector[i] * (i + f_half);
    }
    res[1] /= res[0];

    // 2: Get Variance, skew, kurt
    for (size_t i = 0; i < byteVector.size(); i++)
    {
        for (size_t moment = 2; moment < size; moment++)
        {
            res[moment] += byteVector[i] * static_cast<vector_value>(
                pow((i + f_half) - res[1], moment));
        }
    }

    // 3: Root Variance, Skew, Kurt
    for (size_t moment = 2; moment < size; moment++)
    {
        // 3.1: Divide by mass (not null)
        res[moment] /= res[0];

        // 3.2: Root
        vector_value sign = static_cast<vector_value>(1 - 2 * std::signbit(res[moment]));
        res[moment] = sign * static_cast<vector_value>(pow(sign * res[moment], 1. / moment));
    }

    // 4 : Normalize all for a 1 length vector
    for (size_t i = 1; i < size; i++)
    {
        res[i] /= byteVector.size();
    }

    return res;
}

//
vector_value GetMean(const Vector& doubleVector)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    vector_value sum = static_cast<vector_value>(std::accumulate(doubleVector.begin(), doubleVector.end(), 0.0));
    return sum / doubleVector.size();
}

//
vector_value GetVariance(const Vector& doubleVector, vector_value mean)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    vector_value res = 0;
    std::for_each(doubleVector.begin(), doubleVector.end(), [&](const vector_value d) {
        res += (d - mean) * (d - mean);
    });
    return sqrt(res / doubleVector.size());
}

// TODO template function to mutualize
vector_value GetVariance_Int(const std::vector<int>& doubleVector, vector_value mean)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    vector_value res = 0;
    std::for_each(doubleVector.begin(), doubleVector.end(), [&](const int d) {
        res += static_cast<vector_value>( (d - mean) * (d - mean));
    });
    return sqrt(res / doubleVector.size());
}

//
vector_value GetMedian(const Vector& doubleVector)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    // Don't fully sort
    Vector v = doubleVector;
    size_t n = doubleVector.size() / 2;
    std::nth_element(v.begin(), v.begin() + n, v.end());
    return v[n];
}


} // End namespace yadiff