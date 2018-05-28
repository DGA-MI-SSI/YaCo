
#include "VectorHelpers.hpp"

#include <math.h>
#include <algorithm>
#include <numeric>                  // accumulate

namespace yadiff
{

/*@brief :  Get a distribution central moment (like in physics)
* @param :  <doubleVector>   Ordered vector : the weight (number of instruction) at each instruction offset.
*           <size>           Size of the output.
* @return:  Central moment list
* @remark:  Mean is the instruction offset, starts at 0
*/
Vector GetCentralMomentByte(const Vector& byteVector, size_t size)
{
    Vector res = Vector(size);

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
        res[1] += byteVector[i] * (i + 0.5);
    }
    res[1] /= res[0];

    // 2: Get Variance, skew, kurt
    for (size_t i = 0; i < byteVector.size(); i++)
    {
        for (size_t moment = 2; moment < size; moment++)
        {
            res[moment] += byteVector[i] * pow((i + 0.5) - res[1], moment);
        }
    }

    // 3: Root Variance, Skew, Kurt
    for (size_t moment = 2; moment < size; moment++)
    {
        // 3.1: Divide by mass (not null)
        res[moment] /= res[0];

        // 3.2: Root
        double sign = 1 - 2 * std::signbit(res[moment]);
        res[moment] = sign * pow(sign * res[moment], 1. / moment);
    }

    // 4 : Normalize all for a 1 length vector
    for (size_t i = 1; i < size; i++)
    {
        res[i] /= byteVector.size();
    }

    return res;
}

//
double GetMean(const Vector& doubleVector)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    double sum = std::accumulate(doubleVector.begin(), doubleVector.end(), 0.0);
    return sum / doubleVector.size();
}

//
double GetVariance(const Vector& doubleVector, double mean)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    double res = 0;
    std::for_each(doubleVector.begin(), doubleVector.end(), [&](const double d) {
        res += (d - mean) * (d - mean);
    });
    return sqrt(res / doubleVector.size());
}

// TODO template function to mutualize
double GetVariance(const std::vector<int>& doubleVector, double mean)
{
    // Check
    if (doubleVector.empty())
    {
        return DEFAULT_DOUBLE;
    }

    double res = 0;
    std::for_each(doubleVector.begin(), doubleVector.end(), [&](const double d) {
        res += (d - mean) * (d - mean);
    });
    return sqrt(res / doubleVector.size());
}

//
double GetMedian(const Vector& doubleVector)
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