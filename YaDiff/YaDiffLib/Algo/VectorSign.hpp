#pragma once

#include <functional>
#include "IModel.hpp"
#include "HVersion.hpp"
#include "Algo.hpp"
#include "VectorSign/VectorTypes.hpp"

namespace std { template<typename T> class shared_ptr; }

namespace yadiff { struct IDiffAlgo; }
namespace yadiff { struct AlgoCfg; }

namespace yadiff
{
	struct FunctionVector
	{
		HVersion                			version1_;
		const std::vector<vector_value>&    vector_values;
	};
	typedef std::function<bool (const FunctionVector&)> OnVectorFn;

struct IVectorSigner : IDiffAlgo
{
    virtual ~IVectorSigner() {}

    /*
     * Build all vectors of database
     */
    virtual void BuildVectors(const IModel& db1, const OnVectorFn& output) = 0;


};

std::shared_ptr<IDiffAlgo> MakeVectorSignAlgo(const AlgoCfg& config);
std::shared_ptr<IVectorSigner> MakeVectorBuilder(const AlgoCfg& config);


}
