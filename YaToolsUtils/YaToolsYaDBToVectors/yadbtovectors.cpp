#include <Yatools.hpp>
#include <IModel.hpp>
#include <FlatBufferModel.hpp>
#include <Algo/Algo.hpp>

#include <string>
#include <memory>

int main(int argc, char** argv) {
    // Hi
    fprintf(stdout, "YaDb2Vectors: Starting\n");
    

    // Save command to discriminate
    globals::s_command = "yadiff-yadbtovector";

    // Init log
    globals::InitFileLogger(*globals::Get().logger, stdout);

    // Check args
    if (argc < 3) {
        fprintf(stderr, "Bad arguments\n"
                        "Usage :\n"
                        "yadbtovectors <target_out_file.vect> <flatbuffer_in_file.yadb>\n");
        exit(-1);
    }

    // Init algo
    const auto db1 = MakeFlatBufferModel(argv[2]);
    yadiff::AlgoCfg cfg;
    cfg.Algo = yadiff::ALGO_VECTOR_SIGN;
    cfg.VectorSign.mapDestination = argv[1];
    cfg.VectorSign.concatenate_children = false;
    cfg.VectorSign.concatenate_parents = false;
    std::shared_ptr<yadiff::IDiffAlgo> p_algo = yadiff::MakeDiffAlgo(cfg);

    // Algowork
    p_algo->Prepare(*db1, *db1);

    // Bye
    fprintf(stdout, "YaDb2Vectors: Finished\n");
    return 0;
}
