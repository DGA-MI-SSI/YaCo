#include <Yatools.hpp>
#include <IModel.hpp>
#include <FlatBufferModel.hpp>
#include <Algo/Algo.hpp>

#include <string>
#include <memory>

int main(int argc, char** argv)
{
    // Save command to discriminate
    char l_command[] = "yadiff-yadbtovector";
    globals::s_command.copy(l_command, sizeof(l_command));

    // Init log
    globals::InitFileLogger(*globals::Get().logger, stdout);

    if (argc < 3)
    {
        fprintf(stderr, "Bad arguments\n"
                        "Usage :\n"
                        "yadbtovectors <flatbuffer> <target_file>\n");
        exit(-1);
    }

    const auto db1 = MakeFlatBufferModel(argv[1]);
    yadiff::AlgoCfg cfg;
    cfg.Algo = yadiff::ALGO_VECTOR_SIGN;
    cfg.VectorSign.mapDestination = argv[2];

    cfg.VectorSign.concatenate_children = true;
    cfg.VectorSign.concatenate_parents = true;

    yadiff::MakeDiffAlgo(cfg)->Prepare(*db1, *db1);
}
