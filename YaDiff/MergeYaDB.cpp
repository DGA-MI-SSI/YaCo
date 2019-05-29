
#include "Yatools.hpp"
#include "YaDiff.hpp"
#include "Propagate.hpp"
#include "Configuration.hpp"
#include "FlatBufferVisitor.hpp"
#include "FlatBufferModel.hpp"

#include <iostream>
using namespace std;


#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("yadiff", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

// Define usage
void usage(char* argv[])
{
    std::cerr << argv[0] << ": <config.xml> <ref_db.yadb> <new_db.yadb> <yadiff.yadb>" << std::endl;
    std::cerr << "\tconfig.xml: " << std::endl;
    std::cerr << "\tref_db.yadb: " << std::endl;
    std::cerr << "\tnew_db.yadb: " << std::endl;
    std::cerr << "\tcache.yadb: update for new_db with information from ref_db" << std::endl;
}

int main(int argc, char** argv)
{
    // Check in
    if (argc != 5) {
        usage(argv);
        return -1;
    }

    // Save command to discriminate
    globals::s_command = "yadiff-mergeyadb";

    // Init log
    globals::InitFileLogger(*globals::Get().logger, stdout);

    // Work
    const auto config = Configuration(argv[1]);
    yadiff::YaDiff(config).MergeCacheFiles(argv[2], argv[3], argv[4]);

    // Bye
    return 0;
}
