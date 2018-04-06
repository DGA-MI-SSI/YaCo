//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "XmlModel.hpp"
#include "IModelVisitor.hpp"
#include "IModel.hpp"
#include "XmlVisitor.hpp"
#include "FlatBufferModel.hpp"
#include "Yatools.hpp"

#include <string>
#include <chrono>
#include <iostream>
#include <memory>

using namespace std;

void print_usage(char* name)
{
    std::cerr << "Usage: " << name << " OUTPUT_FILE INPUT_FILE [INPUT_FILE ...]" << std::endl;
    std::cerr << "\tOUTPUT_FILE:\t\toutput xml file" << std::endl;
    std::cerr << "\tINPUT_FILE:\t\tinput yadb file" << std::endl;

}

int main(int argc, char** argv)
{
    globals::InitFileLogger(*globals::Get().logger, stdout);

    if(argc < 3)
    {
        print_usage(argv[0]);
        return 1;
    }
    for(int i = 2; i < argc; i++)
    {
        if(std::string(argv[i]) == "-h" || std::string(argv[i]) == "--help")
        {
            print_usage(argv[1]);
            return 1;
        }
    }

    std::vector<std::string> filenames;
    for(int i = 2; i < argc; i++)
    {
        filenames.push_back(argv[i]);
    }
    const auto model = MakeMultiFlatBufferModel(filenames);

    auto exporter = MakeFileXmlVisitor(argv[1]);

    model->accept(*exporter);

    return 0;
}
