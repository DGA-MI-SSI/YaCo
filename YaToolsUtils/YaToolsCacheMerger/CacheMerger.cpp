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

#include <XmlModel.hpp>
#include <MemoryModel.hpp>
#include <XmlVisitor.hpp>

#include <iostream>


void usage(char* name)
{
    std::cerr << "Usage: " << std::endl;
    std::cerr << name << " INPUT_FOLDER OUTPUT_FILE" << std::endl;
}

int main_func(const std::string& folder, const std::string&  output_path)
{
    const auto db = MakeMemoryModel();
    MakeXmlAllModel(folder)->accept(*db);
    db->accept(*MakeFileXmlVisitor(output_path));
    return 0;
}

int main(int argc, char** argv)
{
    if(argc < 3)
    {
        usage(argv[0]);
        return -1;
    }
    try
    {
        return main_func(argv[1], argv[2]);
    }
    catch(std::string& exc)
    {
        std::cerr << "error: " << exc << std::endl;
        return -1;
    }
    catch(const char* message)
    {
        std::cerr << "error: " << message << std::endl;
        return -1;
    }
    catch(std::exception& exc)
    {
        std::cerr << "error: " << exc.what() << std::endl;
    }
    catch(...)
    {
        std::cerr << "error !!!" << std::endl;
    }
}

