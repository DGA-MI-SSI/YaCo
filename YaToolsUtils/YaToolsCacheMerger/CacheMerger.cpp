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

#include <iostream>
#include <vector>

#include "XML/XMLDatabaseModel.hpp"
#include "XML/XMLExporter.hpp"
#include "Model.hpp"
#include "IModelAccept.hpp"
#include "IModel.hpp"
#include "DelegatingVisitor.hpp"
using namespace std;


void usage(char* name) {
    cerr << "Usage: " << endl;
    cerr << name << " INPUT_FOLDER OUTPUT_FILE" << endl;
}

int main_func(const std::string& folder, const std::string&  output_path) {

    auto db = MakeModel();
    MakeXmlAllDatabaseModel(folder)->accept(*db.visitor);
    auto file_exporter = MakeFileXmlExporter(output_path);
    db.model->accept(*file_exporter);
    return 0;
}

int main(int argc, char** argv){
    string input_path;
    string output_path;

    if(argc < 3) {
        usage(argv[0]);
        return -1;
    }

    input_path = string(argv[1]);
    output_path = string(argv[2]);

    try {
        return main_func(input_path, output_path);
    }
    catch(string& exc) {
        cerr << "error: " << exc << endl;
        return -1;
    }
    catch(const char* message){
        cerr << "error: " << message << endl;
        return -1;
    }
    catch(exception& exc) {
        cerr << "error: " << exc.what() << endl;
    }
    catch(...) {
        cerr << "error !!!" << endl;
    }
}

