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

%include "std_string.i"
%include "std_map.i"
%include "std_set.i"
%include "std_vector.i"

%{
#include "YaGitLib.hpp"
#include "ResolveFileConflictCallback.hpp"
#include <exception>
%}

namespace std
{
	%template (StringSet) std::set<std::string>;
}
%template () std::map<string,string>;

%feature("director:except") {
    if ($error != NULL) {
        throw Swig::DirectorMethodException();
    }
}

%exception {
	try {
		$action	
	} catch(const char *exc) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc));
		return NULL;
	} catch(const Swig::DirectorException& /*exc*/) {
//		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.getMessage()));
 		SWIG_fail;
//		return NULL;
	} catch(const std::exception& exc) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.what()));
		return NULL;
	} catch(const std::string& exc) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.c_str()));
		return NULL;
	} catch( ... ) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>("an unexpected error occured (default message)"));
		return NULL;
	}
}
%feature("director") ResolveFileConflictCallback;

%include "YaGitLib.hpp"
%include "ResolveFileConflictCallback.hpp"

