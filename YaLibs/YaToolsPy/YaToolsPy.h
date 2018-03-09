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

%include "std_vector.i"
%include "stl.i"

%{
#include "YaSwig.hpp"
#include "YaEnums.hpp"
%}

%exception
{
 	try
    {
		$action
	}
    catch(const char *exc)
    {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc));
		return NULL;
	}
    catch(const Swig::DirectorException& /*exc*/)
    {
 		SWIG_fail;
	}
    catch(const std::exception& exc)
    {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.what()));
		return NULL;
	}
    catch(const std::string& exc)
    {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.c_str()));
		return NULL;
 	}
    catch( ... )
    {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>("an unexpected error occured (default message)"));
 		return NULL;
 	}
 }

%typemap(in) ea_t
{
    if (PyLong_Check($input))
        $1 = static_cast<ea_t>(PyLong_AsUnsignedLongLongMask($input));
    else if(PyInt_Check($input))
        $1 = static_cast<ea_t>(PyInt_AsUnsignedLongMask($input));
    else
        SWIG_exception_fail(SWIG_ValueError, "invalid ea_t value");
}

%template () std::vector<ea_t>;

%typemap(out) std::vector<ea_t, std::allocator<ea_t>>
{
    $result = PyList_New(0);
    for(const auto element : $1)
    {
        const auto obj = PyLong_FromUnsignedLongLong(element);
        Py_XINCREF(obj);
        PyList_Append($result, obj);
    }
}

%include "YaSwig.hpp"
%include "YaEnums.hpp"
