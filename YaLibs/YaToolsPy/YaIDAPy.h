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


%include "std_pair.i"
%include "std_string.i"
%include "std_map.i"
%include "std_multimap.i"
%include "std_set.i"
%include "cstring.i"

%include "std_vector.i"
%include "stl.i"

%template () std::pair<unsigned long long, int>;
%template () std::pair<unsigned long long, unsigned long long>;
%template () std::map<std::pair<unsigned long long, int>,std::string>;
%template () std::map<std::pair<unsigned long long, unsigned long long>,std::string>;
%template () std::map<long long,std::string>;
%template () std::map<int,std::pair<int,int> >;
%template () std::vector<unsigned char>;
%template () std::vector<unsigned long long>;
%template () std::vector<unsigned int>;
%template () std::vector<ea_t>;

%template () std::map<string,string>;



%typemap(typecheck) ea_t
{
    $1 = (PyLong_Check($input) || PyInt_Check($input))? 1:0;
}

%typemap(in) ea_t {
#ifdef __EA64__
        //printf("converting from 64b addr\n");
        if (PyLong_Check($input))
        {
            $1 = (ea_t)PyLong_AsUnsignedLongLongMask($input);
        }
        else if(PyInt_Check($input))
        {
            $1 = PyInt_AsUnsignedLongMask($input);
        }
        else
        {
            printf("bad input : 0x%p\n", $input);
        }

#else
        //printf("converting from 32b addr\n");
          if (PyLong_Check($input)) {
            unsigned long long v = PyLong_AsUnsignedLongLong($input);
            if (PyErr_Occurred()) {
            //printf("PyErr_Occurred on long converting 0x%16X", $input);
            v = 0;
            } else {
              $1 = static_cast<ea_t>(v);
            }
          } else if (PyInt_Check($input)) {
          unsigned long long v;
                v = PyInt_AsLong($input);
            if (PyErr_Occurred()) {
                    //printf("PyErr_Occurred on int converting 0x%16X", $input);
                    v = 0;
                }
                else
                {
                $1 = static_cast<ea_t>(v);
                }
          }
//      $1 = PyLong_AsUnsignedLongMask($input);
#endif
}

%typemap(directorin) ea_t {
#ifdef __EA64__
        //printf("converting from 64b addr\n");
        if (PyLong_Check($input))
        {
            $1 = (ea_t)PyLong_AsUnsignedLongLongMask($input);
        }
        else if(PyInt_Check($input))
        {
            $1 = PyInt_AsUnsignedLongMask($input);
        }
        else
        {
            //printf("bad input : 0x%p\n", $input);
        }

#else
        //printf("converting from 32b addr\n");
          if (PyLong_Check($input)) {
            unsigned long long v = PyLong_AsUnsignedLongLong($input);
            if (PyErr_Occurred()) {
            //printf("PyErr_Occurred on long converting 0x%16X", $input);
            v = 0;
            } else {
              $1 = static_cast<ea_t>(v);
            }
          } else if (PyInt_Check($input)) {
          unsigned long long v;
                v = PyInt_AsLong($input);
            if (PyErr_Occurred()) {
                    //printf("PyErr_Occurred on int converting 0x%16X", $input);
                    v = 0;
                }
                else
                {
                $1 = static_cast<ea_t>(v);
                }
          }
//      $1 = PyLong_AsUnsignedLongMask($input);
#endif
}

%typemap(out) ea_t {
#ifdef __EA64__
        //printf("converting from 64b addr\n");
        $result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
        Py_XINCREF($result);
#else
        //printf("converting from 32b addr\n");
        $result = PyLong_FromUnsignedLong(((unsigned long) ($1 & 0xFFFFFFFF)));
        Py_XINCREF($result);
#endif
}

%apply ea_t {bmask_t};

%typemap(out)  std::vector< ea_t,std::allocator< ea_t > >
{
    $result = PyList_New(0);
    for (auto element : $1)
    {
#ifdef __EA64__
        auto thisobj = PyLong_FromUnsignedLongLong((unsigned long long) element);
#else
        auto thisobj = PyLong_FromUnsignedLong((unsigned long) (element & 0xFFFFFFFF));
#endif
        Py_XINCREF(thisobj);
        PyList_Append($result, thisobj);
    }
}



//std::vector<std::pair<CommentType_e, std::string>> YaToolsIDANativeLib::get_comments_at_ea(ea_t ea)
%typemap(out) std::vector<std::pair<enum CommentType_e,std::string>,std::allocator<std::pair<enum CommentType_e,std::string>>>
//%typemap(out) std::map< std::pair< unsigned long long,CommentType_e >,std::string,std::less< std::pair< unsigned long long,CommentType_e > >,std::allocator< std::pair< std::pair< unsigned long long,CommentType_e > const,std::string > > > const&
{
    $result = PyList_New(0);
//    std::vector<std::pair<enum CommentType_e,std::string>,std::allocator<std::pair<enum CommentType_e,std::string>>> v = $1;
    for(const auto& it : *&$1)
    {
        CommentType_e type = (it).first;
        const std::string& str = (it).second;
        auto tuple = PyTuple_New(2);
        PyTuple_SetItem(tuple, 0, PyInt_FromLong(type));
        PyTuple_SetItem(tuple, 1, SWIG_From_std_string(str));
        PyList_Append($result, tuple);
    }
}


%include <stdint.i>
%include <std_shared_ptr.i>

%shared_ptr(YaToolsIDANativeLib)
%shared_ptr(IExporter)

%template () std::shared_ptr<YaToolsIDANativeLib>;
%template () std::vector<std::shared_ptr<YaToolsIDANativeLib> >;
%{
//in pro.h, they forbid use of some functions that SWIG needs : use them anyway and f*** ida!
#define USE_DANGEROUS_FUNCTIONS

#include <memory>
#include <pro.h>
#include <kernwin.hpp>
#include "YaToolsIDANativeLib.hpp"
#include "IDANativeExporter.hpp"
#include "IDANativeModel.hpp"

#include "YaToolsHashProvider.hpp"
#include <exception>

#include "Comparable.hpp"
#include "Hashable.hpp"
#include "Signature.hpp"
#include "IModelAccept.hpp"
#include "IModelVisitor.hpp"
#include "ExporterValidatorVisitor.hpp"
#include "MultiplexerDelegatingVisitor.hpp"
#include "PathDebuggerVisitor.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "XML/XMLExporter.hpp"
#include "FlatBufferExporter.hpp"
#include "FlatBufferDatabaseModel.hpp"
#include "IObjectVisitorListener.hpp"
#include "YaToolObjectId.hpp"
#include "YaToolObjectVersion.hpp"
#include "YaToolReferencedObject.hpp"
#include "DependencyResolverVisitor.hpp"
#include "VersionRelation.hpp"


%}

%feature("director:except") {
    if ($error != NULL) {
//      PyErr_Print();
//      PyObject *ptype;
//      PyObject *pvalue;
//      PyObject *ptraceback;
//      PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        //PyObject_CallMethod(ptraceback, const_cast<char*>("print_exc"), NULL);
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
//      PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.getMessage()));
        SWIG_fail;
//      return NULL;
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



%include "YaToolsIDANativeLib.hpp"
%include "IDANativeExporter.hpp"
%include "IDANativeModel.hpp"
%include "YaToolsHashProvider.hpp"

