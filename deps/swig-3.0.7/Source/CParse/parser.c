/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 22 "parser.y" /* yacc.c:339  */

#define yylex yylex

#include "swig.h"
#include "cparse.h"
#include "preprocessor.h"
#include <ctype.h>

/* We do this for portability */
#undef alloca
#define alloca malloc

/* -----------------------------------------------------------------------------
 *                               Externals
 * ----------------------------------------------------------------------------- */

int  yyparse();

/* NEW Variables */

static Node    *top = 0;      /* Top of the generated parse tree */
static int      unnamed = 0;  /* Unnamed datatype counter */
static Hash    *classes = 0;        /* Hash table of classes */
static Hash    *classes_typedefs = 0; /* Hash table of typedef classes: typedef struct X {...} Y; */
static Symtab  *prev_symtab = 0;
static Node    *current_class = 0;
String  *ModuleName = 0;
static Node    *module_node = 0;
static String  *Classprefix = 0;  
static String  *Namespaceprefix = 0;
static int      inclass = 0;
static Node    *currentOuterClass = 0; /* for nested classes */
static const char *last_cpptype = 0;
static int      inherit_list = 0;
static Parm    *template_parameters = 0;
static int      extendmode   = 0;
static int      compact_default_args = 0;
static int      template_reduce = 0;
static int      cparse_externc = 0;
int		ignore_nested_classes = 0;
int		kwargs_supported = 0;
/* -----------------------------------------------------------------------------
 *                            Assist Functions
 * ----------------------------------------------------------------------------- */


 
/* Called by the parser (yyparse) when an error is found.*/
static void yyerror (const char *e) {
  (void)e;
}

/* Copies a node.  Does not copy tree links or symbol table data (except for
   sym:name) */

static Node *copy_node(Node *n) {
  Node *nn;
  Iterator k;
  nn = NewHash();
  Setfile(nn,Getfile(n));
  Setline(nn,Getline(n));
  for (k = First(n); k.key; k = Next(k)) {
    String *ci;
    String *key = k.key;
    char *ckey = Char(key);
    if ((strcmp(ckey,"nextSibling") == 0) ||
	(strcmp(ckey,"previousSibling") == 0) ||
	(strcmp(ckey,"parentNode") == 0) ||
	(strcmp(ckey,"lastChild") == 0)) {
      continue;
    }
    if (Strncmp(key,"csym:",5) == 0) continue;
    /* We do copy sym:name.  For templates */
    if ((strcmp(ckey,"sym:name") == 0) || 
	(strcmp(ckey,"sym:weak") == 0) ||
	(strcmp(ckey,"sym:typename") == 0)) {
      String *ci = Copy(k.item);
      Setattr(nn,key, ci);
      Delete(ci);
      continue;
    }
    if (strcmp(ckey,"sym:symtab") == 0) {
      Setattr(nn,"sym:needs_symtab", "1");
    }
    /* We don't copy any other symbol table attributes */
    if (strncmp(ckey,"sym:",4) == 0) {
      continue;
    }
    /* If children.  We copy them recursively using this function */
    if (strcmp(ckey,"firstChild") == 0) {
      /* Copy children */
      Node *cn = k.item;
      while (cn) {
	Node *copy = copy_node(cn);
	appendChild(nn,copy);
	Delete(copy);
	cn = nextSibling(cn);
      }
      continue;
    }
    /* We don't copy the symbol table.  But we drop an attribute 
       requires_symtab so that functions know it needs to be built */

    if (strcmp(ckey,"symtab") == 0) {
      /* Node defined a symbol table. */
      Setattr(nn,"requires_symtab","1");
      continue;
    }
    /* Can't copy nodes */
    if (strcmp(ckey,"node") == 0) {
      continue;
    }
    if ((strcmp(ckey,"parms") == 0) || (strcmp(ckey,"pattern") == 0) || (strcmp(ckey,"throws") == 0)
	|| (strcmp(ckey,"kwargs") == 0)) {
      ParmList *pl = CopyParmList(k.item);
      Setattr(nn,key,pl);
      Delete(pl);
      continue;
    }
    if (strcmp(ckey,"nested:outer") == 0) { /* don't copy outer classes links, they will be updated later */
      Setattr(nn, key, k.item);
      continue;
    }
    /* Looks okay.  Just copy the data using Copy */
    ci = Copy(k.item);
    Setattr(nn, key, ci);
    Delete(ci);
  }
  return nn;
}

/* -----------------------------------------------------------------------------
 *                              Variables
 * ----------------------------------------------------------------------------- */

static char  *typemap_lang = 0;    /* Current language setting */

static int cplus_mode  = 0;

/* C++ modes */

#define  CPLUS_PUBLIC    1
#define  CPLUS_PRIVATE   2
#define  CPLUS_PROTECTED 3

/* include types */
static int   import_mode = 0;

void SWIG_typemap_lang(const char *tm_lang) {
  typemap_lang = Swig_copy_string(tm_lang);
}

void SWIG_cparse_set_compact_default_args(int defargs) {
  compact_default_args = defargs;
}

int SWIG_cparse_template_reduce(int treduce) {
  template_reduce = treduce;
  return treduce;  
}

/* -----------------------------------------------------------------------------
 *                           Assist functions
 * ----------------------------------------------------------------------------- */

static int promote_type(int t) {
  if (t <= T_UCHAR || t == T_CHAR) return T_INT;
  return t;
}

/* Perform type-promotion for binary operators */
static int promote(int t1, int t2) {
  t1 = promote_type(t1);
  t2 = promote_type(t2);
  return t1 > t2 ? t1 : t2;
}

static String *yyrename = 0;

/* Forward renaming operator */

static String *resolve_create_node_scope(String *cname);


Hash *Swig_cparse_features(void) {
  static Hash   *features_hash = 0;
  if (!features_hash) features_hash = NewHash();
  return features_hash;
}

/* Fully qualify any template parameters */
static String *feature_identifier_fix(String *s) {
  String *tp = SwigType_istemplate_templateprefix(s);
  if (tp) {
    String *ts, *ta, *tq;
    ts = SwigType_templatesuffix(s);
    ta = SwigType_templateargs(s);
    tq = Swig_symbol_type_qualify(ta,0);
    Append(tp,tq);
    Append(tp,ts);
    Delete(ts);
    Delete(ta);
    Delete(tq);
    return tp;
  } else {
    return NewString(s);
  }
}

static void set_access_mode(Node *n) {
  if (cplus_mode == CPLUS_PUBLIC)
    Setattr(n, "access", "public");
  else if (cplus_mode == CPLUS_PROTECTED)
    Setattr(n, "access", "protected");
  else
    Setattr(n, "access", "private");
}

static void restore_access_mode(Node *n) {
  String *mode = Getattr(n, "access");
  if (Strcmp(mode, "private") == 0)
    cplus_mode = CPLUS_PRIVATE;
  else if (Strcmp(mode, "protected") == 0)
    cplus_mode = CPLUS_PROTECTED;
  else
    cplus_mode = CPLUS_PUBLIC;
}

/* Generate the symbol table name for an object */
/* This is a bit of a mess. Need to clean up */
static String *add_oldname = 0;



static String *make_name(Node *n, String *name,SwigType *decl) {
  int destructor = name && (*(Char(name)) == '~');

  if (yyrename) {
    String *s = NewString(yyrename);
    Delete(yyrename);
    yyrename = 0;
    if (destructor  && (*(Char(s)) != '~')) {
      Insert(s,0,"~");
    }
    return s;
  }

  if (!name) return 0;
  return Swig_name_make(n,Namespaceprefix,name,decl,add_oldname);
}

/* Generate an unnamed identifier */
static String *make_unnamed() {
  unnamed++;
  return NewStringf("$unnamed%d$",unnamed);
}

/* Return if the node is a friend declaration */
static int is_friend(Node *n) {
  return Cmp(Getattr(n,"storage"),"friend") == 0;
}

static int is_operator(String *name) {
  return Strncmp(name,"operator ", 9) == 0;
}


/* Add declaration list to symbol table */
static int  add_only_one = 0;

static void add_symbols(Node *n) {
  String *decl;
  String *wrn = 0;

  if (inclass && n) {
    cparse_normalize_void(n);
  }
  while (n) {
    String *symname = 0;
    /* for friends, we need to pop the scope once */
    String *old_prefix = 0;
    Symtab *old_scope = 0;
    int isfriend = inclass && is_friend(n);
    int iscdecl = Cmp(nodeType(n),"cdecl") == 0;
    int only_csymbol = 0;
    
    if (inclass) {
      String *name = Getattr(n, "name");
      if (isfriend) {
	/* for friends, we need to add the scopename if needed */
	String *prefix = name ? Swig_scopename_prefix(name) : 0;
	old_prefix = Namespaceprefix;
	old_scope = Swig_symbol_popscope();
	Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	if (!prefix) {
	  if (name && !is_operator(name) && Namespaceprefix) {
	    String *nname = NewStringf("%s::%s", Namespaceprefix, name);
	    Setattr(n,"name",nname);
	    Delete(nname);
	  }
	} else {
	  Symtab *st = Swig_symbol_getscope(prefix);
	  String *ns = st ? Getattr(st,"name") : prefix;
	  String *base  = Swig_scopename_last(name);
	  String *nname = NewStringf("%s::%s", ns, base);
	  Setattr(n,"name",nname);
	  Delete(nname);
	  Delete(base);
	  Delete(prefix);
	}
	Namespaceprefix = 0;
      } else {
	/* for member functions, we need to remove the redundant
	   class scope if provided, as in
	   
	   struct Foo {
	   int Foo::method(int a);
	   };
	   
	*/
	String *prefix = name ? Swig_scopename_prefix(name) : 0;
	if (prefix) {
	  if (Classprefix && (Equal(prefix,Classprefix))) {
	    String *base = Swig_scopename_last(name);
	    Setattr(n,"name",base);
	    Delete(base);
	  }
	  Delete(prefix);
	}
      }
    }

    if (!isfriend && (inclass || extendmode)) {
      Setattr(n,"ismember","1");
    }

    if (extendmode) {
      Setattr(n,"isextendmember","1");
    }

    if (!isfriend && inclass) {
      if ((cplus_mode != CPLUS_PUBLIC)) {
	only_csymbol = 1;
	if (cplus_mode == CPLUS_PROTECTED) {
	  Setattr(n,"access", "protected");
	  only_csymbol = !Swig_need_protected(n);
	} else {
	  Setattr(n,"access", "private");
	  /* private are needed only when they are pure virtuals - why? */
	  if ((Cmp(Getattr(n,"storage"),"virtual") == 0) && (Cmp(Getattr(n,"value"),"0") == 0)) {
	    only_csymbol = 0;
	  }
	  if (Cmp(nodeType(n),"destructor") == 0) {
	    /* Needed for "unref" feature */
	    only_csymbol = 0;
	  }
	}
      } else {
	  Setattr(n,"access", "public");
      }
    }
    if (Getattr(n,"sym:name")) {
      n = nextSibling(n);
      continue;
    }
    decl = Getattr(n,"decl");
    if (!SwigType_isfunction(decl)) {
      String *name = Getattr(n,"name");
      String *makename = Getattr(n,"parser:makename");
      if (iscdecl) {	
	String *storage = Getattr(n, "storage");
	if (Cmp(storage,"typedef") == 0) {
	  Setattr(n,"kind","typedef");
	} else {
	  SwigType *type = Getattr(n,"type");
	  String *value = Getattr(n,"value");
	  Setattr(n,"kind","variable");
	  if (value && Len(value)) {
	    Setattr(n,"hasvalue","1");
	  }
	  if (type) {
	    SwigType *ty;
	    SwigType *tmp = 0;
	    if (decl) {
	      ty = tmp = Copy(type);
	      SwigType_push(ty,decl);
	    } else {
	      ty = type;
	    }
	    if (!SwigType_ismutable(ty) || (storage && Strstr(storage, "constexpr"))) {
	      SetFlag(n,"hasconsttype");
	      SetFlag(n,"feature:immutable");
	    }
	    if (tmp) Delete(tmp);
	  }
	  if (!type) {
	    Printf(stderr,"notype name %s\n", name);
	  }
	}
      }
      Swig_features_get(Swig_cparse_features(), Namespaceprefix, name, 0, n);
      if (makename) {
	symname = make_name(n, makename,0);
        Delattr(n,"parser:makename"); /* temporary information, don't leave it hanging around */
      } else {
        makename = name;
	symname = make_name(n, makename,0);
      }
      
      if (!symname) {
	symname = Copy(Getattr(n,"unnamed"));
      }
      if (symname) {
	wrn = Swig_name_warning(n, Namespaceprefix, symname,0);
      }
    } else {
      String *name = Getattr(n,"name");
      SwigType *fdecl = Copy(decl);
      SwigType *fun = SwigType_pop_function(fdecl);
      if (iscdecl) {	
	Setattr(n,"kind","function");
      }
      
      Swig_features_get(Swig_cparse_features(),Namespaceprefix,name,fun,n);

      symname = make_name(n, name,fun);
      wrn = Swig_name_warning(n, Namespaceprefix,symname,fun);
      
      Delete(fdecl);
      Delete(fun);
      
    }
    if (!symname) {
      n = nextSibling(n);
      continue;
    }
    if (cparse_cplusplus) {
      String *value = Getattr(n, "value");
      if (value && Strcmp(value, "delete") == 0) {
	/* C++11 deleted definition / deleted function */
        SetFlag(n,"deleted");
        SetFlag(n,"feature:ignore");
      }
    }
    if (only_csymbol || GetFlag(n,"feature:ignore") || strncmp(Char(symname),"$ignore",7) == 0) {
      /* Only add to C symbol table and continue */
      Swig_symbol_add(0, n);
      if (!only_csymbol && !GetFlag(n, "feature:ignore")) {
	/* Print the warning attached to $ignore name, if any */
        char *c = Char(symname) + 7;
	if (strlen(c)) {
	  SWIG_WARN_NODE_BEGIN(n);
	  Swig_warning(0,Getfile(n), Getline(n), "%s\n",c+1);
	  SWIG_WARN_NODE_END(n);
	}
	/* If the symbol was ignored via "rename" and is visible, set also feature:ignore*/
	SetFlag(n, "feature:ignore");
      }
      if (!GetFlag(n, "feature:ignore") && Strcmp(symname,"$ignore") == 0) {
	/* Add feature:ignore if the symbol was explicitely ignored, regardless of visibility */
	SetFlag(n, "feature:ignore");
      }
    } else {
      Node *c;
      if ((wrn) && (Len(wrn))) {
	String *metaname = symname;
	if (!Getmeta(metaname,"already_warned")) {
	  SWIG_WARN_NODE_BEGIN(n);
	  Swig_warning(0,Getfile(n),Getline(n), "%s\n", wrn);
	  SWIG_WARN_NODE_END(n);
	  Setmeta(metaname,"already_warned","1");
	}
      }
      c = Swig_symbol_add(symname,n);

      if (c != n) {
        /* symbol conflict attempting to add in the new symbol */
        if (Getattr(n,"sym:weak")) {
          Setattr(n,"sym:name",symname);
        } else {
          String *e = NewStringEmpty();
          String *en = NewStringEmpty();
          String *ec = NewStringEmpty();
          int redefined = Swig_need_redefined_warn(n,c,inclass);
          if (redefined) {
            Printf(en,"Identifier '%s' redefined (ignored)",symname);
            Printf(ec,"previous definition of '%s'",symname);
          } else {
            Printf(en,"Redundant redeclaration of '%s'",symname);
            Printf(ec,"previous declaration of '%s'",symname);
          }
          if (Cmp(symname,Getattr(n,"name"))) {
            Printf(en," (Renamed from '%s')", SwigType_namestr(Getattr(n,"name")));
          }
          Printf(en,",");
          if (Cmp(symname,Getattr(c,"name"))) {
            Printf(ec," (Renamed from '%s')", SwigType_namestr(Getattr(c,"name")));
          }
          Printf(ec,".");
	  SWIG_WARN_NODE_BEGIN(n);
          if (redefined) {
            Swig_warning(WARN_PARSE_REDEFINED,Getfile(n),Getline(n),"%s\n",en);
            Swig_warning(WARN_PARSE_REDEFINED,Getfile(c),Getline(c),"%s\n",ec);
          } else if (!is_friend(n) && !is_friend(c)) {
            Swig_warning(WARN_PARSE_REDUNDANT,Getfile(n),Getline(n),"%s\n",en);
            Swig_warning(WARN_PARSE_REDUNDANT,Getfile(c),Getline(c),"%s\n",ec);
          }
	  SWIG_WARN_NODE_END(n);
          Printf(e,"%s:%d:%s\n%s:%d:%s\n",Getfile(n),Getline(n),en,
                 Getfile(c),Getline(c),ec);
          Setattr(n,"error",e);
	  Delete(e);
          Delete(en);
          Delete(ec);
        }
      }
    }
    /* restore the class scope if needed */
    if (isfriend) {
      Swig_symbol_setscope(old_scope);
      if (old_prefix) {
	Delete(Namespaceprefix);
	Namespaceprefix = old_prefix;
      }
    }
    Delete(symname);

    if (add_only_one) return;
    n = nextSibling(n);
  }
}


/* add symbols a parse tree node copy */

static void add_symbols_copy(Node *n) {
  String *name;
  int    emode = 0;
  while (n) {
    char *cnodeType = Char(nodeType(n));

    if (strcmp(cnodeType,"access") == 0) {
      String *kind = Getattr(n,"kind");
      if (Strcmp(kind,"public") == 0) {
	cplus_mode = CPLUS_PUBLIC;
      } else if (Strcmp(kind,"private") == 0) {
	cplus_mode = CPLUS_PRIVATE;
      } else if (Strcmp(kind,"protected") == 0) {
	cplus_mode = CPLUS_PROTECTED;
      }
      n = nextSibling(n);
      continue;
    }

    add_oldname = Getattr(n,"sym:name");
    if ((add_oldname) || (Getattr(n,"sym:needs_symtab"))) {
      int old_inclass = -1;
      Node *old_current_class = 0;
      if (add_oldname) {
	DohIncref(add_oldname);
	/*  Disable this, it prevents %rename to work with templates */
	/* If already renamed, we used that name  */
	/*
	if (Strcmp(add_oldname, Getattr(n,"name")) != 0) {
	  Delete(yyrename);
	  yyrename = Copy(add_oldname);
	}
	*/
      }
      Delattr(n,"sym:needs_symtab");
      Delattr(n,"sym:name");

      add_only_one = 1;
      add_symbols(n);

      if (Getattr(n,"partialargs")) {
	Swig_symbol_cadd(Getattr(n,"partialargs"),n);
      }
      add_only_one = 0;
      name = Getattr(n,"name");
      if (Getattr(n,"requires_symtab")) {
	Swig_symbol_newscope();
	Swig_symbol_setscopename(name);
	Delete(Namespaceprefix);
	Namespaceprefix = Swig_symbol_qualifiedscopename(0);
      }
      if (strcmp(cnodeType,"class") == 0) {
	old_inclass = inclass;
	inclass = 1;
	old_current_class = current_class;
	current_class = n;
	if (Strcmp(Getattr(n,"kind"),"class") == 0) {
	  cplus_mode = CPLUS_PRIVATE;
	} else {
	  cplus_mode = CPLUS_PUBLIC;
	}
      }
      if (strcmp(cnodeType,"extend") == 0) {
	emode = cplus_mode;
	cplus_mode = CPLUS_PUBLIC;
      }
      add_symbols_copy(firstChild(n));
      if (strcmp(cnodeType,"extend") == 0) {
	cplus_mode = emode;
      }
      if (Getattr(n,"requires_symtab")) {
	Setattr(n,"symtab", Swig_symbol_popscope());
	Delattr(n,"requires_symtab");
	Delete(Namespaceprefix);
	Namespaceprefix = Swig_symbol_qualifiedscopename(0);
      }
      if (add_oldname) {
	Delete(add_oldname);
	add_oldname = 0;
      }
      if (strcmp(cnodeType,"class") == 0) {
	inclass = old_inclass;
	current_class = old_current_class;
      }
    } else {
      if (strcmp(cnodeType,"extend") == 0) {
	emode = cplus_mode;
	cplus_mode = CPLUS_PUBLIC;
      }
      add_symbols_copy(firstChild(n));
      if (strcmp(cnodeType,"extend") == 0) {
	cplus_mode = emode;
      }
    }
    n = nextSibling(n);
  }
}

/* Check a set of declarations to see if any are pure-abstract */

static List *pure_abstracts(Node *n) {
  List *abstracts = 0;
  while (n) {
    if (Cmp(nodeType(n),"cdecl") == 0) {
      String *decl = Getattr(n,"decl");
      if (SwigType_isfunction(decl)) {
	String *init = Getattr(n,"value");
	if (Cmp(init,"0") == 0) {
	  if (!abstracts) {
	    abstracts = NewList();
	  }
	  Append(abstracts,n);
	  SetFlag(n,"abstract");
	}
      }
    } else if (Cmp(nodeType(n),"destructor") == 0) {
      if (Cmp(Getattr(n,"value"),"0") == 0) {
	if (!abstracts) {
	  abstracts = NewList();
	}
	Append(abstracts,n);
	SetFlag(n,"abstract");
      }
    }
    n = nextSibling(n);
  }
  return abstracts;
}

/* Make a classname */

static String *make_class_name(String *name) {
  String *nname = 0;
  String *prefix;
  if (Namespaceprefix) {
    nname= NewStringf("%s::%s", Namespaceprefix, name);
  } else {
    nname = NewString(name);
  }
  prefix = SwigType_istemplate_templateprefix(nname);
  if (prefix) {
    String *args, *qargs;
    args   = SwigType_templateargs(nname);
    qargs  = Swig_symbol_type_qualify(args,0);
    Append(prefix,qargs);
    Delete(nname);
    Delete(args);
    Delete(qargs);
    nname = prefix;
  }
  return nname;
}

/* Use typedef name as class name */

static void add_typedef_name(Node *n, Node *declnode, String *oldName, Symtab *cscope, String *scpname) {
  String *class_rename = 0;
  SwigType *decl = Getattr(declnode, "decl");
  if (!decl || !Len(decl)) {
    String *cname;
    String *tdscopename;
    String *class_scope = Swig_symbol_qualifiedscopename(cscope);
    String *name = Getattr(declnode, "name");
    cname = Copy(name);
    Setattr(n, "tdname", cname);
    tdscopename = class_scope ? NewStringf("%s::%s", class_scope, name) : Copy(name);
    class_rename = Getattr(n, "class_rename");
    if (class_rename && (Strcmp(class_rename, oldName) == 0))
      Setattr(n, "class_rename", NewString(name));
    if (!classes_typedefs) classes_typedefs = NewHash();
    if (!Equal(scpname, tdscopename) && !Getattr(classes_typedefs, tdscopename)) {
      Setattr(classes_typedefs, tdscopename, n);
    }
    Setattr(n, "decl", decl);
    Delete(class_scope);
    Delete(cname);
    Delete(tdscopename);
  }
}

/* If the class name is qualified.  We need to create or lookup namespace entries */

static Symtab *set_scope_to_global() {
  Symtab *symtab = Swig_symbol_global_scope();
  Swig_symbol_setscope(symtab);
  return symtab;
}
 
/* Remove the block braces, { and }, if the 'noblock' attribute is set.
 * Node *kw can be either a Hash or Parmlist. */
static String *remove_block(Node *kw, const String *inputcode) {
  String *modified_code = 0;
  while (kw) {
   String *name = Getattr(kw,"name");
   if (name && (Cmp(name,"noblock") == 0)) {
     char *cstr = Char(inputcode);
     int len = Len(inputcode);
     if (len && cstr[0] == '{') {
       --len; ++cstr; 
       if (len && cstr[len - 1] == '}') { --len; }
       /* we now remove the extra spaces */
       while (len && isspace((int)cstr[0])) { --len; ++cstr; }
       while (len && isspace((int)cstr[len - 1])) { --len; }
       modified_code = NewStringWithSize(cstr, len);
       break;
     }
   }
   kw = nextSibling(kw);
  }
  return modified_code;
}


static Node *nscope = 0;
static Node *nscope_inner = 0;

/* Remove the scope prefix from cname and return the base name without the prefix.
 * The scopes required for the symbol name are resolved and/or created, if required.
 * For example AA::BB::CC as input returns CC and creates the namespace AA then inner 
 * namespace BB in the current scope. If cname is found to already exist as a weak symbol
 * (forward reference) then the scope might be changed to match, such as when a symbol match 
 * is made via a using reference. */
static String *resolve_create_node_scope(String *cname) {
  Symtab *gscope = 0;
  Node *cname_node = 0;
  int skip_lookup = 0;
  nscope = 0;
  nscope_inner = 0;  

  if (Strncmp(cname,"::",2) == 0)
    skip_lookup = 1;

  cname_node = skip_lookup ? 0 : Swig_symbol_clookup_no_inherit(cname, 0);

  if (cname_node) {
    /* The symbol has been defined already or is in another scope.
       If it is a weak symbol, it needs replacing and if it was brought into the current scope
       via a using declaration, the scope needs adjusting appropriately for the new symbol.
       Similarly for defined templates. */
    Symtab *symtab = Getattr(cname_node, "sym:symtab");
    Node *sym_weak = Getattr(cname_node, "sym:weak");
    if ((symtab && sym_weak) || Equal(nodeType(cname_node), "template")) {
      /* Check if the scope is the current scope */
      String *current_scopename = Swig_symbol_qualifiedscopename(0);
      String *found_scopename = Swig_symbol_qualifiedscopename(symtab);
      int len;
      if (!current_scopename)
	current_scopename = NewString("");
      if (!found_scopename)
	found_scopename = NewString("");
      len = Len(current_scopename);
      if ((len > 0) && (Strncmp(current_scopename, found_scopename, len) == 0)) {
	if (Len(found_scopename) > len + 2) {
	  /* A matching weak symbol was found in non-global scope, some scope adjustment may be required */
	  String *new_cname = NewString(Char(found_scopename) + len + 2); /* skip over "::" prefix */
	  String *base = Swig_scopename_last(cname);
	  Printf(new_cname, "::%s", base);
	  cname = new_cname;
	  Delete(base);
	} else {
	  /* A matching weak symbol was found in the same non-global local scope, no scope adjustment required */
	  assert(len == Len(found_scopename));
	}
      } else {
	String *base = Swig_scopename_last(cname);
	if (Len(found_scopename) > 0) {
	  /* A matching weak symbol was found in a different scope to the local scope - probably via a using declaration */
	  cname = NewStringf("%s::%s", found_scopename, base);
	} else {
	  /* Either:
	      1) A matching weak symbol was found in a different scope to the local scope - this is actually a
	      symbol with the same name in a different scope which we don't want, so no adjustment required.
	      2) A matching weak symbol was found in the global scope - no adjustment required.
	  */
	  cname = Copy(base);
	}
	Delete(base);
      }
      Delete(current_scopename);
      Delete(found_scopename);
    }
  }

  if (Swig_scopename_check(cname)) {
    Node   *ns;
    String *prefix = Swig_scopename_prefix(cname);
    String *base = Swig_scopename_last(cname);
    if (prefix && (Strncmp(prefix,"::",2) == 0)) {
/* I don't think we can use :: global scope to declare classes and hence neither %template. - consider reporting error instead - wsfulton. */
      /* Use the global scope */
      String *nprefix = NewString(Char(prefix)+2);
      Delete(prefix);
      prefix= nprefix;
      gscope = set_scope_to_global();
    }
    if (Len(prefix) == 0) {
      /* Use the global scope, but we need to add a 'global' namespace.  */
      if (!gscope) gscope = set_scope_to_global();
      /* note that this namespace is not the "unnamed" one,
	 and we don't use Setattr(nscope,"name", ""),
	 because the unnamed namespace is private */
      nscope = new_node("namespace");
      Setattr(nscope,"symtab", gscope);;
      nscope_inner = nscope;
      return base;
    }
    /* Try to locate the scope */
    ns = Swig_symbol_clookup(prefix,0);
    if (!ns) {
      Swig_error(cparse_file,cparse_line,"Undefined scope '%s'\n", prefix);
    } else {
      Symtab *nstab = Getattr(ns,"symtab");
      if (!nstab) {
	Swig_error(cparse_file,cparse_line, "'%s' is not defined as a valid scope.\n", prefix);
	ns = 0;
      } else {
	/* Check if the node scope is the current scope */
	String *tname = Swig_symbol_qualifiedscopename(0);
	String *nname = Swig_symbol_qualifiedscopename(nstab);
	if (tname && (Strcmp(tname,nname) == 0)) {
	  ns = 0;
	  cname = base;
	}
	Delete(tname);
	Delete(nname);
      }
      if (ns) {
	/* we will try to create a new node using the namespaces we
	   can find in the scope name */
	List *scopes;
	String *sname;
	Iterator si;
	String *name = NewString(prefix);
	scopes = NewList();
	while (name) {
	  String *base = Swig_scopename_last(name);
	  String *tprefix = Swig_scopename_prefix(name);
	  Insert(scopes,0,base);
	  Delete(base);
	  Delete(name);
	  name = tprefix;
	}
	for (si = First(scopes); si.item; si = Next(si)) {
	  Node *ns1,*ns2;
	  sname = si.item;
	  ns1 = Swig_symbol_clookup(sname,0);
	  assert(ns1);
	  if (Strcmp(nodeType(ns1),"namespace") == 0) {
	    if (Getattr(ns1,"alias")) {
	      ns1 = Getattr(ns1,"namespace");
	    }
	  } else {
	    /* now this last part is a class */
	    si = Next(si);
	    /*  or a nested class tree, which is unrolled here */
	    for (; si.item; si = Next(si)) {
	      if (si.item) {
		Printf(sname,"::%s",si.item);
	      }
	    }
	    /* we get the 'inner' class */
	    nscope_inner = Swig_symbol_clookup(sname,0);
	    /* set the scope to the inner class */
	    Swig_symbol_setscope(Getattr(nscope_inner,"symtab"));
	    /* save the last namespace prefix */
	    Delete(Namespaceprefix);
	    Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	    /* and return the node name, including the inner class prefix */
	    break;
	  }
	  /* here we just populate the namespace tree as usual */
	  ns2 = new_node("namespace");
	  Setattr(ns2,"name",sname);
	  Setattr(ns2,"symtab", Getattr(ns1,"symtab"));
	  add_symbols(ns2);
	  Swig_symbol_setscope(Getattr(ns1,"symtab"));
	  Delete(Namespaceprefix);
	  Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	  if (nscope_inner) {
	    if (Getattr(nscope_inner,"symtab") != Getattr(ns2,"symtab")) {
	      appendChild(nscope_inner,ns2);
	      Delete(ns2);
	    }
	  }
	  nscope_inner = ns2;
	  if (!nscope) nscope = ns2;
	}
	cname = base;
	Delete(scopes);
      }
    }
    Delete(prefix);
  }

  return cname;
}
 
/* look for simple typedef name in typedef list */
static String *try_to_find_a_name_for_unnamed_structure(const char *storage, Node *decls) {
  String *name = 0;
  Node *n = decls;
  if (storage && (strcmp(storage, "typedef") == 0)) {
    for (; n; n = nextSibling(n)) {
      if (!Len(Getattr(n, "decl"))) {
	name = Copy(Getattr(n, "name"));
	break;
      }
    }
  }
  return name;
}

/* traverse copied tree segment, and update outer class links*/
static void update_nested_classes(Node *n)
{
  Node *c = firstChild(n);
  while (c) {
    if (Getattr(c, "nested:outer"))
      Setattr(c, "nested:outer", n);
    update_nested_classes(c);
    c = nextSibling(c);
  }
}

/* -----------------------------------------------------------------------------
 * nested_forward_declaration()
 * 
 * Nested struct handling for C++ code if the nested classes are disabled.
 * Create the nested class/struct/union as a forward declaration.
 * ----------------------------------------------------------------------------- */

static Node *nested_forward_declaration(const char *storage, const char *kind, String *sname, String *name, Node *cpp_opt_declarators) {
  Node *nn = 0;

  if (sname) {
    /* Add forward declaration of the nested type */
    Node *n = new_node("classforward");
    Setattr(n, "kind", kind);
    Setattr(n, "name", sname);
    Setattr(n, "storage", storage);
    Setattr(n, "sym:weak", "1");
    add_symbols(n);
    nn = n;
  }

  /* Add any variable instances. Also add in any further typedefs of the nested type.
     Note that anonymous typedefs (eg typedef struct {...} a, b;) are treated as class forward declarations */
  if (cpp_opt_declarators) {
    int storage_typedef = (storage && (strcmp(storage, "typedef") == 0));
    int variable_of_anonymous_type = !sname && !storage_typedef;
    if (!variable_of_anonymous_type) {
      int anonymous_typedef = !sname && (storage && (strcmp(storage, "typedef") == 0));
      Node *n = cpp_opt_declarators;
      SwigType *type = name;
      while (n) {
	Setattr(n, "type", type);
	Setattr(n, "storage", storage);
	if (anonymous_typedef) {
	  Setattr(n, "nodeType", "classforward");
	  Setattr(n, "sym:weak", "1");
	}
	n = nextSibling(n);
      }
      add_symbols(cpp_opt_declarators);

      if (nn) {
	set_nextSibling(nn, cpp_opt_declarators);
      } else {
	nn = cpp_opt_declarators;
      }
    }
  }

  if (!currentOuterClass || !GetFlag(currentOuterClass, "nested")) {
    if (nn && Equal(nodeType(nn), "classforward")) {
      Node *n = nn;
      if (!GetFlag(n, "feature:ignore")) {
	SWIG_WARN_NODE_BEGIN(n);
	Swig_warning(WARN_PARSE_NAMED_NESTED_CLASS, cparse_file, cparse_line,"Nested %s not currently supported (%s ignored)\n", kind, sname ? sname : name);
	SWIG_WARN_NODE_END(n);
      }
    } else {
      Swig_warning(WARN_PARSE_UNNAMED_NESTED_CLASS, cparse_file, cparse_line, "Nested %s not currently supported (ignored).\n", kind);
    }
  }

  return nn;
}


Node *Swig_cparse(File *f) {
  scanner_file(f);
  top = 0;
  yyparse();
  return top;
}

static void single_new_feature(const char *featurename, String *val, Hash *featureattribs, char *declaratorid, SwigType *type, ParmList *declaratorparms, String *qualifier) {
  String *fname;
  String *name;
  String *fixname;
  SwigType *t = Copy(type);

  /* Printf(stdout, "single_new_feature: [%s] [%s] [%s] [%s] [%s] [%s]\n", featurename, val, declaratorid, t, ParmList_str_defaultargs(declaratorparms), qualifier); */

  /* Warn about deprecated features */
  if (strcmp(featurename, "nestedworkaround") == 0)
    Swig_warning(WARN_DEPRECATED_NESTED_WORKAROUND, cparse_file, cparse_line, "The 'nestedworkaround' feature is deprecated.\n");

  fname = NewStringf("feature:%s",featurename);
  if (declaratorid) {
    fixname = feature_identifier_fix(declaratorid);
  } else {
    fixname = NewStringEmpty();
  }
  if (Namespaceprefix) {
    name = NewStringf("%s::%s",Namespaceprefix, fixname);
  } else {
    name = fixname;
  }

  if (declaratorparms) Setmeta(val,"parms",declaratorparms);
  if (!Len(t)) t = 0;
  if (t) {
    if (qualifier) SwigType_push(t,qualifier);
    if (SwigType_isfunction(t)) {
      SwigType *decl = SwigType_pop_function(t);
      if (SwigType_ispointer(t)) {
	String *nname = NewStringf("*%s",name);
	Swig_feature_set(Swig_cparse_features(), nname, decl, fname, val, featureattribs);
	Delete(nname);
      } else {
	Swig_feature_set(Swig_cparse_features(), name, decl, fname, val, featureattribs);
      }
      Delete(decl);
    } else if (SwigType_ispointer(t)) {
      String *nname = NewStringf("*%s",name);
      Swig_feature_set(Swig_cparse_features(),nname,0,fname,val, featureattribs);
      Delete(nname);
    }
  } else {
    /* Global feature, that is, feature not associated with any particular symbol */
    Swig_feature_set(Swig_cparse_features(),name,0,fname,val, featureattribs);
  }
  Delete(fname);
  Delete(name);
}

/* Add a new feature to the Hash. Additional features are added if the feature has a parameter list (declaratorparms)
 * and one or more of the parameters have a default argument. An extra feature is added for each defaulted parameter,
 * simulating the equivalent overloaded method. */
static void new_feature(const char *featurename, String *val, Hash *featureattribs, char *declaratorid, SwigType *type, ParmList *declaratorparms, String *qualifier) {

  ParmList *declparms = declaratorparms;

  /* remove the { and } braces if the noblock attribute is set */
  String *newval = remove_block(featureattribs, val);
  val = newval ? newval : val;

  /* Add the feature */
  single_new_feature(featurename, val, featureattribs, declaratorid, type, declaratorparms, qualifier);

  /* Add extra features if there are default parameters in the parameter list */
  if (type) {
    while (declparms) {
      if (ParmList_has_defaultargs(declparms)) {

        /* Create a parameter list for the new feature by copying all
           but the last (defaulted) parameter */
        ParmList* newparms = CopyParmListMax(declparms, ParmList_len(declparms)-1);

        /* Create new declaration - with the last parameter removed */
        SwigType *newtype = Copy(type);
        Delete(SwigType_pop_function(newtype)); /* remove the old parameter list from newtype */
        SwigType_add_function(newtype,newparms);

        single_new_feature(featurename, Copy(val), featureattribs, declaratorid, newtype, newparms, qualifier);
        declparms = newparms;
      } else {
        declparms = 0;
      }
    }
  }
}

/* check if a function declaration is a plain C object */
static int is_cfunction(Node *n) {
  if (!cparse_cplusplus || cparse_externc)
    return 1;
  if (Swig_storage_isexternc(n)) {
    return 1;
  }
  return 0;
}

/* If the Node is a function with parameters, check to see if any of the parameters
 * have default arguments. If so create a new function for each defaulted argument. 
 * The additional functions form a linked list of nodes with the head being the original Node n. */
static void default_arguments(Node *n) {
  Node *function = n;

  if (function) {
    ParmList *varargs = Getattr(function,"feature:varargs");
    if (varargs) {
      /* Handles the %varargs directive by looking for "feature:varargs" and 
       * substituting ... with an alternative set of arguments.  */
      Parm     *p = Getattr(function,"parms");
      Parm     *pp = 0;
      while (p) {
	SwigType *t = Getattr(p,"type");
	if (Strcmp(t,"v(...)") == 0) {
	  if (pp) {
	    ParmList *cv = Copy(varargs);
	    set_nextSibling(pp,cv);
	    Delete(cv);
	  } else {
	    ParmList *cv =  Copy(varargs);
	    Setattr(function,"parms", cv);
	    Delete(cv);
	  }
	  break;
	}
	pp = p;
	p = nextSibling(p);
      }
    }

    /* Do not add in functions if kwargs is being used or if user wants old default argument wrapping
       (one wrapped method per function irrespective of number of default arguments) */
    if (compact_default_args 
	|| is_cfunction(function) 
	|| GetFlag(function,"feature:compactdefaultargs") 
	|| (GetFlag(function,"feature:kwargs") && kwargs_supported)) {
      ParmList *p = Getattr(function,"parms");
      if (p) 
        Setattr(p,"compactdefargs", "1"); /* mark parameters for special handling */
      function = 0; /* don't add in extra methods */
    }
  }

  while (function) {
    ParmList *parms = Getattr(function,"parms");
    if (ParmList_has_defaultargs(parms)) {

      /* Create a parameter list for the new function by copying all
         but the last (defaulted) parameter */
      ParmList* newparms = CopyParmListMax(parms,ParmList_len(parms)-1);

      /* Create new function and add to symbol table */
      {
	SwigType *ntype = Copy(nodeType(function));
	char *cntype = Char(ntype);
        Node *new_function = new_node(ntype);
        SwigType *decl = Copy(Getattr(function,"decl"));
        int constqualifier = SwigType_isconst(decl);
	String *ccode = Copy(Getattr(function,"code"));
	String *cstorage = Copy(Getattr(function,"storage"));
	String *cvalue = Copy(Getattr(function,"value"));
	SwigType *ctype = Copy(Getattr(function,"type"));
	String *cthrow = Copy(Getattr(function,"throw"));

        Delete(SwigType_pop_function(decl)); /* remove the old parameter list from decl */
        SwigType_add_function(decl,newparms);
        if (constqualifier)
          SwigType_add_qualifier(decl,"const");

        Setattr(new_function,"name", Getattr(function,"name"));
        Setattr(new_function,"code", ccode);
        Setattr(new_function,"decl", decl);
        Setattr(new_function,"parms", newparms);
        Setattr(new_function,"storage", cstorage);
        Setattr(new_function,"value", cvalue);
        Setattr(new_function,"type", ctype);
        Setattr(new_function,"throw", cthrow);

	Delete(ccode);
	Delete(cstorage);
	Delete(cvalue);
	Delete(ctype);
	Delete(cthrow);
	Delete(decl);

        {
          Node *throws = Getattr(function,"throws");
	  ParmList *pl = CopyParmList(throws);
          if (throws) Setattr(new_function,"throws",pl);
	  Delete(pl);
        }

        /* copy specific attributes for global (or in a namespace) template functions - these are not templated class methods */
        if (strcmp(cntype,"template") == 0) {
          Node *templatetype = Getattr(function,"templatetype");
          Node *symtypename = Getattr(function,"sym:typename");
          Parm *templateparms = Getattr(function,"templateparms");
          if (templatetype) {
	    Node *tmp = Copy(templatetype);
	    Setattr(new_function,"templatetype",tmp);
	    Delete(tmp);
	  }
          if (symtypename) {
	    Node *tmp = Copy(symtypename);
	    Setattr(new_function,"sym:typename",tmp);
	    Delete(tmp);
	  }
          if (templateparms) {
	    Parm *tmp = CopyParmList(templateparms);
	    Setattr(new_function,"templateparms",tmp);
	    Delete(tmp);
	  }
        } else if (strcmp(cntype,"constructor") == 0) {
          /* only copied for constructors as this is not a user defined feature - it is hard coded in the parser */
          if (GetFlag(function,"feature:new")) SetFlag(new_function,"feature:new");
        }

        add_symbols(new_function);
        /* mark added functions as ones with overloaded parameters and point to the parsed method */
        Setattr(new_function,"defaultargs", n);

        /* Point to the new function, extending the linked list */
        set_nextSibling(function, new_function);
	Delete(new_function);
        function = new_function;
	
	Delete(ntype);
      }
    } else {
      function = 0;
    }
  }
}

/* -----------------------------------------------------------------------------
 * mark_nodes_as_extend()
 *
 * Used by the %extend to mark subtypes with "feature:extend".
 * template instances declared within %extend are skipped
 * ----------------------------------------------------------------------------- */

static void mark_nodes_as_extend(Node *n) {
  for (; n; n = nextSibling(n)) {
    if (Getattr(n, "template") && Strcmp(nodeType(n), "class") == 0)
      continue;
    /* Fix me: extend is not a feature. Replace with isextendmember? */
    Setattr(n, "feature:extend", "1");
    mark_nodes_as_extend(firstChild(n));
  }
}


#line 1351 "y.tab.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_YY_Y_TAB_H_INCLUDED
# define YY_YY_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    ID = 258,
    HBLOCK = 259,
    POUND = 260,
    STRING = 261,
    WSTRING = 262,
    INCLUDE = 263,
    IMPORT = 264,
    INSERT = 265,
    CHARCONST = 266,
    WCHARCONST = 267,
    NUM_INT = 268,
    NUM_FLOAT = 269,
    NUM_UNSIGNED = 270,
    NUM_LONG = 271,
    NUM_ULONG = 272,
    NUM_LONGLONG = 273,
    NUM_ULONGLONG = 274,
    NUM_BOOL = 275,
    TYPEDEF = 276,
    TYPE_INT = 277,
    TYPE_UNSIGNED = 278,
    TYPE_SHORT = 279,
    TYPE_LONG = 280,
    TYPE_FLOAT = 281,
    TYPE_DOUBLE = 282,
    TYPE_CHAR = 283,
    TYPE_WCHAR = 284,
    TYPE_VOID = 285,
    TYPE_SIGNED = 286,
    TYPE_BOOL = 287,
    TYPE_COMPLEX = 288,
    TYPE_TYPEDEF = 289,
    TYPE_RAW = 290,
    TYPE_NON_ISO_INT8 = 291,
    TYPE_NON_ISO_INT16 = 292,
    TYPE_NON_ISO_INT32 = 293,
    TYPE_NON_ISO_INT64 = 294,
    LPAREN = 295,
    RPAREN = 296,
    COMMA = 297,
    SEMI = 298,
    EXTERN = 299,
    INIT = 300,
    LBRACE = 301,
    RBRACE = 302,
    PERIOD = 303,
    CONST_QUAL = 304,
    VOLATILE = 305,
    REGISTER = 306,
    STRUCT = 307,
    UNION = 308,
    EQUAL = 309,
    SIZEOF = 310,
    MODULE = 311,
    LBRACKET = 312,
    RBRACKET = 313,
    BEGINFILE = 314,
    ENDOFFILE = 315,
    ILLEGAL = 316,
    CONSTANT = 317,
    NAME = 318,
    RENAME = 319,
    NAMEWARN = 320,
    EXTEND = 321,
    PRAGMA = 322,
    FEATURE = 323,
    VARARGS = 324,
    ENUM = 325,
    CLASS = 326,
    TYPENAME = 327,
    PRIVATE = 328,
    PUBLIC = 329,
    PROTECTED = 330,
    COLON = 331,
    STATIC = 332,
    VIRTUAL = 333,
    FRIEND = 334,
    THROW = 335,
    CATCH = 336,
    EXPLICIT = 337,
    STATIC_ASSERT = 338,
    CONSTEXPR = 339,
    THREAD_LOCAL = 340,
    DECLTYPE = 341,
    AUTO = 342,
    NOEXCEPT = 343,
    OVERRIDE = 344,
    FINAL = 345,
    USING = 346,
    NAMESPACE = 347,
    NATIVE = 348,
    INLINE = 349,
    TYPEMAP = 350,
    EXCEPT = 351,
    ECHO = 352,
    APPLY = 353,
    CLEAR = 354,
    SWIGTEMPLATE = 355,
    FRAGMENT = 356,
    WARN = 357,
    LESSTHAN = 358,
    GREATERTHAN = 359,
    DELETE_KW = 360,
    DEFAULT = 361,
    LESSTHANOREQUALTO = 362,
    GREATERTHANOREQUALTO = 363,
    EQUALTO = 364,
    NOTEQUALTO = 365,
    ARROW = 366,
    QUESTIONMARK = 367,
    TYPES = 368,
    PARMS = 369,
    NONID = 370,
    DSTAR = 371,
    DCNOT = 372,
    TEMPLATE = 373,
    OPERATOR = 374,
    CONVERSIONOPERATOR = 375,
    PARSETYPE = 376,
    PARSEPARM = 377,
    PARSEPARMS = 378,
    CAST = 379,
    LOR = 380,
    LAND = 381,
    OR = 382,
    XOR = 383,
    AND = 384,
    LSHIFT = 385,
    RSHIFT = 386,
    PLUS = 387,
    MINUS = 388,
    STAR = 389,
    SLASH = 390,
    MODULO = 391,
    UMINUS = 392,
    NOT = 393,
    LNOT = 394,
    DCOLON = 395
  };
#endif
/* Tokens.  */
#define ID 258
#define HBLOCK 259
#define POUND 260
#define STRING 261
#define WSTRING 262
#define INCLUDE 263
#define IMPORT 264
#define INSERT 265
#define CHARCONST 266
#define WCHARCONST 267
#define NUM_INT 268
#define NUM_FLOAT 269
#define NUM_UNSIGNED 270
#define NUM_LONG 271
#define NUM_ULONG 272
#define NUM_LONGLONG 273
#define NUM_ULONGLONG 274
#define NUM_BOOL 275
#define TYPEDEF 276
#define TYPE_INT 277
#define TYPE_UNSIGNED 278
#define TYPE_SHORT 279
#define TYPE_LONG 280
#define TYPE_FLOAT 281
#define TYPE_DOUBLE 282
#define TYPE_CHAR 283
#define TYPE_WCHAR 284
#define TYPE_VOID 285
#define TYPE_SIGNED 286
#define TYPE_BOOL 287
#define TYPE_COMPLEX 288
#define TYPE_TYPEDEF 289
#define TYPE_RAW 290
#define TYPE_NON_ISO_INT8 291
#define TYPE_NON_ISO_INT16 292
#define TYPE_NON_ISO_INT32 293
#define TYPE_NON_ISO_INT64 294
#define LPAREN 295
#define RPAREN 296
#define COMMA 297
#define SEMI 298
#define EXTERN 299
#define INIT 300
#define LBRACE 301
#define RBRACE 302
#define PERIOD 303
#define CONST_QUAL 304
#define VOLATILE 305
#define REGISTER 306
#define STRUCT 307
#define UNION 308
#define EQUAL 309
#define SIZEOF 310
#define MODULE 311
#define LBRACKET 312
#define RBRACKET 313
#define BEGINFILE 314
#define ENDOFFILE 315
#define ILLEGAL 316
#define CONSTANT 317
#define NAME 318
#define RENAME 319
#define NAMEWARN 320
#define EXTEND 321
#define PRAGMA 322
#define FEATURE 323
#define VARARGS 324
#define ENUM 325
#define CLASS 326
#define TYPENAME 327
#define PRIVATE 328
#define PUBLIC 329
#define PROTECTED 330
#define COLON 331
#define STATIC 332
#define VIRTUAL 333
#define FRIEND 334
#define THROW 335
#define CATCH 336
#define EXPLICIT 337
#define STATIC_ASSERT 338
#define CONSTEXPR 339
#define THREAD_LOCAL 340
#define DECLTYPE 341
#define AUTO 342
#define NOEXCEPT 343
#define OVERRIDE 344
#define FINAL 345
#define USING 346
#define NAMESPACE 347
#define NATIVE 348
#define INLINE 349
#define TYPEMAP 350
#define EXCEPT 351
#define ECHO 352
#define APPLY 353
#define CLEAR 354
#define SWIGTEMPLATE 355
#define FRAGMENT 356
#define WARN 357
#define LESSTHAN 358
#define GREATERTHAN 359
#define DELETE_KW 360
#define DEFAULT 361
#define LESSTHANOREQUALTO 362
#define GREATERTHANOREQUALTO 363
#define EQUALTO 364
#define NOTEQUALTO 365
#define ARROW 366
#define QUESTIONMARK 367
#define TYPES 368
#define PARMS 369
#define NONID 370
#define DSTAR 371
#define DCNOT 372
#define TEMPLATE 373
#define OPERATOR 374
#define CONVERSIONOPERATOR 375
#define PARSETYPE 376
#define PARSEPARM 377
#define PARSEPARMS 378
#define CAST 379
#define LOR 380
#define LAND 381
#define OR 382
#define XOR 383
#define AND 384
#define LSHIFT 385
#define RSHIFT 386
#define PLUS 387
#define MINUS 388
#define STAR 389
#define SLASH 390
#define MODULO 391
#define UMINUS 392
#define NOT 393
#define LNOT 394
#define DCOLON 395

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 1307 "parser.y" /* yacc.c:355  */

  const char  *id;
  List  *bases;
  struct Define {
    String *val;
    String *rawval;
    int     type;
    String *qualifier;
    String *bitfield;
    Parm   *throws;
    String *throwf;
    String *nexcept;
  } dtype;
  struct {
    const char *type;
    String *filename;
    int   line;
  } loc;
  struct {
    char      *id;
    SwigType  *type;
    String    *defarg;
    ParmList  *parms;
    short      have_parms;
    ParmList  *throws;
    String    *throwf;
    String    *nexcept;
  } decl;
  Parm         *tparms;
  struct {
    String     *method;
    Hash       *kwargs;
  } tmap;
  struct {
    String     *type;
    String     *us;
  } ptype;
  SwigType     *type;
  String       *str;
  Parm         *p;
  ParmList     *pl;
  int           intvalue;
  Node         *node;

#line 1716 "y.tab.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_Y_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 1731 "y.tab.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  60
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   5023

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  141
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  169
/* YYNRULES -- Number of rules.  */
#define YYNRULES  574
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  1122

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   395

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,  1472,  1472,  1484,  1488,  1491,  1494,  1497,  1500,  1505,
    1510,  1515,  1516,  1517,  1518,  1519,  1529,  1545,  1555,  1556,
    1557,  1558,  1559,  1560,  1561,  1562,  1563,  1564,  1565,  1566,
    1567,  1568,  1569,  1570,  1571,  1572,  1573,  1574,  1575,  1582,
    1582,  1664,  1674,  1685,  1706,  1728,  1739,  1748,  1767,  1773,
    1779,  1784,  1791,  1798,  1802,  1815,  1824,  1839,  1852,  1852,
    1908,  1909,  1916,  1935,  1966,  1970,  1980,  1985,  2003,  2046,
    2052,  2065,  2071,  2097,  2103,  2110,  2111,  2114,  2115,  2122,
    2168,  2214,  2225,  2228,  2255,  2261,  2267,  2273,  2281,  2287,
    2293,  2299,  2307,  2308,  2309,  2312,  2317,  2327,  2363,  2364,
    2399,  2416,  2424,  2437,  2462,  2468,  2472,  2475,  2486,  2491,
    2504,  2516,  2806,  2816,  2823,  2824,  2828,  2828,  2853,  2859,
    2871,  2889,  2949,  3007,  3011,  3034,  3038,  3049,  3056,  3063,
    3070,  3079,  3080,  3081,  3085,  3086,  3087,  3098,  3103,  3108,
    3115,  3121,  3126,  3129,  3129,  3142,  3145,  3148,  3157,  3160,
    3167,  3189,  3218,  3316,  3368,  3369,  3370,  3371,  3372,  3373,
    3378,  3378,  3625,  3625,  3770,  3771,  3783,  3801,  3801,  4060,
    4066,  4072,  4075,  4078,  4081,  4084,  4087,  4090,  4095,  4131,
    4135,  4138,  4141,  4146,  4150,  4155,  4165,  4196,  4196,  4225,
    4225,  4247,  4274,  4291,  4296,  4291,  4304,  4305,  4306,  4306,
    4322,  4323,  4340,  4341,  4342,  4343,  4344,  4345,  4346,  4347,
    4348,  4349,  4350,  4351,  4352,  4353,  4354,  4355,  4356,  4365,
    4393,  4420,  4451,  4466,  4483,  4501,  4520,  4539,  4546,  4553,
    4560,  4568,  4576,  4579,  4583,  4586,  4587,  4588,  4589,  4590,
    4591,  4592,  4593,  4596,  4603,  4610,  4619,  4628,  4637,  4649,
    4652,  4655,  4656,  4660,  4662,  4670,  4682,  4683,  4684,  4685,
    4686,  4687,  4688,  4689,  4690,  4691,  4692,  4693,  4694,  4695,
    4696,  4697,  4698,  4699,  4700,  4701,  4708,  4719,  4723,  4726,
    4730,  4734,  4744,  4752,  4760,  4773,  4777,  4780,  4784,  4788,
    4816,  4824,  4836,  4851,  4861,  4870,  4881,  4885,  4889,  4896,
    4913,  4930,  4938,  4946,  4955,  4964,  4968,  4977,  4988,  4999,
    5011,  5021,  5035,  5043,  5052,  5061,  5065,  5074,  5085,  5096,
    5108,  5118,  5128,  5139,  5152,  5159,  5167,  5183,  5191,  5202,
    5213,  5224,  5243,  5251,  5268,  5276,  5283,  5290,  5301,  5312,
    5323,  5343,  5364,  5370,  5376,  5383,  5390,  5399,  5408,  5411,
    5420,  5429,  5436,  5443,  5450,  5460,  5471,  5482,  5493,  5500,
    5507,  5510,  5527,  5537,  5544,  5550,  5555,  5561,  5565,  5571,
    5572,  5573,  5579,  5585,  5589,  5590,  5594,  5601,  5604,  5605,
    5609,  5610,  5612,  5615,  5618,  5623,  5634,  5659,  5662,  5716,
    5720,  5724,  5728,  5732,  5736,  5740,  5744,  5748,  5752,  5756,
    5760,  5764,  5768,  5774,  5774,  5788,  5793,  5796,  5802,  5815,
    5829,  5830,  5833,  5834,  5838,  5844,  5847,  5851,  5856,  5864,
    5876,  5891,  5892,  5911,  5912,  5916,  5921,  5926,  5927,  5932,
    5945,  5960,  5967,  5984,  5991,  5998,  6005,  6013,  6021,  6025,
    6029,  6035,  6036,  6037,  6038,  6039,  6040,  6041,  6042,  6045,
    6049,  6053,  6057,  6061,  6065,  6069,  6073,  6077,  6081,  6085,
    6089,  6093,  6097,  6111,  6115,  6119,  6125,  6129,  6133,  6137,
    6141,  6157,  6162,  6165,  6170,  6175,  6175,  6176,  6179,  6196,
    6205,  6205,  6223,  6223,  6241,  6242,  6243,  6247,  6251,  6255,
    6259,  6265,  6268,  6272,  6278,  6279,  6282,  6285,  6288,  6291,
    6296,  6301,  6306,  6311,  6316,  6323,  6329,  6333,  6337,  6345,
    6353,  6361,  6370,  6379,  6386,  6395,  6396,  6399,  6400,  6401,
    6402,  6405,  6417,  6423,  6432,  6433,  6434,  6437,  6438,  6439,
    6442,  6443,  6446,  6451,  6455,  6458,  6461,  6464,  6467,  6472,
    6476,  6479,  6486,  6492,  6495,  6500,  6503,  6509,  6514,  6518,
    6521,  6524,  6527,  6532,  6536,  6539,  6542,  6548,  6551,  6554,
    6562,  6565,  6568,  6572,  6577,  6590,  6594,  6599,  6605,  6609,
    6614,  6618,  6625,  6628,  6633
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "ID", "HBLOCK", "POUND", "STRING",
  "WSTRING", "INCLUDE", "IMPORT", "INSERT", "CHARCONST", "WCHARCONST",
  "NUM_INT", "NUM_FLOAT", "NUM_UNSIGNED", "NUM_LONG", "NUM_ULONG",
  "NUM_LONGLONG", "NUM_ULONGLONG", "NUM_BOOL", "TYPEDEF", "TYPE_INT",
  "TYPE_UNSIGNED", "TYPE_SHORT", "TYPE_LONG", "TYPE_FLOAT", "TYPE_DOUBLE",
  "TYPE_CHAR", "TYPE_WCHAR", "TYPE_VOID", "TYPE_SIGNED", "TYPE_BOOL",
  "TYPE_COMPLEX", "TYPE_TYPEDEF", "TYPE_RAW", "TYPE_NON_ISO_INT8",
  "TYPE_NON_ISO_INT16", "TYPE_NON_ISO_INT32", "TYPE_NON_ISO_INT64",
  "LPAREN", "RPAREN", "COMMA", "SEMI", "EXTERN", "INIT", "LBRACE",
  "RBRACE", "PERIOD", "CONST_QUAL", "VOLATILE", "REGISTER", "STRUCT",
  "UNION", "EQUAL", "SIZEOF", "MODULE", "LBRACKET", "RBRACKET",
  "BEGINFILE", "ENDOFFILE", "ILLEGAL", "CONSTANT", "NAME", "RENAME",
  "NAMEWARN", "EXTEND", "PRAGMA", "FEATURE", "VARARGS", "ENUM", "CLASS",
  "TYPENAME", "PRIVATE", "PUBLIC", "PROTECTED", "COLON", "STATIC",
  "VIRTUAL", "FRIEND", "THROW", "CATCH", "EXPLICIT", "STATIC_ASSERT",
  "CONSTEXPR", "THREAD_LOCAL", "DECLTYPE", "AUTO", "NOEXCEPT", "OVERRIDE",
  "FINAL", "USING", "NAMESPACE", "NATIVE", "INLINE", "TYPEMAP", "EXCEPT",
  "ECHO", "APPLY", "CLEAR", "SWIGTEMPLATE", "FRAGMENT", "WARN", "LESSTHAN",
  "GREATERTHAN", "DELETE_KW", "DEFAULT", "LESSTHANOREQUALTO",
  "GREATERTHANOREQUALTO", "EQUALTO", "NOTEQUALTO", "ARROW", "QUESTIONMARK",
  "TYPES", "PARMS", "NONID", "DSTAR", "DCNOT", "TEMPLATE", "OPERATOR",
  "CONVERSIONOPERATOR", "PARSETYPE", "PARSEPARM", "PARSEPARMS", "CAST",
  "LOR", "LAND", "OR", "XOR", "AND", "LSHIFT", "RSHIFT", "PLUS", "MINUS",
  "STAR", "SLASH", "MODULO", "UMINUS", "NOT", "LNOT", "DCOLON", "$accept",
  "program", "interface", "declaration", "swig_directive",
  "extend_directive", "$@1", "apply_directive", "clear_directive",
  "constant_directive", "echo_directive", "except_directive", "stringtype",
  "fname", "fragment_directive", "include_directive", "$@2", "includetype",
  "inline_directive", "insert_directive", "module_directive",
  "name_directive", "native_directive", "pragma_directive", "pragma_arg",
  "pragma_lang", "rename_directive", "rename_namewarn",
  "feature_directive", "stringbracesemi", "featattr", "varargs_directive",
  "varargs_parms", "typemap_directive", "typemap_type", "tm_list",
  "tm_tail", "typemap_parm", "types_directive", "template_directive",
  "warn_directive", "c_declaration", "$@3", "c_decl", "c_decl_tail",
  "initializer", "cpp_alternate_rettype", "cpp_lambda_decl",
  "lambda_introducer", "lambda_body", "lambda_tail", "$@4", "c_enum_key",
  "c_enum_inherit", "c_enum_forward_decl", "c_enum_decl",
  "c_constructor_decl", "cpp_declaration", "cpp_class_decl", "@5", "@6",
  "cpp_opt_declarators", "cpp_forward_class_decl", "cpp_template_decl",
  "$@7", "cpp_temp_possible", "template_parms", "templateparameters",
  "templateparameter", "templateparameterstail", "cpp_using_decl",
  "cpp_namespace_decl", "$@8", "$@9", "cpp_members", "$@10", "$@11",
  "$@12", "cpp_member", "cpp_constructor_decl", "cpp_destructor_decl",
  "cpp_conversion_operator", "cpp_catch_decl", "cpp_static_assert",
  "cpp_protection_decl", "cpp_swig_directive", "cpp_end", "cpp_vend",
  "anonymous_bitfield", "anon_bitfield_type", "extern_string",
  "storage_class", "parms", "rawparms", "ptail", "parm", "valparms",
  "rawvalparms", "valptail", "valparm", "def_args", "parameter_declarator",
  "plain_declarator", "declarator", "notso_direct_declarator",
  "direct_declarator", "abstract_declarator", "direct_abstract_declarator",
  "pointer", "type_qualifier", "type_qualifier_raw", "type", "rawtype",
  "type_right", "decltype", "primitive_type", "primitive_type_list",
  "type_specifier", "definetype", "$@13", "default_delete",
  "deleted_definition", "explicit_default", "ename",
  "optional_constant_directive", "enumlist", "edecl", "etype", "expr",
  "valexpr", "exprnum", "exprcompound", "ellipsis", "variadic", "inherit",
  "raw_inherit", "$@14", "base_list", "base_specifier", "@15", "@16",
  "access_specifier", "templcpptype", "cpptype", "opt_virtual",
  "virt_specifier_seq", "exception_specification", "cpp_const", "ctor_end",
  "ctor_initializer", "mem_initializer_list", "mem_initializer",
  "less_valparms_greater", "identifier", "idstring", "idstringopt",
  "idcolon", "idcolontail", "idtemplate", "idtemplatetemplate",
  "idcolonnt", "idcolontailnt", "string", "wstring", "stringbrace",
  "options", "kwargs", "stringnum", "empty", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395
};
# endif

#define YYPACT_NINF -904

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-904)))

#define YYTABLE_NINF -575

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     692,  4117,  4189,   300,    64,  3607,  -904,  -904,  -904,  -904,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,  -904,  -904,  -904,  -904,  -904,   110,  -904,  -904,  -904,
    -904,  -904,     5,   117,   141,   129,  -904,  -904,   -49,   -20,
     132,    96,   176,  4834,   793,  1218,   793,  -904,  -904,  -904,
    2093,  -904,    96,   132,  -904,   -32,  -904,   255,   266,  4551,
    -904,   140,  -904,  -904,  -904,   303,  -904,  -904,    37,   314,
    4261,   337,  -904,  -904,   314,   357,   364,   372,   475,  -904,
    -904,   380,   367,   356,    18,   519,   722,   431,   175,   479,
     406,   285,  4622,  4622,   487,   493,   529,   507,   407,  -904,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,   314,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,  1580,  -904,  -904,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,    39,  4693,  -904,
     517,  -904,  -904,   536,   545,    96,    41,   384,  2135,  -904,
    -904,  -904,   793,  -904,  3279,   547,    77,  2269,  3073,    44,
    1338,  2275,   163,    96,  -904,  -904,   231,   159,   231,   306,
    1677,   486,  -904,  -904,  -904,  -904,  -904,   113,   136,  -904,
    -904,  -904,   556,  -904,   562,  -904,  -904,   425,  -904,  -904,
     384,   198,   425,   425,  -904,   580,  1698,  -904,    98,  1184,
      96,   113,   113,  -904,   425,  4479,  -904,  -904,  4551,  -904,
    -904,  -904,  -904,  -904,    96,    27,  -904,   139,   582,   113,
    -904,  -904,   425,   113,  -904,  -904,  -904,   624,  4551,   590,
    1044,   597,   602,   425,   529,   624,  4551,  4551,    96,   529,
    2089,   484,   911,   425,   387,   530,  -904,  -904,  1698,    96,
    1786,   226,  -904,   600,   604,   629,   113,  -904,  -904,   -32,
     579,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,  -904,  3073,   169,  3073,  3073,  3073,  3073,  3073,  3073,
    3073,  -904,   581,  -904,   652,   661,   354,  3022,     8,  -904,
    -904,   624,   706,  -904,  -904,  3392,  1017,  1017,   697,   702,
     280,   617,   700,  -904,  -904,  -904,   703,  3073,  -904,  -904,
    -904,  -904,  4265,  -904,  3022,   711,  3392,   709,    96,   326,
     306,  -904,   715,   326,   306,  -904,   625,  -904,  -904,  4551,
    2403,  -904,  4551,  2537,   723,  2409,  2543,   326,   306,   665,
    2223,  -904,  -904,   -32,   734,  4551,  -904,  -904,  -904,  -904,
     741,   624,    96,  -904,  -904,   344,   743,  -904,  -904,   138,
     231,   483,  -904,   744,   745,   746,   739,   623,   756,   758,
    -904,   760,   762,  -904,  4764,  -904,    96,  -904,   765,   779,
    -904,   781,   790,  4622,  -904,  -904,  -904,  -904,  -904,  4622,
    -904,  -904,  -904,   791,  -904,  -904,   646,   217,   795,   730,
    -904,   797,  -904,    13,  -904,  -904,   112,  1354,  1354,  1354,
     351,   729,   807,   158,   806,  1090,  1124,   735,  2223,   747,
      24,   794,   268,  -904,  3464,  1934,  -904,   821,  -904,   292,
    -904,  -904,  -904,  -904,   132,  -904,   384,  2638,  4764,   827,
    1969,  2888,  -904,  -904,  -904,  -904,  -904,  -904,  2135,  -904,
    -904,  -904,  3073,  3073,  3073,  3073,  3073,  3073,  3073,  3073,
    3073,  3073,  3073,  3073,  3073,  3073,  3073,  3073,  3073,  -904,
     334,   334,  1683,   753,   578,  -904,   586,  -904,  -904,   334,
     334,   601,   766,  1354,  1354,  3073,  3022,  -904,  4551,   472,
      17,   828,  -904,  4551,  2671,   835,  -904,   843,  -904,  4626,
     844,  -904,  4713,   842,   847,   326,   306,   848,   326,   306,
    1813,   851,   855,  1126,   326,  -904,  -904,   562,   216,  -904,
    -904,   425,  1824,  -904,   849,   863,  -904,  -904,  -904,   494,
    1273,  2491,   866,  4551,  1698,   862,  -904,  1044,  3709,   868,
    -904,   363,  4622,   419,   869,   870,   602,   561,   876,   425,
    4551,   131,   822,  4551,  -904,  -904,  -904,  1354,  1365,  1524,
      38,  -904,  2357,  4904,   867,  4834,   439,  -904,   879,   729,
     887,   191,   840,   850,   257,  -904,   939,  -904,   231,   853,
    -904,  -904,   886,  -904,    96,  3073,  2805,  2939,  3207,    69,
    1218,   894,   652,   694,   694,  1977,  1977,  2509,  4050,  1969,
    2238,  2646,  2888,  1007,  1007,   728,   728,  -904,  -904,  -904,
     766,  -904,  -904,  -904,  -904,   334,   627,   159,  4838,   904,
     632,   766,  -904,  1524,  1524,   917,  -904,  4850,  1524,  -904,
    -904,  -904,  -904,  1524,   912,   913,   915,   916,  1215,   326,
     306,   923,   925,   926,   326,  -904,  -904,  -904,   624,  3811,
    -904,   935,  -904,   217,   938,  -904,  -904,  1968,  -904,  -904,
     624,  -904,  -904,  -904,   941,  -904,  1068,   624,  -904,   928,
      35,   688,  1273,  -904,  1068,  -904,   943,  -904,  -904,  3913,
      53,  4764,   318,  -904,  -904,  4551,  -904,  -904,   854,  -904,
     219,   881,  -904,   946,   942,  -904,    96,  2159,   797,  -904,
    1068,   289,  1524,  -904,  -904,  -904,  1934,  -904,  -904,  -904,
    -904,   453,  -904,  -904,   929,   767,  4551,  3073,  -904,  -904,
    -904,  -904,  1698,  -904,  -904,  -904,  -904,   231,  -904,  -904,
     953,  -904,   805,  -904,  1968,  -904,   231,  3022,  3073,  3073,
    3207,  3534,  3073,   947,   961,   963,   966,  -904,  3073,  -904,
    -904,  -904,  -904,   699,   326,  -904,  -904,   326,   326,  1524,
    1524,   959,   964,   965,   326,  1524,   970,   973,  -904,   425,
     425,  -904,  -904,   978,   933,   955,   957,   873,   994,   113,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,   988,  1968,  -904,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,  4332,   991,  4551,   415,  -904,   131,  -904,  1824,  1434,
     425,   998,  -904,  1068,   997,  -904,  -904,   624,  1698,    25,
    -904,  4622,  -904,  1002,   215,   113,   291,  -904,  2135,   188,
    -904,   996,    37,   737,  -904,  -904,  -904,  -904,  -904,  -904,
    -904,  -904,  4404,  -904,  4015,  1008,  -904,   257,  4551,  -904,
     468,  -904,   113,   481,  -904,  4551,   483,   999,   976,  -904,
    1014,  2754,  1934,  -904,   853,  -904,  -904,  -904,    96,  -904,
    1011,  1968,  -904,  3022,  3022,  3022,  3073,  3073,  -904,  4764,
    3245,  -904,   326,   326,  1524,  1012,  1016,   326,  1524,  1524,
    -904,  -904,  1968,  -904,  -904,  -904,  -904,   113,  -904,  1019,
    -904,  -904,   995,  1000,  1001,  4764,  1003,  1818,  1004,   247,
    1031,  -904,  -904,   624,  1033,  -904,  1068,  1447,   131,  -904,
    1030,  -904,  1040,  -904,  -904,   219,  -904,  -904,   219,   982,
    -904,  -904,  4764,  4551,  1698,  -904,  -904,  -904,  1046,  -904,
    -904,  -904,   929,  1035,   929,  1618,  1050,  1051,   483,    96,
     511,  -904,  -904,  -904,   257,  -904,  1047,   853,  1642,  1053,
    3022,  3022,  1218,   326,  1524,  1524,   326,   326,  -904,  1968,
    1069,  4551,    71,  3073,  3464,  -904,  1065,  -904,  1067,  -904,
    1068,  -904,  -904,  -904,  -904,  -904,  1070,  1044,  1024,  1068,
    1073,  -904,  3073,   113,  -904,  1934,   534,  -904,  1077,  1081,
    1083,   461,  -904,  -904,  -904,  1087,  -904,  -904,  -904,    96,
    -904,  -904,  1934,  1642,  1096,   326,   326,  1097,  4551,  1104,
    4551,  1106,  1110,    16,  2905,  1111,  -904,  -904,  1117,  -904,
    1118,  -904,    51,  -904,  -904,  3022,   929,   257,  -904,  -904,
    -904,    96,  1105,  -904,  -904,  1114,  1047,   257,  -904,  -904,
    -904,  1113,  1068,  1127,  4551,  4551,  4551,  1129,  -904,   767,
    -904,  -904,  4764,   468,  -904,  -904,  1119,  1136,  -904,  -904,
    -904,  1968,  1068,  -904,   333,  1068,  1134,  1153,  1155,  4551,
    -904,  1151,  -904,  1150,  -904,  -904,  -904,   418,  -904,  -904,
     483,  -904,  1068,  1068,  1068,  1163,   468,  1160,  -904,  -904,
     483,  1167,  -904,  -904,  -904,  1068,  -904,  -904,  1168,  -904,
    -904,  -904
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
     574,     0,     0,     0,     0,     0,    10,     4,   524,   389,
     397,   390,   391,   394,   395,   392,   393,   379,   396,   378,
     398,   381,   399,   400,   401,   402,     0,   369,   370,   371,
     492,   493,   145,   487,   488,     0,   525,   526,     0,     0,
     536,     0,     0,     0,   367,   574,   374,   384,   377,   386,
     387,   491,     0,   543,   382,   534,     6,     0,     0,   574,
       1,    15,    64,    60,    61,     0,   261,    14,   256,   574,
       0,     0,    82,    83,   574,   574,     0,     0,   260,   262,
     263,     0,   264,   265,   270,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     9,
      11,    18,    19,    20,    21,    22,    23,    24,    25,   574,
      26,    27,    28,    29,    30,    31,    32,     0,    33,    34,
      35,    36,    37,    38,    12,   113,   118,   115,   114,    16,
      13,   154,   155,   156,   157,   158,   159,   257,     0,   275,
       0,   147,   146,     0,     0,     0,     0,     0,   574,   537,
     380,     3,   373,   368,   574,     0,   403,     0,     0,   536,
     352,   351,   366,     0,   298,   281,   574,   305,   574,   348,
     342,   332,   295,   375,   388,   383,   544,     0,     0,   532,
       5,     8,     0,   276,   574,   278,    17,     0,   558,   273,
       0,   255,     0,     0,   565,     0,     0,   372,   543,     0,
       0,     0,     0,    78,     0,   574,   268,   272,   574,   266,
     269,   267,   274,   271,     0,     0,   189,   543,     0,     0,
      62,    63,     0,     0,    51,    49,    46,    47,   574,     0,
     574,     0,   574,   574,     0,   112,   574,   574,     0,     0,
       0,     0,     0,     0,     0,   332,   259,   258,     0,   574,
       0,   574,   283,     0,     0,     0,     0,   538,   545,   535,
       0,   560,   429,   430,   441,   442,   443,   444,   445,   446,
     447,   448,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   289,     0,   284,   574,   422,   372,     0,   421,   423,
     427,   424,   428,   286,   376,   574,   352,   351,     0,     0,
     342,   382,     0,   293,   408,   409,   291,     0,   405,   406,
     407,   358,     0,   421,   294,     0,   574,     0,     0,   307,
     350,   324,     0,   306,   349,   364,   365,   333,   296,   574,
       0,   297,   574,     0,     0,   345,   344,   302,   343,   324,
     353,   542,   541,   540,     0,     0,   277,   280,   528,   527,
       0,   529,     0,   557,   116,   568,     0,    68,    45,     0,
     574,   403,    70,     0,     0,     0,    74,     0,     0,     0,
      98,     0,     0,   185,     0,   574,     0,   187,     0,     0,
     103,     0,     0,     0,   107,   299,   300,   301,    42,     0,
     104,   106,   530,     0,   531,    54,     0,    53,     0,     0,
     178,   574,   182,   491,   180,   169,     0,     0,     0,     0,
     527,     0,     0,     0,     0,     0,     0,   324,     0,     0,
     332,   574,   543,   411,   574,   574,   475,     0,   474,   383,
     477,   489,   490,   385,     0,   533,     0,     0,     0,     0,
     439,   438,   467,   466,   440,   468,   469,   523,     0,   285,
     288,   470,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   559,
     352,   351,   342,   382,     0,   332,     0,   362,   360,   345,
     344,     0,   332,   353,     0,     0,   404,   359,   574,   342,
     382,     0,   325,   574,     0,     0,   363,     0,   338,     0,
       0,   356,     0,     0,     0,   304,   347,     0,   303,   346,
     354,     0,     0,     0,   308,   539,     7,   574,     0,   170,
     574,     0,     0,   564,     0,     0,    69,    39,    77,     0,
       0,     0,     0,     0,     0,     0,   186,   574,     0,     0,
     574,   574,     0,     0,   108,     0,   574,     0,     0,     0,
       0,     0,   167,     0,   179,   184,    58,     0,     0,     0,
       0,    79,     0,     0,     0,     0,     0,   149,     0,   382,
       0,   501,   496,   497,     0,   127,   574,   502,   574,   574,
     162,   166,     0,   546,     0,   431,     0,     0,   366,     0,
     574,     0,   574,   464,   463,   461,   462,     0,   460,   459,
     455,   456,   454,   457,   458,   449,   450,   451,   452,   453,
       0,   353,   336,   335,   334,   354,     0,   315,     0,     0,
       0,   324,   326,   353,     0,     0,   329,     0,     0,   340,
     339,   361,   357,     0,     0,     0,     0,     0,     0,   309,
     355,     0,     0,     0,   311,   279,    66,    67,    65,     0,
     569,   570,   573,   572,   566,    44,    43,     0,    76,    73,
      75,   563,    93,   562,     0,    88,   574,   561,    92,     0,
     572,     0,     0,    99,   574,   227,     0,   190,   191,     0,
     256,     0,     0,    50,    48,   574,    41,   105,     0,   551,
     549,     0,    57,     0,     0,   110,     0,   574,   574,   574,
     574,     0,     0,   133,   132,   134,   574,   136,   131,   135,
     140,     0,   148,   150,   574,   574,   574,     0,   503,   499,
     498,   126,     0,   123,   125,   121,   128,   574,   129,   494,
     476,   478,   480,   495,     0,   160,   574,   432,     0,     0,
     366,   365,     0,     0,     0,     0,     0,   287,     0,   337,
     292,   341,   327,     0,   317,   331,   330,   316,   312,     0,
       0,     0,     0,     0,   310,     0,     0,     0,   117,     0,
       0,   198,   218,     0,     0,     0,     0,   262,     0,     0,
     240,   241,   233,   242,   216,   196,   238,   234,   232,   235,
     236,   237,   239,   217,   213,   214,   200,   208,   207,   211,
     210,     0,     0,   201,   202,   206,   212,   203,   204,   205,
     215,     0,   275,   574,   505,   506,     0,   508,     0,     0,
       0,     0,    90,   574,     0,   119,   188,   255,     0,   543,
     101,     0,   100,     0,     0,     0,     0,   547,   574,     0,
      52,     0,   256,     0,   171,   172,   176,   175,   168,   173,
     177,   174,     0,   183,     0,     0,    81,     0,   574,   141,
       0,   412,   417,     0,   413,   574,   403,   506,   574,   153,
       0,     0,   574,   130,   574,   485,   484,   486,     0,   482,
       0,     0,   282,   435,   434,   433,     0,     0,   425,     0,
     465,   328,   314,   313,     0,     0,     0,   318,     0,     0,
     571,   567,     0,   193,   230,   229,   231,     0,   228,     0,
      40,   192,   379,   378,   381,     0,     0,     0,   377,   382,
       0,   507,    84,   572,    95,    89,   574,     0,     0,    97,
       0,    71,     0,   109,   552,   550,   556,   555,   554,     0,
      55,    56,     0,   574,     0,    59,    80,   122,     0,   143,
     142,   139,   574,   418,   574,     0,     0,     0,     0,     0,
       0,   516,   500,   504,     0,   479,   574,   574,     0,     0,
     437,   436,   574,   319,     0,     0,   323,   322,   199,     0,
       0,   574,     0,     0,   574,   209,     0,    96,     0,    91,
     574,    86,    72,   102,   548,   553,     0,   574,     0,   574,
       0,   416,     0,   415,   151,   574,     0,   513,     0,   515,
     517,     0,   509,   510,   124,     0,   472,   481,   473,     0,
     164,   163,   574,     0,     0,   321,   320,     0,   574,     0,
     574,     0,     0,     0,     0,     0,    94,    85,     0,   111,
       0,   167,     0,   144,   419,   420,   574,     0,   511,   512,
     514,     0,     0,   521,   522,     0,   574,     0,   161,   426,
     194,     0,   574,     0,   574,   574,   574,     0,   249,   574,
      87,   120,     0,     0,   414,   152,   518,     0,   471,   483,
     165,     0,   574,   220,     0,   574,     0,     0,     0,   574,
     219,     0,   137,     0,   519,   195,   221,     0,   243,   245,
       0,   226,   574,   574,   574,     0,     0,     0,   246,   248,
     403,     0,   224,   223,   222,   574,   138,   520,     0,   244,
     225,   247
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -904,  -904,  -344,  -904,  -904,  -904,  -904,    43,    47,    -4,
      56,  -904,   690,  -904,    58,    62,  -904,  -904,  -904,    67,
    -904,    68,  -904,    75,  -904,  -904,    79,  -904,    82,  -523,
    -642,    83,  -904,    93,  -904,  -351,   674,   -79,    95,   101,
     115,   116,  -904,   532,  -811,  -666,  -904,  -904,  -904,  -867,
    -748,  -904,  -130,  -904,  -904,  -904,  -904,  -904,     7,  -904,
    -904,   203,    11,    12,  -904,  -904,   293,  -904,   681,   537,
     121,  -904,  -904,  -904,  -708,  -904,  -904,  -904,  -904,   541,
    -904,   552,   124,   557,  -904,  -904,  -904,  -533,  -904,  -904,
    -904,    -2,    60,  -904,   725,    22,   422,  -904,   664,   796,
     -34,  -572,  -531,   -40,  1162,  -133,  -144,   -57,    26,   -37,
    -904,   -56,    33,   -22,   698,  -524,  1203,  -904,  -357,  -904,
    -154,  -904,  -904,  -904,  -903,  -904,   254,  -904,  1142,  -118,
    -489,  -904,  -904,   209,   839,  -904,  -904,  -904,   396,  -904,
    -904,  -904,  -222,   -33,   304,   707,  -398,  -573,   211,  -904,
    -904,   230,   -15,   984,   -97,  -904,   951,  -193,  -124,  1107,
    -904,  -323,   701,  -904,   606,   239,  -202,  -512,     0
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     4,     5,    99,   100,   101,   657,   780,   781,   782,
     783,   106,   395,   396,   784,   785,   699,   109,   110,   786,
     112,   787,   114,   788,   659,   202,   789,   117,   790,   665,
     532,   791,   369,   792,   379,   231,   390,   232,   793,   794,
     795,   796,   520,   125,   725,   574,   706,   126,   711,   860,
     951,  1000,    41,   566,   127,   128,   129,   130,   797,   881,
     734,  1021,   798,   799,   697,   848,   399,   400,   401,   554,
     800,   135,   540,   375,   801,   979,  1081,   902,   802,   803,
     804,   805,   806,   807,   808,   809,  1083,  1096,   810,   916,
     137,   811,   298,   183,   346,   184,   282,   283,   449,   284,
     575,   165,   384,   166,   319,   167,   168,   169,   244,    43,
      44,   285,   197,    46,    47,    48,    49,    50,   306,   307,
     348,   309,   310,   421,   862,   863,   952,  1044,   287,   313,
     289,   290,  1016,  1017,   427,   428,   579,   730,   731,   878,
     967,   879,    51,    52,   732,   577,   815,  1097,   869,   960,
    1009,  1010,   176,    53,   355,   393,    54,   179,    55,   259,
     691,   837,   291,   292,   668,   193,   356,   654,   185
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
       6,   104,   308,   138,   525,   139,   676,   153,   249,   173,
     299,   164,   131,   229,   196,   403,   132,   133,   745,   671,
     380,   152,   258,    42,    57,   149,   880,   578,   695,   821,
     288,   538,   545,   652,    45,    45,   230,   230,   412,   708,
     857,   353,   652,   188,     8,   172,   947,   315,   102,  1001,
    -290,  1003,   103,   341,   258,  -181,  1066,   141,   622,   188,
     246,   105,   212,   107,    60,   238,   435,   108,   931,   194,
     373,   170,   111,   113,   194,   203,   142,   243,   564,   622,
     115,   374,   250,   147,   116,   177,   386,   118,   119,  -529,
     350,   146,    45,   816,   911,   213,   357,   859,   120,     8,
     121,   824,   363,   320,   324,   251,   122,   367,   178,   194,
     742,  1030,  -290,   338,   260,   294,     8,  -181,   353,   182,
     123,   124,   189,   303,   247,   326,   134,   855,   148,   136,
      36,    37,   328,   623,   331,   661,   392,   188,   189,     8,
     418,     8,   868,  1074,   149,  1067,   414,   148,   293,   822,
     515,   299,   361,  1014,   702,   190,   360,   352,   140,   256,
     257,     8,  1072,   474,   476,   143,   172,   481,   172,   145,
     281,   556,   299,   969,   662,  1073,   649,   663,   727,   220,
     300,   286,   304,   305,   347,    36,    37,    45,   325,   144,
     385,   682,   940,   376,   978,   743,   679,  1031,   744,   329,
    1032,   148,    36,    37,   353,   162,   964,   308,   419,   438,
     425,    38,    27,    28,    29,    40,   330,   439,     8,   151,
     646,   221,   188,   353,  1106,    36,    37,    36,    37,     8,
     387,   717,   391,   394,   941,   148,  1075,   404,    45,   320,
     324,    45,   148,   338,   354,   664,  1080,    36,    37,   423,
     928,   430,   164,    38,   256,   342,   170,    40,   721,   402,
     186,    45,   647,   550,   407,   370,   409,   408,   371,    45,
      45,  1027,   162,    38,   474,   476,   481,    40,   506,   509,
     572,   573,   987,     8,   450,   156,   172,   918,   382,   226,
     985,   188,   162,   922,     8,   353,   398,   162,   180,   722,
     723,    58,   426,   724,    36,    37,   924,   158,   578,   181,
     546,  -410,   170,   200,  -410,    36,    37,   867,   537,   650,
     154,   472,   661,  -254,   188,  1092,   524,   230,    45,   652,
     288,   403,   856,   230,   934,   581,   835,   157,  -574,  1047,
      59,    38,   489,   187,  -410,    40,   332,   693,   239,    45,
     616,   617,   496,   988,   192,   854,  1057,     8,  1116,   836,
     172,   830,    45,   333,   663,    45,   493,   517,   426,    36,
      37,   148,   831,  1095,   295,     6,  1098,   199,    45,  1099,
      36,    37,   590,   494,    66,   409,   521,  1100,   576,   497,
       8,   157,   500,   386,   154,    38,  -574,   201,   522,   159,
    1024,   555,   155,   584,   204,   991,   479,   680,   156,   480,
     937,   157,   205,   320,   324,   338,   921,  1038,   163,   583,
     208,   567,   506,   509,   616,   172,  1042,   413,     8,   430,
     158,   188,   338,   210,   669,   334,    30,    31,   211,   559,
      78,    79,    80,    36,    37,    82,   223,    83,    84,   224,
     409,   209,   225,   640,   148,    33,    34,    45,  -574,    30,
      31,  1108,   683,   589,  1109,   684,  1040,  -543,  -543,    38,
     281,   219,  1110,   159,   578,     8,    36,    37,    33,    34,
     160,   286,   713,   161,   568,   714,   230,     8,   162,  1084,
     666,  -543,   163,   858,   674,   570,   868,   385,   658,   859,
     188,  1053,    38,   571,   572,   573,    40,  1054,   949,   957,
     237,   950,   316,   415,    36,    37,   416,   347,   700,   222,
       6,    45,     8,   954,   413,   318,    45,   233,   955,   157,
     304,   305,   317,   234,   104,   188,   138,   387,   139,   681,
       6,   139,   726,   712,   728,   131,   391,   236,   619,   132,
     133,   741,  1101,   625,  1012,   673,   164,  1013,   640,   206,
     207,    36,    37,   170,     8,   252,    45,   900,   901,  1112,
    1113,  1114,   694,    36,    37,   402,   172,  1048,   172,   733,
    1049,   102,  1120,    45,   253,   103,    45,    38,   304,   305,
     172,    40,   450,   254,   105,   302,   107,   344,   479,    38,
     108,   480,   340,    40,   345,   111,   113,   578,    36,    37,
     318,   214,   994,   115,   325,   995,   170,   116,   329,   612,
     118,   119,   318,   358,   578,   828,   329,   613,   377,   814,
     353,   120,   823,   121,    38,   330,   383,   814,    40,   122,
     388,   329,   614,   330,   389,   104,   418,   138,   431,   139,
      36,    37,   432,   123,   124,   909,   131,   812,   330,   134,
     132,   133,   136,   814,   530,   531,   817,   329,   749,   576,
     433,   867,   493,   752,   817,   104,   688,   138,   814,   139,
     689,   249,   872,   436,   330,   447,   131,   548,   549,   494,
     132,   133,   102,   873,   448,   852,   103,   139,   555,     6,
     817,   451,   882,   741,   845,   105,   172,   107,   846,   847,
     861,   108,   308,   469,   864,   817,   111,   113,    45,   152,
     288,   403,   102,   669,   115,     8,   103,   172,   116,   819,
     820,   118,   119,   483,   812,   105,   172,   107,   477,   493,
     891,   108,   120,   478,   121,   833,   111,   113,   484,    45,
     122,   488,   932,  1118,   115,   917,   494,   491,   116,   162,
     485,   118,   119,   495,   123,   124,   325,   496,   216,   191,
     134,   503,   120,   136,   121,   230,   870,   516,   251,   926,
     122,   510,   518,   980,   523,   526,   814,   528,   930,    30,
      31,   527,   227,   529,   123,   124,   917,   235,   533,   534,
     134,   535,   812,   136,  1008,   536,   541,   865,    33,    34,
     238,    36,    37,     1,     2,     3,    27,    28,    29,   251,
     542,   866,   543,   817,   462,   463,   464,   465,   466,   467,
     468,   544,   547,   972,   552,   576,   551,    38,   293,   553,
     943,    40,    27,    28,    29,   557,    45,   570,   558,   561,
     104,   562,   138,   386,   139,   571,   572,   573,   563,   982,
     281,   131,   466,   467,   468,   132,   133,   580,   961,   611,
     565,   286,   172,   920,   733,   591,   624,   425,   875,   876,
     877,   812,   615,   628,   629,   631,   997,   990,   351,   814,
     633,    45,   655,   351,   351,   634,   635,   102,    45,   641,
     351,   103,   812,   642,   419,   351,   656,   672,   675,   685,
     105,   678,   107,   696,     8,  1005,   108,   686,   948,   692,
     715,   111,   113,   351,   710,   956,   817,   716,  1022,   115,
     719,   729,   735,   116,   351,   397,   118,   119,   164,   720,
     406,   351,   746,   404,   351,   751,  1111,   120,   861,   121,
     861,   413,   864,   814,   864,   122,   308,   385,   755,   322,
     759,   760,   814,   761,   762,   402,  1018,   733,   576,   123,
     124,   765,   172,   766,   767,   134,    45,   769,   136,   812,
     770,   813,   818,  1022,   838,   576,   825,   839,   886,   840,
     817,    70,   150,   156,   834,   874,   171,   387,   170,   817,
      36,    37,   887,   175,   888,   172,   889,   894,  1033,   904,
     409,   907,   895,   896,    45,   158,  1091,    45,   898,   570,
       8,   899,   172,   170,   903,   814,    38,   571,   572,   573,
      40,   905,   814,   906,   908,   910,   215,   218,  -197,   927,
     929,  1029,   861,   933,  1035,   814,   864,     8,   814,   318,
     942,   946,   959,   958,   198,   962,  1018,   154,   968,   981,
     974,    45,   817,    45,   975,   814,   814,   814,   245,   817,
     217,  -252,   986,   992,   157,   820,  -251,  -253,   814,   983,
    -250,   812,   817,   993,   154,   817,   996,   999,  1061,  1002,
    1063,  1006,   155,     8,  1007,  1015,   255,    45,    45,    45,
    1023,   157,   817,   817,   817,   301,    36,    37,  1036,  1028,
    1037,   321,   321,  1039,   327,   817,  1043,    27,    28,    29,
    1050,   339,    45,  1051,  1086,  1087,  1088,     8,  1041,     8,
     413,  1052,    38,    36,    37,  1055,   159,  1059,   504,   464,
     465,   466,   467,   468,  1060,  1062,  1064,   245,   570,  1105,
    1065,   364,  1069,  1077,  1082,   163,   571,   572,   573,    38,
    1070,  1071,  1078,   159,   413,   372,   413,  1093,  1085,  1089,
     160,   349,   507,   161,   643,  1102,   349,   349,   162,    36,
      37,   171,   163,   349,  1094,   365,   366,     8,   349,   405,
     188,   411,   321,   321,  1103,   417,  1104,   859,  1107,   420,
     150,   245,   429,   378,  1115,    38,   349,   381,  1117,    40,
    1119,  1121,   651,    36,    37,    36,    37,   349,     8,   648,
     687,     8,   351,   653,   410,   362,  1058,   349,   318,   844,
     660,   667,   670,   422,   698,   853,   998,   171,   849,    38,
     434,    38,   645,    40,   592,    40,   473,   475,   475,   850,
     351,   482,   667,   174,   851,   413,   747,  1046,   154,   701,
     939,   707,   318,   763,   318,  1079,   155,   490,   582,   492,
     965,  1019,   156,    36,    37,   157,     8,   661,   718,   188,
    1090,  1076,     0,     0,     0,   343,   321,   321,   832,   304,
     305,   321,     0,     0,   158,     0,     0,     0,     0,   312,
     314,     0,     0,   519,    36,    37,     0,    36,    37,     0,
     411,     0,     0,   359,     0,     0,   662,     0,     0,   663,
       0,   155,     0,   323,     0,     0,     0,   539,     0,     0,
      38,     0,   337,    38,    40,     0,     0,   159,     0,     0,
       0,     8,     0,     0,   160,     0,     0,   161,     0,     0,
       0,     0,   162,   318,     0,     0,   163,     8,   475,   475,
     475,     0,    36,    37,   560,     0,   321,   321,     8,   321,
       0,   188,     0,   667,     0,   569,     0,     0,   316,     0,
       0,   827,     0,   667,     0,     0,   317,   664,    38,     0,
       0,     0,   159,     0,   359,   157,     0,     0,     0,   241,
       0,     0,   242,     0,   323,   359,   337,   162,     0,     0,
       0,   163,     0,   155,   437,     0,   440,   441,   442,   443,
     444,   445,   446,   610,     0,     0,     0,    36,    37,     0,
       0,     0,     0,     0,   475,   475,     0,     8,     0,     0,
     621,     0,     0,    36,    37,     0,     0,     0,     0,   486,
       8,     0,     0,    38,    36,    37,     0,    40,     0,     0,
       0,   321,     0,     0,   321,     0,     0,     0,     0,    38,
     351,   351,   499,   159,   359,   502,   318,   925,     0,     0,
      38,   245,   155,     0,   159,   245,     0,   359,   171,     0,
     989,   241,   163,     0,   242,   155,     0,   505,   508,   162,
       0,     0,   514,   163,     0,   349,     0,     0,   475,   245,
     321,     0,     0,   321,   709,   349,     0,   667,     0,   923,
       0,   351,     0,    36,    37,     0,     0,     8,     0,     0,
       0,   690,     0,   349,     0,   736,    36,    37,     0,     0,
       0,   171,     0,   827,     0,     0,     0,     0,     0,    38,
       0,     0,     0,   159,     0,     0,     0,     0,     0,     0,
     241,     0,    38,   242,   413,     0,   159,     0,   162,     0,
       0,     0,   163,   241,   321,   321,   242,   505,   508,   321,
     514,   162,     0,     8,   321,   163,     0,     0,     0,   321,
       0,     0,     0,     0,   593,   594,   595,   596,   597,   598,
     599,   600,   601,   602,   603,   604,   605,   606,   607,   608,
     609,     0,     0,    36,    37,     0,     0,     0,     0,     0,
     240,     8,     0,   245,     0,     0,     0,   618,   155,   667,
       0,     0,     0,     0,     0,     0,   627,     0,     0,    38,
       0,     0,     0,    40,     0,     8,     0,   841,     0,     0,
       0,   620,     0,   321,     0,     0,     0,     0,   359,     0,
       0,  1004,   318,     0,     0,   829,   155,     0,     0,    36,
      37,     0,   639,   245,     0,   644,     0,     0,     0,     0,
       8,     0,   359,     0,     0,  1020,     8,     0,     0,     0,
     155,     0,     0,     0,     0,    38,     0,     0,     0,   159,
       0,     8,     0,     0,     0,     0,   241,    36,    37,   242,
     321,   321,     0,     0,   162,     0,   321,   316,   163,     0,
       0,   620,     0,   295,   639,   334,     0,   737,   599,   602,
     607,    36,    37,    38,   157,     0,     0,   159,   359,     0,
     157,     0,     0,     0,   241,     0,   155,   242,     0,     0,
       0,     0,   162,   349,   349,     0,   163,    38,     0,     0,
       0,   159,   919,     0,     0,     0,    36,    37,   241,     0,
     245,   242,    36,    37,     0,     0,   162,     0,     0,   245,
     163,     0,     0,     0,     0,   753,   754,    36,    37,     8,
     757,     0,    38,     0,     0,   758,    40,     0,    38,     0,
     764,     0,    40,   335,   349,     0,   336,     0,     0,   479,
       0,     0,   480,    38,     0,   318,     8,   159,   935,   936,
     938,     8,     0,     0,   241,     0,   424,   242,     0,   966,
     188,     0,   162,     0,   155,     0,   163,   264,   265,   266,
     267,   268,   269,   270,   271,   321,   953,     0,     0,   321,
     321,     0,     0,   316,     0,     0,     0,     0,   984,   871,
       0,   636,     0,     0,   753,     0,   155,     0,   245,     0,
     157,     0,     0,     0,     0,    36,    37,     0,   245,     0,
     883,   884,   444,     0,   885,     0,     0,     0,     0,     0,
     890,     0,     0,     0,     0,   245,     0,     0,     0,     0,
       0,    38,    36,    37,     0,   159,   245,    36,    37,     0,
    1011,     0,   241,     0,     0,   242,     0,     0,     0,   245,
     162,   892,   893,   171,   163,   321,   321,   897,    38,     0,
       0,     0,    40,    38,     0,   569,     0,   159,     0,   637,
       0,     0,   638,     0,   241,     0,     0,   242,   171,     0,
       0,   318,   162,     0,     0,     0,   163,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   771,
    1056,  -574,    62,     0,   245,     0,    63,    64,    65,     0,
       0,     0,     0,    27,    28,    29,     0,   953,   156,    66,
    -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,
    -574,  -574,  1011,  -574,  -574,  -574,  -574,  -574,     0,     0,
     158,   772,    68,     0,   570,  -574,     0,  -574,  -574,  -574,
    -574,  -574,   571,   572,   573,     0,     0,     0,   970,   971,
      70,    71,    72,    73,   773,    75,    76,    77,  -574,  -574,
    -574,   774,   775,   776,     0,    78,   777,    80,     0,    81,
      82,   778,    83,    84,  -574,  -574,   973,  -574,  -574,    85,
     976,   977,     0,    89,     0,    91,    92,    93,    94,    95,
      96,     0,     0,     0,     0,     0,   452,   453,   454,   455,
       0,    97,     0,  -574,   452,   453,    98,  -574,  -574,     0,
       0,     0,     8,     0,     0,   188,   459,   460,   461,   462,
     463,   464,   465,   466,   467,   468,   779,   462,   463,   464,
     465,   466,   467,   468,     0,     9,    10,    11,    12,    13,
      14,    15,    16,     0,    18,  1034,    20,     0,     0,    22,
      23,    24,    25,     0,     0,     0,  1025,  1026,     8,     0,
       0,   188,   261,     0,  1045,     0,   262,   263,   264,   265,
     266,   267,   268,   269,   270,   271,     0,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,     0,
      21,    22,    23,    24,    25,   272,     0,     0,    36,    37,
      66,     0,     0,    26,    27,    28,    29,    30,    31,     0,
     273,     0,     0,     0,   304,   305,     0,     0,     0,     0,
       0,     0,     0,   842,    38,    32,    33,    34,    40,     0,
       0,     0,     0,     0,     0,   407,     0,     0,   408,     0,
       0,    35,     0,   162,    36,    37,     8,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    78,    79,    80,     0,
       0,    82,   778,    83,    84,     0,     0,     0,     0,     0,
      38,     0,     0,    39,    40,     0,     0,     0,     0,     0,
       0,   274,     0,   413,   275,     0,     0,   276,   277,   278,
       0,   511,     8,   279,   280,   188,   261,   843,     8,     0,
     262,   263,   264,   265,   266,   267,   268,   269,   270,   271,
       0,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,     0,    21,    22,    23,    24,    25,   272,
       0,     0,    36,    37,     0,   316,     0,     0,    27,    28,
      29,    30,    31,   322,   273,     0,     0,   311,     0,     0,
       0,     0,   157,     0,     0,     0,     0,     0,    38,    32,
      33,    34,    40,     0,     0,   452,   453,   454,   455,   512,
       0,     0,   513,     0,     0,    35,     0,     0,    36,    37,
       8,   318,     0,     0,    36,    37,   460,   461,   462,   463,
     464,   465,   466,   467,   468,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    38,     0,     0,     0,    40,     0,
      38,     0,     0,     0,    40,   274,     0,   413,   275,     0,
       0,   276,   277,   278,     0,   636,     8,   279,   280,   188,
     261,     0,     8,   318,   262,   263,   264,   265,   266,   267,
     268,   269,   270,   271,     0,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,     0,    21,    22,
      23,    24,    25,   272,     0,     0,    36,    37,     0,   316,
       0,     0,    27,    28,    29,    30,    31,   504,   273,     0,
       0,   498,     0,     0,     0,     0,   157,     0,     0,     0,
       0,     0,    38,    32,    33,    34,    40,     0,     0,     0,
       0,     0,     0,   637,     0,     0,   638,     0,     0,    35,
       0,     0,    36,    37,     8,   318,     0,   188,    36,    37,
       0,     0,     0,     0,   264,   265,   266,   267,   268,   269,
     270,   271,     0,     0,     0,     0,     0,     0,    38,     0,
       0,     0,    40,     0,    38,     0,     0,     0,    40,   274,
       0,     0,   275,     0,     0,   276,   277,   278,     0,     0,
       8,   279,   280,   188,   261,     0,     8,   318,   262,   263,
     264,   265,   266,   267,   268,   269,   270,   271,     0,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,     0,    21,    22,    23,    24,    25,   272,     0,     0,
      36,    37,     0,   316,     0,   748,    27,    28,    29,    30,
      31,   507,   273,     0,     0,   501,   304,   305,     0,     0,
     157,     0,     0,     0,     0,     0,     0,    32,    33,    34,
       0,     0,     0,     0,     0,     0,   452,   453,   454,   455,
       0,   456,     0,    35,     0,     0,    36,    37,     0,     0,
       0,     0,    36,    37,   457,   458,   459,   460,   461,   462,
     463,   464,   465,   466,   467,   468,     0,     0,     0,     0,
       0,     0,    38,     0,     0,     0,    40,     0,    38,     0,
       0,     0,    40,   274,     0,     0,   275,     0,     0,   276,
     277,   278,     0,     0,     8,   279,   280,   188,   261,   585,
       0,   318,   262,   263,   264,   265,   266,   267,   268,   269,
     270,   271,     0,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,     0,    21,    22,    23,    24,
      25,   272,     0,     0,     0,     0,     0,     0,     0,     0,
      27,    28,    29,    30,    31,     0,   273,     0,     0,   626,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    32,    33,    34,     0,   452,   453,   454,   455,     0,
     456,     0,     0,   452,   453,   454,   455,    35,     0,     0,
      36,    37,     0,   457,   586,   459,   460,   587,   462,   463,
     464,   465,   588,   467,   468,   461,   462,   463,   464,   465,
     466,   467,   468,     0,     0,     0,    38,     0,     0,     0,
      40,     0,     0,     0,     0,   963,     0,   274,     0,     0,
     275,     0,     0,   276,   277,   278,     0,     0,     8,   279,
     280,   188,   261,     0,     0,     0,   262,   263,   264,   265,
     266,   267,   268,   269,   270,   271,     0,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,     0,
      21,    22,    23,    24,    25,   272,   738,     0,     0,     0,
       0,     0,     0,     0,    27,    28,    29,    30,    31,     0,
     273,   452,   453,   454,   455,     0,   456,     0,     0,     0,
       0,     0,     0,     0,     0,    32,    33,    34,     0,   457,
     458,   459,   460,   461,   462,   463,   464,   465,   466,   467,
     468,    35,     0,     0,    36,    37,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      38,     0,     0,     0,    40,     0,     0,     0,     0,     0,
       0,   274,     0,     0,   275,     0,     0,   276,   277,   278,
       0,     0,     8,   279,   280,   188,   261,     0,  1068,     0,
     262,   263,   264,   265,   266,   267,   268,   269,   270,   271,
       0,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,     0,    21,    22,    23,    24,    25,   272,
     739,     0,     0,     0,     0,     0,     0,     0,    27,    28,
      29,    30,    31,     0,   273,   452,   453,   454,   455,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    32,
      33,    34,   452,   453,   454,   455,     0,   456,   462,   463,
     464,   465,   466,   467,   468,    35,     0,     0,    36,    37,
     457,   458,   459,   460,   461,   462,   463,   464,   465,   466,
     467,   468,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    38,     0,     0,     0,    40,     0,
       0,     0,     0,     0,     0,   274,     0,     0,   275,     0,
       0,   276,   277,   278,     0,     0,     8,   279,   280,   188,
     261,     0,     0,     0,   262,   263,   264,   265,   266,   267,
     268,   269,   270,   271,     0,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,     0,    21,    22,
      23,    24,    25,   272,     0,     0,     0,     0,     0,     0,
       0,     0,    27,    28,    29,    30,    31,     0,   273,   452,
     453,   454,   455,     0,   456,     0,     0,     0,     0,     0,
       0,     0,     0,    32,    33,    34,     0,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   466,   467,   468,    35,
       0,     0,    36,    37,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    38,     0,
       0,     0,    40,     0,     0,     0,     0,     0,     0,   274,
       0,     0,   275,     0,     0,   276,   277,   278,     0,     0,
       8,   279,   280,   188,   261,     0,     0,     0,   262,   263,
     264,   265,   266,   267,   268,   269,   270,   271,     0,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,     0,    21,    22,    23,    24,    25,   272,     0,     0,
       0,     0,     0,     0,     0,     0,    27,    28,    29,    30,
      31,     0,   273,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    32,    33,    34,
       0,     0,     8,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    35,     0,     0,    36,    37,     0,     0,
       0,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,     0,    21,    22,    23,    24,    25,   295,
       0,     0,    38,     0,     0,     0,    40,    26,    27,    28,
      29,    30,    31,     0,     0,     0,   157,     0,     0,   276,
     277,   740,     0,     0,     0,   279,   280,     0,     0,    32,
      33,    34,   452,   453,   454,   455,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    35,     0,     0,    36,    37,
     457,   458,   459,   460,   461,   462,   463,   464,   465,   466,
     467,   468,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    38,     8,     0,    39,    40,     0,
       0,     0,     0,     0,     0,   296,     0,     0,   297,     0,
       0,     0,     0,   162,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,     0,    21,    22,    23,
      24,    25,   295,     0,     0,     0,     0,     0,     0,     0,
      26,    27,    28,    29,    30,    31,     0,     0,     0,   157,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    32,    33,    34,     0,     0,     8,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    35,     0,
       0,    36,    37,     0,     0,     0,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,     0,    21,
      22,    23,    24,    25,     0,     0,     0,    38,     0,     0,
      39,    40,    26,    27,    28,    29,    30,    31,   470,     0,
       0,   471,     0,     0,     0,     0,   162,     0,     0,     0,
       0,     0,     0,     0,    32,    33,    34,     8,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      35,     0,     0,    36,    37,     0,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,     0,    21,
      22,    23,    24,    25,     0,     0,     0,     0,     0,    38,
       0,     0,    39,    40,     0,     0,    30,    31,     0,     0,
     407,     0,     0,   408,     0,     0,     0,     0,   162,     0,
       0,     0,     0,     0,    32,    33,    34,    -2,    61,     0,
    -574,    62,     0,     0,     0,    63,    64,    65,     0,     0,
      35,     0,     0,    36,    37,     0,     0,     0,    66,  -574,
    -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,
    -574,     0,  -574,  -574,  -574,  -574,  -574,     0,     0,    38,
      67,    68,     0,    40,     0,     0,  -574,  -574,  -574,  -574,
    -574,     0,     0,    69,     0,     0,     0,     0,   162,    70,
      71,    72,    73,    74,    75,    76,    77,  -574,  -574,  -574,
       0,     0,     0,     0,    78,    79,    80,     0,    81,    82,
       0,    83,    84,  -574,  -574,     0,  -574,  -574,    85,    86,
      87,    88,    89,    90,    91,    92,    93,    94,    95,    96,
      61,     0,  -574,    62,     0,     0,     0,    63,    64,    65,
      97,     0,  -574,     0,     0,    98,  -574,     0,     0,     0,
      66,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,
    -574,  -574,  -574,     0,  -574,  -574,  -574,  -574,  -574,     0,
       0,     0,    67,    68,     0,     0,   677,     0,  -574,  -574,
    -574,  -574,  -574,     0,     0,    69,     0,     0,     0,     0,
       0,    70,    71,    72,    73,    74,    75,    76,    77,  -574,
    -574,  -574,     0,     0,     0,     0,    78,    79,    80,     0,
      81,    82,     0,    83,    84,  -574,  -574,     0,  -574,  -574,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    61,     0,  -574,    62,     0,     0,     0,    63,
      64,    65,    97,     0,  -574,     0,     0,    98,  -574,     0,
       0,     0,    66,  -574,  -574,  -574,  -574,  -574,  -574,  -574,
    -574,  -574,  -574,  -574,  -574,     0,  -574,  -574,  -574,  -574,
    -574,     0,     0,     0,    67,    68,     0,     0,   768,     0,
    -574,  -574,  -574,  -574,  -574,     0,     0,    69,     0,     0,
       0,     0,     0,    70,    71,    72,    73,    74,    75,    76,
      77,  -574,  -574,  -574,     0,     0,     0,     0,    78,    79,
      80,     0,    81,    82,     0,    83,    84,  -574,  -574,     0,
    -574,  -574,    85,    86,    87,    88,    89,    90,    91,    92,
      93,    94,    95,    96,    61,     0,  -574,    62,     0,     0,
       0,    63,    64,    65,    97,     0,  -574,     0,     0,    98,
    -574,     0,     0,     0,    66,  -574,  -574,  -574,  -574,  -574,
    -574,  -574,  -574,  -574,  -574,  -574,  -574,     0,  -574,  -574,
    -574,  -574,  -574,     0,     0,     0,    67,    68,     0,     0,
     826,     0,  -574,  -574,  -574,  -574,  -574,     0,     0,    69,
       0,     0,     0,     0,     0,    70,    71,    72,    73,    74,
      75,    76,    77,  -574,  -574,  -574,     0,     0,     0,     0,
      78,    79,    80,     0,    81,    82,     0,    83,    84,  -574,
    -574,     0,  -574,  -574,    85,    86,    87,    88,    89,    90,
      91,    92,    93,    94,    95,    96,    61,     0,  -574,    62,
       0,     0,     0,    63,    64,    65,    97,     0,  -574,     0,
       0,    98,  -574,     0,     0,     0,    66,  -574,  -574,  -574,
    -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,  -574,     0,
    -574,  -574,  -574,  -574,  -574,     0,     0,     0,    67,    68,
       0,     0,     0,     0,  -574,  -574,  -574,  -574,  -574,     0,
       0,    69,     0,     0,     0,   945,     0,    70,    71,    72,
      73,    74,    75,    76,    77,  -574,  -574,  -574,     0,     0,
       0,     0,    78,    79,    80,     0,    81,    82,     0,    83,
      84,  -574,  -574,     0,  -574,  -574,    85,    86,    87,    88,
      89,    90,    91,    92,    93,    94,    95,    96,     7,     0,
       8,     0,     0,     0,     0,     0,     0,     0,    97,     0,
    -574,     0,     0,    98,  -574,     0,     0,     0,     0,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,     0,    21,    22,    23,    24,    25,   452,   453,   454,
     455,     0,     0,     0,     0,    26,    27,    28,    29,    30,
      31,     0,     0,     0,     0,     0,   458,   459,   460,   461,
     462,   463,   464,   465,   466,   467,   468,    32,    33,    34,
      56,     0,     8,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    35,     0,     0,    36,    37,     0,     0,
       0,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,     0,    21,    22,    23,    24,    25,     0,
       0,     0,    38,     0,     0,    39,    40,    26,    27,    28,
      29,    30,    31,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    32,
      33,    34,   195,     0,     8,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    35,     0,     0,    36,    37,
       0,     0,     0,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,     0,    21,    22,    23,    24,
      25,     0,     0,     0,    38,     0,     0,    39,    40,     0,
      27,    28,    29,    30,    31,     0,     0,     0,     0,     0,
       0,     0,     0,   487,     0,     0,     0,     0,     0,     0,
       0,    32,    33,    34,     0,     8,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    35,     0,     0,
      36,    37,     0,     0,     9,    10,    11,    12,    13,    14,
      15,    16,   912,    18,   913,    20,     0,   914,    22,    23,
      24,    25,   452,   453,   454,   455,    38,   456,     0,     0,
      40,    27,    28,    29,    30,    31,     0,     0,     0,     0,
     457,   458,   459,   460,   461,   462,   463,   464,   465,   466,
     467,   468,    32,    33,    34,     0,     0,     8,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    35,   248,
       0,    36,    37,     0,     0,     0,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,     0,    21,
      22,    23,    24,    25,     0,     0,     0,    38,     0,     0,
       0,    40,   915,    27,    28,    29,    30,    31,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    32,    33,    34,     0,     0,     0,
       0,     0,     8,     0,     0,     0,     0,     0,     0,     0,
      35,   944,   368,    36,    37,     0,     0,     0,     0,     0,
       0,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,     0,    21,    22,    23,    24,    25,    38,
       0,     0,     0,    40,   915,     0,     0,    26,    27,    28,
      29,    30,    31,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    32,
      33,    34,     0,     0,     8,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    35,     0,     0,    36,    37,
       0,     0,     0,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,     0,    21,    22,    23,    24,
      25,     0,     0,     0,    38,     0,     0,    39,    40,    26,
      27,    28,    29,    30,    31,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    32,    33,    34,     0,     8,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    35,     0,     0,
      36,    37,     0,     0,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,     0,    21,    22,    23,
      24,    25,   228,     0,     0,     0,    38,     0,     0,    39,
      40,    27,    28,    29,    30,    31,     0,     0,     0,     0,
       0,     0,     0,     0,   630,     0,     0,     0,     0,     0,
       0,     0,    32,    33,    34,     0,     8,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    35,     0,
       0,    36,    37,     0,     0,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,     0,    21,    22,
      23,    24,    25,   452,   453,   454,   455,    38,   456,     0,
       0,    40,    27,    28,    29,    30,    31,     0,     0,     0,
       0,   457,   458,   459,   460,   461,   462,   463,   464,   465,
     466,   467,   468,    32,    33,    34,     0,     8,     0,     0,
       0,   632,     0,     0,     0,     0,     0,     0,     0,    35,
     248,     0,    36,    37,     0,     0,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,     0,    21,
      22,    23,    24,    25,     0,     0,     0,     0,    38,     0,
       0,     0,    40,    27,    28,    29,    30,    31,     0,     0,
     452,   453,   454,   455,     0,   456,     0,     0,     0,     0,
       0,     0,     0,     0,    32,    33,    34,     8,   457,   458,
     459,   460,   461,   462,   463,   464,   465,   466,   467,   468,
      35,     0,     0,    36,    37,     0,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,     0,    21,
      22,    23,    24,    25,     0,     0,     0,     0,     0,    38,
       0,     0,     0,    40,     0,     0,    30,    31,     0,     0,
       0,     0,     0,     0,     0,     0,   750,     0,     0,     0,
       0,     0,     0,     0,    32,    33,    34,     8,   756,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      35,     0,     0,    36,    37,     0,     9,    10,    11,    12,
      13,    14,    15,    16,   703,    18,   704,    20,     0,   705,
      22,    23,    24,    25,     0,   452,   453,   454,   455,    38,
     456,     0,     0,    40,     0,     0,     0,   452,   453,   454,
     455,     0,   456,   457,   458,   459,   460,   461,   462,   463,
     464,   465,   466,   467,   468,   457,   458,   459,   460,   461,
     462,   463,   464,   465,   466,   467,   468,     0,     0,     0,
      35,     0,     0,    36,    37,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    38,
       0,     0,     0,    40
};

static const yytype_int16 yycheck[] =
{
       0,     5,   156,     5,   361,     5,   537,    44,   138,    46,
     154,    45,     5,    92,    70,   237,     5,     5,   590,   531,
     222,    43,   146,     1,     2,    40,   734,   425,   551,   671,
     148,   375,   383,   522,     1,     2,    92,    93,   240,   563,
     706,     6,   531,     6,     3,    45,   857,     3,     5,   952,
      42,   954,     5,   177,   178,    42,    40,    52,    41,     6,
      21,     5,    44,     5,     0,    98,   259,     5,    43,    69,
      43,    45,     5,     5,    74,    75,    71,   117,    54,    41,
       5,    54,   138,   103,     5,   117,   230,     5,     5,    54,
     187,   140,    59,   666,   802,    77,   193,    46,     5,     3,
       5,   674,   199,   160,   161,   138,     5,   204,   140,   109,
      41,    40,   104,   170,   147,   152,     3,   104,     6,    59,
       5,     5,    85,    46,    85,   162,     5,   700,   103,     5,
      89,    90,   166,   116,   168,     4,   233,     6,    85,     3,
     116,     3,   715,  1046,   159,   129,   243,   103,   148,   672,
     343,   295,    54,   964,   116,   118,   196,   190,    48,   118,
     119,     3,   111,   296,   297,    48,   166,   300,   168,    40,
     148,    59,   316,   881,    43,  1042,   520,    46,   576,     4,
     154,   148,   105,   106,   184,    89,    90,   154,   162,    48,
     230,   542,     4,    54,   902,   126,   540,   126,   129,    40,
     129,   103,    89,    90,     6,   134,   872,   361,   248,    40,
     250,   115,    49,    50,    51,   119,    57,    48,     3,    43,
       4,    46,     6,     6,  1091,    89,    90,    89,    90,     3,
     230,    40,   232,   233,    46,   103,  1047,   237,   205,   296,
     297,   208,   103,   300,    46,   114,  1057,    89,    90,   249,
     823,   251,   286,   115,   118,   119,   230,   119,     1,   237,
     120,   228,    46,    46,   126,   205,   240,   129,   208,   236,
     237,   979,   134,   115,   407,   408,   409,   119,   335,   336,
      89,    90,   924,     3,   284,    54,   286,   811,   228,     4,
      43,     6,   134,   816,     3,     6,   236,   134,    43,    42,
      43,     1,    76,    46,    89,    90,   818,    76,   706,    43,
     389,    43,   286,    74,    46,    89,    90,   715,   374,   521,
      40,   295,     4,    76,     6,  1073,   360,   383,   295,   818,
     448,   553,    43,   389,   119,    43,   117,    57,    46,  1005,
      40,   115,   316,    40,    76,   119,    40,   549,   109,   316,
     483,   484,   326,   926,    40,   699,  1022,     3,  1106,   140,
     360,    43,   329,    57,    46,   332,    40,   345,    76,    89,
      90,   103,    54,  1081,    40,   375,    43,    40,   345,    46,
      89,    90,   438,    57,    21,   359,    42,    54,   425,   329,
       3,    57,   332,   537,    40,   115,    42,    40,    54,   119,
     972,   401,    48,   436,    40,   928,   126,    44,    54,   129,
     119,    57,    40,   470,   471,   472,   814,   990,   138,   434,
      40,   421,   479,   480,   557,   425,   999,    40,     3,   429,
      76,     6,   489,    77,   531,    48,    52,    53,    82,   413,
      77,    78,    79,    89,    90,    82,    40,    84,    85,    43,
     424,    84,    46,   510,   103,    71,    72,   424,   104,    52,
      53,    43,    43,   437,    46,    46,   997,   116,   117,   115,
     448,    40,    54,   119,   872,     3,    89,    90,    71,    72,
     126,   448,    43,   129,   424,    46,   542,     3,   134,  1062,
     530,   140,   138,    40,   534,    80,  1069,   537,     4,    46,
       6,    40,   115,    88,    89,    90,   119,    46,    40,   866,
     103,    43,    40,   126,    89,    90,   129,   517,   558,    40,
     520,   488,     3,    42,    40,   138,   493,    40,    47,    57,
     105,   106,    48,    40,   538,     6,   538,   537,   538,   541,
     540,   541,   576,   565,   578,   538,   546,    40,   488,   538,
     538,   588,  1085,   493,    43,   533,   590,    46,   615,    84,
      85,    89,    90,   537,     3,    48,   533,   769,   770,  1102,
    1103,  1104,   550,    89,    90,   553,   576,    43,   578,   579,
      46,   538,  1115,   550,    48,   538,   553,   115,   105,   106,
     590,   119,   592,    48,   538,    48,   538,    41,   126,   115,
     538,   129,   116,   119,    42,   538,   538,  1005,    89,    90,
     138,    92,   935,   538,   588,   938,   590,   538,    40,    41,
     538,   538,   138,    43,  1022,   681,    40,    41,    46,   666,
       6,   538,   672,   538,   115,    57,    46,   674,   119,   538,
      43,    40,    41,    57,    42,   649,   116,   649,    48,   649,
      89,    90,    48,   538,   538,   779,   649,   657,    57,   538,
     649,   649,   538,   700,    41,    42,   666,    40,    41,   706,
      41,  1069,    40,    41,   674,   679,   115,   679,   715,   679,
     119,   811,   722,   104,    57,   104,   679,    41,    42,    57,
     679,   679,   649,   727,    42,   697,   649,   697,   698,   699,
     700,    40,   736,   740,   697,   649,   706,   649,   697,   697,
     714,   649,   866,     7,   714,   715,   649,   649,   685,   741,
     838,   943,   679,   820,   649,     3,   679,   727,   649,    41,
      42,   649,   649,   116,   734,   679,   736,   679,    41,    40,
      41,   679,   649,    41,   649,   685,   679,   679,    48,   716,
     649,    40,   831,  1110,   679,   811,    57,    48,   679,   134,
      57,   679,   679,    48,   649,   649,   740,   741,    46,    68,
     649,    48,   679,   649,   679,   831,   716,    43,   811,   819,
     679,   116,    41,   907,    41,    41,   823,    41,   828,    52,
      53,    46,    91,    54,   679,   679,   852,    96,    42,    41,
     679,    41,   802,   679,   958,    43,    41,    40,    71,    72,
     843,    89,    90,   121,   122,   123,    49,    50,    51,   852,
      41,    54,    41,   823,   130,   131,   132,   133,   134,   135,
     136,    41,    41,   889,   104,   872,    41,   115,   838,    42,
     103,   119,    49,    50,    51,   116,   813,    80,    41,    43,
     854,   116,   854,   997,   854,    88,    89,    90,   111,   915,
     838,   854,   134,   135,   136,   854,   854,    46,   868,   116,
      76,   838,   872,   813,   874,    48,    48,   917,    73,    74,
      75,   881,   116,    48,    41,    41,   942,   927,   187,   926,
      48,   858,    43,   192,   193,    48,    48,   854,   865,    48,
     199,   854,   902,    48,   944,   204,    43,    41,    46,    40,
     854,    43,   854,    91,     3,   955,   854,    47,   858,    43,
      41,   854,   854,   222,    57,   865,   926,    40,   968,   854,
      90,    78,    46,   854,   233,   234,   854,   854,   972,    89,
     239,   240,    48,   943,   243,    41,  1100,   854,   952,   854,
     954,    40,   952,   990,   954,   854,  1110,   997,    41,    48,
      48,    48,   999,    48,    48,   943,   966,   967,  1005,   854,
     854,    48,   972,    48,    48,   854,   943,    42,   854,   979,
      42,    40,    54,  1023,   103,  1022,    43,    41,    41,    47,
     990,    62,    41,    54,   140,    42,    45,   997,   972,   999,
      89,    90,    41,    52,    41,  1005,    40,    48,   982,    76,
     984,   138,    48,    48,   981,    76,  1072,   984,    48,    80,
       3,    48,  1022,   997,    46,  1062,   115,    88,    89,    90,
     119,    76,  1069,    76,    40,    47,    85,    86,    47,    41,
      43,   981,  1046,    41,   984,  1082,  1046,     3,  1085,   138,
      54,    43,    76,    54,    70,    41,  1056,    40,    47,    40,
      48,  1028,  1062,  1030,    48,  1102,  1103,  1104,   117,  1069,
      86,    76,    41,    43,    57,    42,    76,    76,  1115,    76,
      76,  1081,  1082,    43,    40,  1085,   104,    41,  1028,    54,
    1030,    41,    48,     3,    43,    48,   145,  1064,  1065,  1066,
      47,    57,  1102,  1103,  1104,   154,    89,    90,    43,    40,
      43,   160,   161,    43,   163,  1115,    43,    49,    50,    51,
      43,   170,  1089,    42,  1064,  1065,  1066,     3,   104,     3,
      40,    48,   115,    89,    90,    48,   119,    41,    48,   132,
     133,   134,   135,   136,    47,    41,    40,   196,    80,  1089,
      40,   200,    41,    48,    41,   138,    88,    89,    90,   115,
      43,    43,    48,   119,    40,   214,    40,    48,    41,    40,
     126,   187,    48,   129,    48,    41,   192,   193,   134,    89,
      90,   230,   138,   199,    48,   201,   202,     3,   204,   238,
       6,   240,   241,   242,    41,   244,    41,    46,    48,   248,
     249,   250,   251,   219,    41,   115,   222,   223,    48,   119,
      43,    43,   522,    89,    90,    89,    90,   233,     3,   518,
     546,     3,   521,   522,   240,    41,  1023,   243,   138,   697,
     529,   530,   531,   249,   553,   698,   943,   286,   697,   115,
     256,   115,   517,   119,   448,   119,   295,   296,   297,   697,
     549,   300,   551,    50,   697,    40,   592,  1003,    40,   558,
     838,   563,   138,    48,   138,  1056,    48,   316,   429,   318,
     874,   967,    54,    89,    90,    57,     3,     4,   571,     6,
    1069,  1051,    -1,    -1,    -1,   178,   335,   336,   682,   105,
     106,   340,    -1,    -1,    76,    -1,    -1,    -1,    -1,   157,
     158,    -1,    -1,   352,    89,    90,    -1,    89,    90,    -1,
     359,    -1,    -1,    40,    -1,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,   161,    -1,    -1,    -1,   376,    -1,    -1,
     115,    -1,   170,   115,   119,    -1,    -1,   119,    -1,    -1,
      -1,     3,    -1,    -1,   126,    -1,    -1,   129,    -1,    -1,
      -1,    -1,   134,   138,    -1,    -1,   138,     3,   407,   408,
     409,    -1,    89,    90,   413,    -1,   415,   416,     3,   418,
      -1,     6,    -1,   672,    -1,   424,    -1,    -1,    40,    -1,
      -1,   680,    -1,   682,    -1,    -1,    48,   114,   115,    -1,
      -1,    -1,   119,    -1,    40,    57,    -1,    -1,    -1,   126,
      -1,    -1,   129,    -1,   242,    40,   244,   134,    -1,    -1,
      -1,   138,    -1,    48,   272,    -1,   274,   275,   276,   277,
     278,   279,   280,   472,    -1,    -1,    -1,    89,    90,    -1,
      -1,    -1,    -1,    -1,   483,   484,    -1,     3,    -1,    -1,
     489,    -1,    -1,    89,    90,    -1,    -1,    -1,    -1,   307,
       3,    -1,    -1,   115,    89,    90,    -1,   119,    -1,    -1,
      -1,   510,    -1,    -1,   513,    -1,    -1,    -1,    -1,   115,
     769,   770,   330,   119,    40,   333,   138,    43,    -1,    -1,
     115,   530,    48,    -1,   119,   534,    -1,    40,   537,    -1,
      43,   126,   138,    -1,   129,    48,    -1,   335,   336,   134,
      -1,    -1,   340,   138,    -1,   521,    -1,    -1,   557,   558,
     559,    -1,    -1,   562,   563,   531,    -1,   816,    -1,   818,
      -1,   820,    -1,    89,    90,    -1,    -1,     3,    -1,    -1,
      -1,   547,    -1,   549,    -1,   584,    89,    90,    -1,    -1,
      -1,   590,    -1,   842,    -1,    -1,    -1,    -1,    -1,   115,
      -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,    -1,    -1,
     126,    -1,   115,   129,    40,    -1,   119,    -1,   134,    -1,
      -1,    -1,   138,   126,   623,   624,   129,   415,   416,   628,
     418,   134,    -1,     3,   633,   138,    -1,    -1,    -1,   638,
      -1,    -1,    -1,    -1,   452,   453,   454,   455,   456,   457,
     458,   459,   460,   461,   462,   463,   464,   465,   466,   467,
     468,    -1,    -1,    89,    90,    -1,    -1,    -1,    -1,    -1,
      40,     3,    -1,   672,    -1,    -1,    -1,   485,    48,   928,
      -1,    -1,    -1,    -1,    -1,    -1,   494,    -1,    -1,   115,
      -1,    -1,    -1,   119,    -1,     3,    -1,   696,    -1,    -1,
      -1,   489,    -1,   702,    -1,    -1,    -1,    -1,    40,    -1,
      -1,    43,   138,    -1,    -1,   681,    48,    -1,    -1,    89,
      90,    -1,   510,   722,    -1,   513,    -1,    -1,    -1,    -1,
       3,    -1,    40,    -1,    -1,    43,     3,    -1,    -1,    -1,
      48,    -1,    -1,    -1,    -1,   115,    -1,    -1,    -1,   119,
      -1,     3,    -1,    -1,    -1,    -1,   126,    89,    90,   129,
     759,   760,    -1,    -1,   134,    -1,   765,    40,   138,    -1,
      -1,   559,    -1,    40,   562,    48,    -1,   585,   586,   587,
     588,    89,    90,   115,    57,    -1,    -1,   119,    40,    -1,
      57,    -1,    -1,    -1,   126,    -1,    48,   129,    -1,    -1,
      -1,    -1,   134,   769,   770,    -1,   138,   115,    -1,    -1,
      -1,   119,   811,    -1,    -1,    -1,    89,    90,   126,    -1,
     819,   129,    89,    90,    -1,    -1,   134,    -1,    -1,   828,
     138,    -1,    -1,    -1,    -1,   623,   624,    89,    90,     3,
     628,    -1,   115,    -1,    -1,   633,   119,    -1,   115,    -1,
     638,    -1,   119,   126,   820,    -1,   129,    -1,    -1,   126,
      -1,    -1,   129,   115,    -1,   138,     3,   119,   834,   835,
     836,     3,    -1,    -1,   126,    -1,    40,   129,    -1,   878,
       6,    -1,   134,    -1,    48,    -1,   138,    13,    14,    15,
      16,    17,    18,    19,    20,   894,   862,    -1,    -1,   898,
     899,    -1,    -1,    40,    -1,    -1,    -1,    -1,    40,   717,
      -1,    48,    -1,    -1,   702,    -1,    48,    -1,   917,    -1,
      57,    -1,    -1,    -1,    -1,    89,    90,    -1,   927,    -1,
     738,   739,   740,    -1,   742,    -1,    -1,    -1,    -1,    -1,
     748,    -1,    -1,    -1,    -1,   944,    -1,    -1,    -1,    -1,
      -1,   115,    89,    90,    -1,   119,   955,    89,    90,    -1,
     959,    -1,   126,    -1,    -1,   129,    -1,    -1,    -1,   968,
     134,   759,   760,   972,   138,   974,   975,   765,   115,    -1,
      -1,    -1,   119,   115,    -1,   984,    -1,   119,    -1,   126,
      -1,    -1,   129,    -1,   126,    -1,    -1,   129,   997,    -1,
      -1,   138,   134,    -1,    -1,    -1,   138,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     1,
    1019,     3,     4,    -1,  1023,    -1,     8,     9,    10,    -1,
      -1,    -1,    -1,    49,    50,    51,    -1,  1003,    54,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,  1051,    35,    36,    37,    38,    39,    -1,    -1,
      76,    43,    44,    -1,    80,    47,    -1,    49,    50,    51,
      52,    53,    88,    89,    90,    -1,    -1,    -1,   886,   887,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,    73,    74,    75,    -1,    77,    78,    79,    -1,    81,
      82,    83,    84,    85,    86,    87,   894,    89,    90,    91,
     898,   899,    -1,    95,    -1,    97,    98,    99,   100,   101,
     102,    -1,    -1,    -1,    -1,    -1,   107,   108,   109,   110,
      -1,   113,    -1,   115,   107,   108,   118,   119,   120,    -1,
      -1,    -1,     3,    -1,    -1,     6,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   138,   130,   131,   132,
     133,   134,   135,   136,    -1,    22,    23,    24,    25,    26,
      27,    28,    29,    -1,    31,   983,    33,    -1,    -1,    36,
      37,    38,    39,    -1,    -1,    -1,   974,   975,     3,    -1,
      -1,     6,     7,    -1,  1002,    -1,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    -1,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    -1,
      35,    36,    37,    38,    39,    40,    -1,    -1,    89,    90,
      21,    -1,    -1,    48,    49,    50,    51,    52,    53,    -1,
      55,    -1,    -1,    -1,   105,   106,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    44,   115,    70,    71,    72,   119,    -1,
      -1,    -1,    -1,    -1,    -1,   126,    -1,    -1,   129,    -1,
      -1,    86,    -1,   134,    89,    90,     3,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    77,    78,    79,    -1,
      -1,    82,    83,    84,    85,    -1,    -1,    -1,    -1,    -1,
     115,    -1,    -1,   118,   119,    -1,    -1,    -1,    -1,    -1,
      -1,   126,    -1,    40,   129,    -1,    -1,   132,   133,   134,
      -1,    48,     3,   138,   139,     6,     7,   118,     3,    -1,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      -1,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    -1,    35,    36,    37,    38,    39,    40,
      -1,    -1,    89,    90,    -1,    40,    -1,    -1,    49,    50,
      51,    52,    53,    48,    55,    -1,    -1,    58,    -1,    -1,
      -1,    -1,    57,    -1,    -1,    -1,    -1,    -1,   115,    70,
      71,    72,   119,    -1,    -1,   107,   108,   109,   110,   126,
      -1,    -1,   129,    -1,    -1,    86,    -1,    -1,    89,    90,
       3,   138,    -1,    -1,    89,    90,   128,   129,   130,   131,
     132,   133,   134,   135,   136,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   115,    -1,    -1,    -1,   119,    -1,
     115,    -1,    -1,    -1,   119,   126,    -1,    40,   129,    -1,
      -1,   132,   133,   134,    -1,    48,     3,   138,   139,     6,
       7,    -1,     3,   138,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    -1,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    -1,    35,    36,
      37,    38,    39,    40,    -1,    -1,    89,    90,    -1,    40,
      -1,    -1,    49,    50,    51,    52,    53,    48,    55,    -1,
      -1,    58,    -1,    -1,    -1,    -1,    57,    -1,    -1,    -1,
      -1,    -1,   115,    70,    71,    72,   119,    -1,    -1,    -1,
      -1,    -1,    -1,   126,    -1,    -1,   129,    -1,    -1,    86,
      -1,    -1,    89,    90,     3,   138,    -1,     6,    89,    90,
      -1,    -1,    -1,    -1,    13,    14,    15,    16,    17,    18,
      19,    20,    -1,    -1,    -1,    -1,    -1,    -1,   115,    -1,
      -1,    -1,   119,    -1,   115,    -1,    -1,    -1,   119,   126,
      -1,    -1,   129,    -1,    -1,   132,   133,   134,    -1,    -1,
       3,   138,   139,     6,     7,    -1,     3,   138,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    -1,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    -1,    35,    36,    37,    38,    39,    40,    -1,    -1,
      89,    90,    -1,    40,    -1,    76,    49,    50,    51,    52,
      53,    48,    55,    -1,    -1,    58,   105,   106,    -1,    -1,
      57,    -1,    -1,    -1,    -1,    -1,    -1,    70,    71,    72,
      -1,    -1,    -1,    -1,    -1,    -1,   107,   108,   109,   110,
      -1,   112,    -1,    86,    -1,    -1,    89,    90,    -1,    -1,
      -1,    -1,    89,    90,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,    -1,    -1,    -1,    -1,
      -1,    -1,   115,    -1,    -1,    -1,   119,    -1,   115,    -1,
      -1,    -1,   119,   126,    -1,    -1,   129,    -1,    -1,   132,
     133,   134,    -1,    -1,     3,   138,   139,     6,     7,    41,
      -1,   138,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    -1,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    -1,    35,    36,    37,    38,
      39,    40,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      49,    50,    51,    52,    53,    -1,    55,    -1,    -1,    58,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    70,    71,    72,    -1,   107,   108,   109,   110,    -1,
     112,    -1,    -1,   107,   108,   109,   110,    86,    -1,    -1,
      89,    90,    -1,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   129,   130,   131,   132,   133,
     134,   135,   136,    -1,    -1,    -1,   115,    -1,    -1,    -1,
     119,    -1,    -1,    -1,    -1,    41,    -1,   126,    -1,    -1,
     129,    -1,    -1,   132,   133,   134,    -1,    -1,     3,   138,
     139,     6,     7,    -1,    -1,    -1,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    -1,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    -1,
      35,    36,    37,    38,    39,    40,    41,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    49,    50,    51,    52,    53,    -1,
      55,   107,   108,   109,   110,    -1,   112,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    70,    71,    72,    -1,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,    86,    -1,    -1,    89,    90,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     115,    -1,    -1,    -1,   119,    -1,    -1,    -1,    -1,    -1,
      -1,   126,    -1,    -1,   129,    -1,    -1,   132,   133,   134,
      -1,    -1,     3,   138,   139,     6,     7,    -1,    43,    -1,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      -1,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    -1,    35,    36,    37,    38,    39,    40,
      41,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    49,    50,
      51,    52,    53,    -1,    55,   107,   108,   109,   110,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,
      71,    72,   107,   108,   109,   110,    -1,   112,   130,   131,
     132,   133,   134,   135,   136,    86,    -1,    -1,    89,    90,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   115,    -1,    -1,    -1,   119,    -1,
      -1,    -1,    -1,    -1,    -1,   126,    -1,    -1,   129,    -1,
      -1,   132,   133,   134,    -1,    -1,     3,   138,   139,     6,
       7,    -1,    -1,    -1,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    -1,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    -1,    35,    36,
      37,    38,    39,    40,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    49,    50,    51,    52,    53,    -1,    55,   107,
     108,   109,   110,    -1,   112,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    70,    71,    72,    -1,   125,   126,   127,
     128,   129,   130,   131,   132,   133,   134,   135,   136,    86,
      -1,    -1,    89,    90,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   115,    -1,
      -1,    -1,   119,    -1,    -1,    -1,    -1,    -1,    -1,   126,
      -1,    -1,   129,    -1,    -1,   132,   133,   134,    -1,    -1,
       3,   138,   139,     6,     7,    -1,    -1,    -1,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    -1,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    -1,    35,    36,    37,    38,    39,    40,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    49,    50,    51,    52,
      53,    -1,    55,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,    71,    72,
      -1,    -1,     3,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    86,    -1,    -1,    89,    90,    -1,    -1,
      -1,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    -1,    35,    36,    37,    38,    39,    40,
      -1,    -1,   115,    -1,    -1,    -1,   119,    48,    49,    50,
      51,    52,    53,    -1,    -1,    -1,    57,    -1,    -1,   132,
     133,   134,    -1,    -1,    -1,   138,   139,    -1,    -1,    70,
      71,    72,   107,   108,   109,   110,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    86,    -1,    -1,    89,    90,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   115,     3,    -1,   118,   119,    -1,
      -1,    -1,    -1,    -1,    -1,   126,    -1,    -1,   129,    -1,
      -1,    -1,    -1,   134,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    -1,    35,    36,    37,
      38,    39,    40,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      48,    49,    50,    51,    52,    53,    -1,    -1,    -1,    57,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    70,    71,    72,    -1,    -1,     3,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    86,    -1,
      -1,    89,    90,    -1,    -1,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    -1,    35,
      36,    37,    38,    39,    -1,    -1,    -1,   115,    -1,    -1,
     118,   119,    48,    49,    50,    51,    52,    53,   126,    -1,
      -1,   129,    -1,    -1,    -1,    -1,   134,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    70,    71,    72,     3,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      86,    -1,    -1,    89,    90,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    -1,    35,
      36,    37,    38,    39,    -1,    -1,    -1,    -1,    -1,   115,
      -1,    -1,   118,   119,    -1,    -1,    52,    53,    -1,    -1,
     126,    -1,    -1,   129,    -1,    -1,    -1,    -1,   134,    -1,
      -1,    -1,    -1,    -1,    70,    71,    72,     0,     1,    -1,
       3,     4,    -1,    -1,    -1,     8,     9,    10,    -1,    -1,
      86,    -1,    -1,    89,    90,    -1,    -1,    -1,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    -1,    35,    36,    37,    38,    39,    -1,    -1,   115,
      43,    44,    -1,   119,    -1,    -1,    49,    50,    51,    52,
      53,    -1,    -1,    56,    -1,    -1,    -1,    -1,   134,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      -1,    -1,    -1,    -1,    77,    78,    79,    -1,    81,    82,
      -1,    84,    85,    86,    87,    -1,    89,    90,    91,    92,
      93,    94,    95,    96,    97,    98,    99,   100,   101,   102,
       1,    -1,     3,     4,    -1,    -1,    -1,     8,     9,    10,
     113,    -1,   115,    -1,    -1,   118,   119,    -1,    -1,    -1,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    -1,    35,    36,    37,    38,    39,    -1,
      -1,    -1,    43,    44,    -1,    -1,    47,    -1,    49,    50,
      51,    52,    53,    -1,    -1,    56,    -1,    -1,    -1,    -1,
      -1,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    -1,    -1,    -1,    -1,    77,    78,    79,    -1,
      81,    82,    -1,    84,    85,    86,    87,    -1,    89,    90,
      91,    92,    93,    94,    95,    96,    97,    98,    99,   100,
     101,   102,     1,    -1,     3,     4,    -1,    -1,    -1,     8,
       9,    10,   113,    -1,   115,    -1,    -1,   118,   119,    -1,
      -1,    -1,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    -1,    35,    36,    37,    38,
      39,    -1,    -1,    -1,    43,    44,    -1,    -1,    47,    -1,
      49,    50,    51,    52,    53,    -1,    -1,    56,    -1,    -1,
      -1,    -1,    -1,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    -1,    -1,    -1,    -1,    77,    78,
      79,    -1,    81,    82,    -1,    84,    85,    86,    87,    -1,
      89,    90,    91,    92,    93,    94,    95,    96,    97,    98,
      99,   100,   101,   102,     1,    -1,     3,     4,    -1,    -1,
      -1,     8,     9,    10,   113,    -1,   115,    -1,    -1,   118,
     119,    -1,    -1,    -1,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    -1,    35,    36,
      37,    38,    39,    -1,    -1,    -1,    43,    44,    -1,    -1,
      47,    -1,    49,    50,    51,    52,    53,    -1,    -1,    56,
      -1,    -1,    -1,    -1,    -1,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    -1,    -1,    -1,    -1,
      77,    78,    79,    -1,    81,    82,    -1,    84,    85,    86,
      87,    -1,    89,    90,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,   102,     1,    -1,     3,     4,
      -1,    -1,    -1,     8,     9,    10,   113,    -1,   115,    -1,
      -1,   118,   119,    -1,    -1,    -1,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    -1,
      35,    36,    37,    38,    39,    -1,    -1,    -1,    43,    44,
      -1,    -1,    -1,    -1,    49,    50,    51,    52,    53,    -1,
      -1,    56,    -1,    -1,    -1,    60,    -1,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    -1,    -1,
      -1,    -1,    77,    78,    79,    -1,    81,    82,    -1,    84,
      85,    86,    87,    -1,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,     1,    -1,
       3,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   113,    -1,
     115,    -1,    -1,   118,   119,    -1,    -1,    -1,    -1,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    -1,    35,    36,    37,    38,    39,   107,   108,   109,
     110,    -1,    -1,    -1,    -1,    48,    49,    50,    51,    52,
      53,    -1,    -1,    -1,    -1,    -1,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,    70,    71,    72,
       1,    -1,     3,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    86,    -1,    -1,    89,    90,    -1,    -1,
      -1,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    -1,    35,    36,    37,    38,    39,    -1,
      -1,    -1,   115,    -1,    -1,   118,   119,    48,    49,    50,
      51,    52,    53,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,
      71,    72,     1,    -1,     3,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    86,    -1,    -1,    89,    90,
      -1,    -1,    -1,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    -1,    35,    36,    37,    38,
      39,    -1,    -1,    -1,   115,    -1,    -1,   118,   119,    -1,
      49,    50,    51,    52,    53,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    70,    71,    72,    -1,     3,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    86,    -1,    -1,
      89,    90,    -1,    -1,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    -1,    35,    36,    37,
      38,    39,   107,   108,   109,   110,   115,   112,    -1,    -1,
     119,    49,    50,    51,    52,    53,    -1,    -1,    -1,    -1,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,    70,    71,    72,    -1,    -1,     3,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    86,    87,
      -1,    89,    90,    -1,    -1,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    -1,    35,
      36,    37,    38,    39,    -1,    -1,    -1,   115,    -1,    -1,
      -1,   119,   120,    49,    50,    51,    52,    53,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    70,    71,    72,    -1,    -1,    -1,
      -1,    -1,     3,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      86,    87,    13,    89,    90,    -1,    -1,    -1,    -1,    -1,
      -1,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    -1,    35,    36,    37,    38,    39,   115,
      -1,    -1,    -1,   119,   120,    -1,    -1,    48,    49,    50,
      51,    52,    53,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    70,
      71,    72,    -1,    -1,     3,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    86,    -1,    -1,    89,    90,
      -1,    -1,    -1,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    -1,    35,    36,    37,    38,
      39,    -1,    -1,    -1,   115,    -1,    -1,   118,   119,    48,
      49,    50,    51,    52,    53,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    70,    71,    72,    -1,     3,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    86,    -1,    -1,
      89,    90,    -1,    -1,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    -1,    35,    36,    37,
      38,    39,    40,    -1,    -1,    -1,   115,    -1,    -1,   118,
     119,    49,    50,    51,    52,    53,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    70,    71,    72,    -1,     3,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    86,    -1,
      -1,    89,    90,    -1,    -1,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    -1,    35,    36,
      37,    38,    39,   107,   108,   109,   110,   115,   112,    -1,
      -1,   119,    49,    50,    51,    52,    53,    -1,    -1,    -1,
      -1,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,    70,    71,    72,    -1,     3,    -1,    -1,
      -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    86,
      87,    -1,    89,    90,    -1,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    -1,    35,
      36,    37,    38,    39,    -1,    -1,    -1,    -1,   115,    -1,
      -1,    -1,   119,    49,    50,    51,    52,    53,    -1,    -1,
     107,   108,   109,   110,    -1,   112,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    70,    71,    72,     3,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
      86,    -1,    -1,    89,    90,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    -1,    35,
      36,    37,    38,    39,    -1,    -1,    -1,    -1,    -1,   115,
      -1,    -1,    -1,   119,    -1,    -1,    52,    53,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    70,    71,    72,     3,    58,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      86,    -1,    -1,    89,    90,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    -1,    35,
      36,    37,    38,    39,    -1,   107,   108,   109,   110,   115,
     112,    -1,    -1,   119,    -1,    -1,    -1,   107,   108,   109,
     110,    -1,   112,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,    -1,    -1,    -1,
      86,    -1,    -1,    89,    90,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   115,
      -1,    -1,    -1,   119
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,   121,   122,   123,   142,   143,   309,     1,     3,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    35,    36,    37,    38,    39,    48,    49,    50,    51,
      52,    53,    70,    71,    72,    86,    89,    90,   115,   118,
     119,   193,   236,   250,   251,   253,   254,   255,   256,   257,
     258,   283,   284,   294,   297,   299,     1,   236,     1,    40,
       0,     1,     4,     8,     9,    10,    21,    43,    44,    56,
      62,    63,    64,    65,    66,    67,    68,    69,    77,    78,
      79,    81,    82,    84,    85,    91,    92,    93,    94,    95,
      96,    97,    98,    99,   100,   101,   102,   113,   118,   144,
     145,   146,   148,   149,   150,   151,   152,   155,   156,   158,
     159,   160,   161,   162,   163,   164,   167,   168,   169,   172,
     174,   179,   180,   181,   182,   184,   188,   195,   196,   197,
     198,   199,   203,   204,   211,   212,   223,   231,   232,   309,
      48,    52,    71,    48,    48,    40,   140,   103,   103,   293,
     297,    43,   254,   250,    40,    48,    54,    57,    76,   119,
     126,   129,   134,   138,   241,   242,   244,   246,   247,   248,
     249,   297,   309,   250,   257,   297,   293,   117,   140,   298,
      43,    43,   233,   234,   236,   309,   120,    40,     6,    85,
     118,   303,    40,   306,   309,     1,   252,   253,   294,    40,
     306,    40,   166,   309,    40,    40,    84,    85,    40,    84,
      77,    82,    44,    77,    92,   297,    46,   294,   297,    40,
       4,    46,    40,    40,    43,    46,     4,   303,    40,   178,
     252,   176,   178,    40,    40,   303,    40,   103,   284,   306,
      40,   126,   129,   244,   249,   297,    21,    85,    87,   193,
     252,   284,    48,    48,    48,   297,   118,   119,   299,   300,
     284,     7,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    40,    55,   126,   129,   132,   133,   134,   138,
     139,   236,   237,   238,   240,   252,   253,   269,   270,   271,
     272,   303,   304,   309,   250,    40,   126,   129,   233,   247,
     249,   297,    48,    46,   105,   106,   259,   260,   261,   262,
     263,    58,   269,   270,   269,     3,    40,    48,   138,   245,
     248,   297,    48,   245,   248,   249,   250,   297,   241,    40,
      57,   241,    40,    57,    48,   126,   129,   245,   248,   297,
     116,   299,   119,   300,    41,    42,   235,   309,   261,   294,
     295,   303,   284,     6,    46,   295,   307,   295,    43,    40,
     244,    54,    41,   295,   297,   294,   294,   295,    13,   173,
     233,   233,   297,    43,    54,   214,    54,    46,   294,   175,
     307,   294,   233,    46,   243,   244,   247,   309,    43,    42,
     177,   309,   295,   296,   309,   153,   154,   303,   233,   207,
     208,   209,   236,   283,   309,   297,   303,   126,   129,   249,
     294,   297,   307,    40,   295,   126,   129,   297,   116,   244,
     297,   264,   294,   309,    40,   244,    76,   275,   276,   297,
     309,    48,    48,    41,   294,   298,   104,   269,    40,    48,
     269,   269,   269,   269,   269,   269,   269,   104,    42,   239,
     309,    40,   107,   108,   109,   110,   112,   125,   126,   127,
     128,   129,   130,   131,   132,   133,   134,   135,   136,     7,
     126,   129,   249,   297,   246,   297,   246,    41,    41,   126,
     129,   246,   297,   116,    48,    57,   269,    58,    40,   249,
     297,    48,   297,    40,    57,    48,   249,   233,    58,   269,
     233,    58,   269,    48,    48,   245,   248,    48,   245,   248,
     116,    48,   126,   129,   245,   298,    43,   236,    41,   297,
     183,    42,    54,    41,   241,   259,    41,    46,    41,    54,
      41,    42,   171,    42,    41,    41,    43,   252,   143,   297,
     213,    41,    41,    41,    41,   176,   178,    41,    41,    42,
      46,    41,   104,    42,   210,   309,    59,   116,    41,   249,
     297,    43,   116,   111,    54,    76,   194,   309,   233,   297,
      80,    88,    89,    90,   186,   241,   250,   286,   287,   277,
      46,    43,   275,   293,   284,    41,   126,   129,   134,   249,
     252,    48,   240,   269,   269,   269,   269,   269,   269,   269,
     269,   269,   269,   269,   269,   269,   269,   269,   269,   269,
     297,   116,    41,    41,    41,   116,   246,   246,   269,   233,
     245,   297,    41,   116,    48,   233,    58,   269,    48,    41,
      58,    41,    58,    48,    48,    48,    48,   126,   129,   245,
     248,    48,    48,    48,   245,   235,     4,    46,   303,   143,
     307,   153,   271,   303,   308,    43,    43,   147,     4,   165,
     303,     4,    43,    46,   114,   170,   244,   303,   305,   295,
     303,   308,    41,   236,   244,    46,   243,    47,    43,   143,
      44,   232,   176,    43,    46,    40,    47,   177,   115,   119,
     294,   301,    43,   307,   236,   170,    91,   205,   209,   157,
     244,   303,   116,    30,    32,    35,   187,   255,   256,   297,
      57,   189,   254,    43,    46,    41,    40,    40,   286,    90,
      89,     1,    42,    43,    46,   185,   241,   287,   241,    78,
     278,   279,   285,   309,   201,    46,   297,   269,    41,    41,
     134,   250,    41,   126,   129,   242,    48,   239,    76,    41,
      58,    41,    41,   245,   245,    41,    58,   245,   245,    48,
      48,    48,    48,    48,   245,    48,    48,    48,    47,    42,
      42,     1,    43,    66,    73,    74,    75,    78,    83,   138,
     148,   149,   150,   151,   155,   156,   160,   162,   164,   167,
     169,   172,   174,   179,   180,   181,   182,   199,   203,   204,
     211,   215,   219,   220,   221,   222,   223,   224,   225,   226,
     229,   232,   309,    40,   250,   287,   288,   309,    54,    41,
      42,   171,   170,   244,   288,    43,    47,   303,   252,   294,
      43,    54,   305,   233,   140,   117,   140,   302,   103,    41,
      47,   297,    44,   118,   184,   199,   203,   204,   206,   220,
     222,   224,   232,   210,   143,   288,    43,   186,    40,    46,
     190,   150,   265,   266,   309,    40,    54,   287,   288,   289,
     233,   269,   244,   241,    42,    73,    74,    75,   280,   282,
     215,   200,   241,   269,   269,   269,    41,    41,    41,    40,
     269,    41,   245,   245,    48,    48,    48,   245,    48,    48,
     307,   307,   218,    46,    76,    76,    76,   138,    40,   299,
      47,   215,    30,    32,    35,   120,   230,   252,   256,   297,
     233,   287,   170,   303,   308,    43,   244,    41,   288,    43,
     244,    43,   178,    41,   119,   294,   294,   119,   294,   237,
       4,    46,    54,   103,    87,    60,    43,   185,   233,    40,
      43,   191,   267,   294,    42,    47,   233,   259,    54,    76,
     290,   309,    41,    41,   186,   279,   297,   281,    47,   215,
     269,   269,   252,   245,    48,    48,   245,   245,   215,   216,
     299,    40,   252,    76,    40,    43,    41,   171,   288,    43,
     244,   170,    43,    43,   302,   302,   104,   252,   207,    41,
     192,   265,    54,   265,    43,   244,    41,    43,   261,   291,
     292,   297,    43,    46,   185,    48,   273,   274,   309,   285,
      43,   202,   244,    47,   242,   245,   245,   215,    40,   233,
      40,   126,   129,   249,   269,   233,    43,    43,   288,    43,
     243,   104,   288,    43,   268,   269,   267,   186,    43,    46,
      43,    42,    48,    40,    46,    48,   297,   186,   202,    41,
      47,   233,    41,   233,    40,    40,    40,   129,    43,    41,
      43,    43,   111,   190,   265,   185,   292,    48,    48,   274,
     185,   217,    41,   227,   288,    41,   233,   233,   233,    40,
     289,   252,   191,    48,    48,   215,   228,   288,    43,    46,
      54,   228,    41,    41,    41,   233,   190,    48,    43,    46,
      54,   261,   228,   228,   228,    41,   191,    48,   259,    43,
     228,    43
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   141,   142,   142,   142,   142,   142,   142,   142,   143,
     143,   144,   144,   144,   144,   144,   144,   144,   145,   145,
     145,   145,   145,   145,   145,   145,   145,   145,   145,   145,
     145,   145,   145,   145,   145,   145,   145,   145,   145,   147,
     146,   148,   149,   150,   150,   150,   151,   151,   152,   152,
     152,   152,   153,   154,   154,   155,   155,   155,   157,   156,
     158,   158,   159,   159,   160,   160,   160,   160,   161,   162,
     162,   163,   163,   164,   164,   165,   165,   166,   166,   167,
     167,   167,   168,   168,   169,   169,   169,   169,   169,   169,
     169,   169,   170,   170,   170,   171,   171,   172,   173,   173,
     174,   174,   174,   175,   176,   177,   177,   178,   178,   178,
     179,   180,   181,   182,   182,   182,   183,   182,   182,   182,
     182,   184,   184,   185,   185,   185,   185,   186,   186,   186,
     186,   187,   187,   187,   187,   187,   187,   188,   188,   188,
     189,   190,   191,   192,   191,   193,   193,   193,   194,   194,
     195,   196,   196,   197,   198,   198,   198,   198,   198,   198,
     200,   199,   201,   199,   202,   202,   203,   205,   204,   204,
     204,   206,   206,   206,   206,   206,   206,   206,   207,   208,
     208,   209,   209,   210,   210,   211,   211,   213,   212,   214,
     212,   212,   215,   216,   217,   215,   215,   215,   218,   215,
     219,   219,   219,   219,   219,   219,   219,   219,   219,   219,
     219,   219,   219,   219,   219,   219,   219,   219,   219,   220,
     221,   221,   222,   222,   222,   222,   222,   223,   224,   225,
     225,   225,   226,   226,   226,   226,   226,   226,   226,   226,
     226,   226,   226,   227,   227,   227,   228,   228,   228,   229,
     230,   230,   230,   230,   230,   231,   232,   232,   232,   232,
     232,   232,   232,   232,   232,   232,   232,   232,   232,   232,
     232,   232,   232,   232,   232,   232,   233,   234,   234,   235,
     235,   236,   236,   236,   237,   238,   238,   239,   239,   240,
     240,   241,   241,   241,   241,   241,   242,   242,   242,   243,
     243,   243,   244,   244,   244,   244,   244,   244,   244,   244,
     244,   244,   244,   244,   244,   244,   244,   244,   244,   244,
     244,   244,   244,   244,   245,   245,   245,   245,   245,   245,
     245,   245,   246,   246,   246,   246,   246,   246,   246,   246,
     246,   246,   247,   247,   247,   247,   247,   247,   247,   247,
     247,   247,   247,   247,   247,   247,   248,   248,   248,   248,
     248,   248,   248,   249,   249,   249,   249,   250,   250,   251,
     251,   251,   252,   253,   253,   253,   253,   254,   254,   254,
     254,   254,   254,   254,   254,   255,   256,   257,   257,   258,
     258,   258,   258,   258,   258,   258,   258,   258,   258,   258,
     258,   258,   258,   260,   259,   259,   261,   261,   262,   263,
     264,   264,   265,   265,   266,   266,   266,   266,   267,   267,
     268,   269,   269,   270,   270,   270,   270,   270,   270,   270,
     270,   270,   270,   270,   270,   270,   270,   270,   270,   270,
     270,   271,   271,   271,   271,   271,   271,   271,   271,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   272,   272,   272,   272,   272,   272,   272,   272,   272,
     272,   273,   274,   274,   275,   277,   276,   276,   278,   278,
     280,   279,   281,   279,   282,   282,   282,   283,   283,   283,
     283,   284,   284,   284,   285,   285,   286,   286,   286,   286,
     287,   287,   287,   287,   287,   288,   288,   288,   288,   289,
     289,   289,   289,   289,   289,   290,   290,   291,   291,   291,
     291,   292,   292,   293,   294,   294,   294,   295,   295,   295,
     296,   296,   297,   297,   297,   297,   297,   297,   297,   298,
     298,   298,   298,   299,   299,   300,   300,   301,   301,   301,
     301,   301,   301,   302,   302,   302,   302,   303,   303,   304,
     304,   305,   305,   305,   306,   306,   307,   307,   307,   307,
     307,   307,   308,   308,   309
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     3,     2,     3,     2,     5,     3,     2,
       1,     1,     1,     1,     1,     1,     1,     2,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     0,
       7,     5,     3,     5,     5,     3,     2,     2,     5,     2,
       5,     2,     4,     1,     1,     7,     7,     5,     0,     7,
       1,     1,     2,     2,     1,     5,     5,     5,     3,     4,
       3,     7,     8,     5,     3,     1,     1,     3,     1,     4,
       7,     6,     1,     1,     7,     9,     8,    10,     5,     7,
       6,     8,     1,     1,     5,     4,     5,     7,     1,     3,
       6,     6,     8,     1,     2,     3,     1,     2,     3,     6,
       5,     9,     2,     1,     1,     1,     0,     6,     1,     6,
      10,     5,     7,     1,     4,     1,     1,     1,     2,     2,
       3,     1,     1,     1,     1,     1,     1,    11,    13,     7,
       1,     1,     1,     0,     3,     1,     2,     2,     2,     1,
       5,     8,    10,     6,     1,     1,     1,     1,     1,     1,
       0,     9,     0,     8,     1,     3,     4,     0,     6,     3,
       4,     1,     1,     1,     1,     1,     1,     1,     1,     2,
       1,     1,     1,     3,     1,     3,     4,     0,     6,     0,
       5,     5,     2,     0,     0,     7,     1,     1,     0,     3,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     6,
       6,     7,     8,     8,     8,     9,     7,     5,     2,     2,
       2,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     4,     2,     2,     4,     2,     5,
       1,     1,     1,     1,     1,     2,     1,     1,     2,     2,
       1,     1,     1,     1,     1,     1,     2,     2,     2,     2,
       1,     2,     2,     2,     2,     1,     1,     2,     1,     3,
       1,     2,     7,     3,     1,     2,     1,     3,     1,     1,
       1,     2,     5,     2,     2,     1,     2,     2,     1,     1,
       1,     1,     2,     3,     3,     1,     2,     2,     3,     4,
       5,     4,     5,     6,     6,     4,     5,     5,     6,     7,
       8,     8,     7,     7,     1,     2,     3,     4,     5,     3,
       4,     4,     1,     2,     4,     4,     4,     5,     3,     4,
       4,     5,     1,     2,     2,     2,     3,     3,     1,     2,
       2,     1,     1,     2,     3,     4,     3,     4,     2,     3,
       3,     4,     3,     3,     2,     2,     1,     1,     2,     1,
       1,     1,     1,     2,     1,     2,     3,     1,     1,     1,
       2,     1,     1,     2,     1,     4,     1,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     0,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     5,     3,     3,     1,     1,     3,
       1,     1,     1,     1,     1,     5,     8,     1,     1,     1,
       1,     3,     4,     5,     5,     5,     6,     6,     2,     2,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     5,     2,     2,     2,     2,
       2,     3,     1,     1,     1,     0,     3,     1,     1,     3,
       0,     4,     0,     6,     1,     1,     1,     1,     1,     4,
       4,     1,     1,     1,     1,     1,     1,     1,     2,     2,
       4,     1,     1,     2,     4,     1,     1,     2,     1,     3,
       3,     4,     4,     3,     4,     2,     1,     1,     3,     4,
       6,     2,     2,     3,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     4,     1,     3,     1,     2,     3,     3,
       2,     2,     2,     1,     2,     1,     3,     2,     4,     1,
       3,     1,     3,     3,     2,     2,     2,     2,     1,     2,
       1,     1,     1,     1,     3,     1,     3,     5,     1,     3,
       3,     5,     1,     1,     0
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 1472 "parser.y" /* yacc.c:1646  */
    {
                   if (!classes) classes = NewHash();
		   Setattr((yyvsp[0].node),"classes",classes); 
		   Setattr((yyvsp[0].node),"name",ModuleName);
		   
		   if ((!module_node) && ModuleName) {
		     module_node = new_node("module");
		     Setattr(module_node,"name",ModuleName);
		   }
		   Setattr((yyvsp[0].node),"module",module_node);
	           top = (yyvsp[0].node);
               }
#line 4441 "y.tab.c" /* yacc.c:1646  */
    break;

  case 3:
#line 1484 "parser.y" /* yacc.c:1646  */
    {
                 top = Copy(Getattr((yyvsp[-1].p),"type"));
		 Delete((yyvsp[-1].p));
               }
#line 4450 "y.tab.c" /* yacc.c:1646  */
    break;

  case 4:
#line 1488 "parser.y" /* yacc.c:1646  */
    {
                 top = 0;
               }
#line 4458 "y.tab.c" /* yacc.c:1646  */
    break;

  case 5:
#line 1491 "parser.y" /* yacc.c:1646  */
    {
                 top = (yyvsp[-1].p);
               }
#line 4466 "y.tab.c" /* yacc.c:1646  */
    break;

  case 6:
#line 1494 "parser.y" /* yacc.c:1646  */
    {
                 top = 0;
               }
#line 4474 "y.tab.c" /* yacc.c:1646  */
    break;

  case 7:
#line 1497 "parser.y" /* yacc.c:1646  */
    {
                 top = (yyvsp[-2].pl);
               }
#line 4482 "y.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 1500 "parser.y" /* yacc.c:1646  */
    {
                 top = 0;
               }
#line 4490 "y.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 1505 "parser.y" /* yacc.c:1646  */
    {  
                   /* add declaration to end of linked list (the declaration isn't always a single declaration, sometimes it is a linked list itself) */
                   appendChild((yyvsp[-1].node),(yyvsp[0].node));
                   (yyval.node) = (yyvsp[-1].node);
               }
#line 4500 "y.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 1510 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = new_node("top");
               }
#line 4508 "y.tab.c" /* yacc.c:1646  */
    break;

  case 11:
#line 1515 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4514 "y.tab.c" /* yacc.c:1646  */
    break;

  case 12:
#line 1516 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4520 "y.tab.c" /* yacc.c:1646  */
    break;

  case 13:
#line 1517 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4526 "y.tab.c" /* yacc.c:1646  */
    break;

  case 14:
#line 1518 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 4532 "y.tab.c" /* yacc.c:1646  */
    break;

  case 15:
#line 1519 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.node) = 0;
		  if (cparse_unknown_directive) {
		      Swig_error(cparse_file, cparse_line, "Unknown directive '%s'.\n", cparse_unknown_directive);
		  } else {
		      Swig_error(cparse_file, cparse_line, "Syntax error in input(1).\n");
		  }
		  exit(1);
               }
#line 4546 "y.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 1529 "parser.y" /* yacc.c:1646  */
    { 
                  if ((yyval.node)) {
   		      add_symbols((yyval.node));
                  }
                  (yyval.node) = (yyvsp[0].node); 
	       }
#line 4557 "y.tab.c" /* yacc.c:1646  */
    break;

  case 17:
#line 1545 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.node) = 0;
                  skip_decl();
               }
#line 4566 "y.tab.c" /* yacc.c:1646  */
    break;

  case 18:
#line 1555 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4572 "y.tab.c" /* yacc.c:1646  */
    break;

  case 19:
#line 1556 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4578 "y.tab.c" /* yacc.c:1646  */
    break;

  case 20:
#line 1557 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4584 "y.tab.c" /* yacc.c:1646  */
    break;

  case 21:
#line 1558 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4590 "y.tab.c" /* yacc.c:1646  */
    break;

  case 22:
#line 1559 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4596 "y.tab.c" /* yacc.c:1646  */
    break;

  case 23:
#line 1560 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4602 "y.tab.c" /* yacc.c:1646  */
    break;

  case 24:
#line 1561 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4608 "y.tab.c" /* yacc.c:1646  */
    break;

  case 25:
#line 1562 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4614 "y.tab.c" /* yacc.c:1646  */
    break;

  case 26:
#line 1563 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4620 "y.tab.c" /* yacc.c:1646  */
    break;

  case 27:
#line 1564 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4626 "y.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 1565 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4632 "y.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 1566 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4638 "y.tab.c" /* yacc.c:1646  */
    break;

  case 30:
#line 1567 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4644 "y.tab.c" /* yacc.c:1646  */
    break;

  case 31:
#line 1568 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4650 "y.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 1569 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4656 "y.tab.c" /* yacc.c:1646  */
    break;

  case 33:
#line 1570 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4662 "y.tab.c" /* yacc.c:1646  */
    break;

  case 34:
#line 1571 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4668 "y.tab.c" /* yacc.c:1646  */
    break;

  case 35:
#line 1572 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4674 "y.tab.c" /* yacc.c:1646  */
    break;

  case 36:
#line 1573 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4680 "y.tab.c" /* yacc.c:1646  */
    break;

  case 37:
#line 1574 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4686 "y.tab.c" /* yacc.c:1646  */
    break;

  case 38:
#line 1575 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 4692 "y.tab.c" /* yacc.c:1646  */
    break;

  case 39:
#line 1582 "parser.y" /* yacc.c:1646  */
    {
               Node *cls;
	       String *clsname;
	       extendmode = 1;
	       cplus_mode = CPLUS_PUBLIC;
	       if (!classes) classes = NewHash();
	       if (!classes_typedefs) classes_typedefs = NewHash();
	       clsname = make_class_name((yyvsp[-1].str));
	       cls = Getattr(classes,clsname);
	       if (!cls) {
	         cls = Getattr(classes_typedefs, clsname);
		 if (!cls) {
		   /* No previous definition. Create a new scope */
		   Node *am = Getattr(Swig_extend_hash(),clsname);
		   if (!am) {
		     Swig_symbol_newscope();
		     Swig_symbol_setscopename((yyvsp[-1].str));
		     prev_symtab = 0;
		   } else {
		     prev_symtab = Swig_symbol_setscope(Getattr(am,"symtab"));
		   }
		   current_class = 0;
		 } else {
		   /* Previous typedef class definition.  Use its symbol table.
		      Deprecated, just the real name should be used. 
		      Note that %extend before the class typedef never worked, only %extend after the class typdef. */
		   prev_symtab = Swig_symbol_setscope(Getattr(cls, "symtab"));
		   current_class = cls;
		   SWIG_WARN_NODE_BEGIN(cls);
		   Swig_warning(WARN_PARSE_EXTEND_NAME, cparse_file, cparse_line, "Deprecated %%extend name used - the %s name '%s' should be used instead of the typedef name '%s'.\n", Getattr(cls, "kind"), SwigType_namestr(Getattr(cls, "name")), (yyvsp[-1].str));
		   SWIG_WARN_NODE_END(cls);
		 }
	       } else {
		 /* Previous class definition.  Use its symbol table */
		 prev_symtab = Swig_symbol_setscope(Getattr(cls,"symtab"));
		 current_class = cls;
	       }
	       Classprefix = NewString((yyvsp[-1].str));
	       Namespaceprefix= Swig_symbol_qualifiedscopename(0);
	       Delete(clsname);
	     }
#line 4738 "y.tab.c" /* yacc.c:1646  */
    break;

  case 40:
#line 1622 "parser.y" /* yacc.c:1646  */
    {
               String *clsname;
	       extendmode = 0;
               (yyval.node) = new_node("extend");
	       Setattr((yyval.node),"symtab",Swig_symbol_popscope());
	       if (prev_symtab) {
		 Swig_symbol_setscope(prev_symtab);
	       }
	       Namespaceprefix = Swig_symbol_qualifiedscopename(0);
               clsname = make_class_name((yyvsp[-4].str));
	       Setattr((yyval.node),"name",clsname);

	       mark_nodes_as_extend((yyvsp[-1].node));
	       if (current_class) {
		 /* We add the extension to the previously defined class */
		 appendChild((yyval.node),(yyvsp[-1].node));
		 appendChild(current_class,(yyval.node));
	       } else {
		 /* We store the extensions in the extensions hash */
		 Node *am = Getattr(Swig_extend_hash(),clsname);
		 if (am) {
		   /* Append the members to the previous extend methods */
		   appendChild(am,(yyvsp[-1].node));
		 } else {
		   appendChild((yyval.node),(yyvsp[-1].node));
		   Setattr(Swig_extend_hash(),clsname,(yyval.node));
		 }
	       }
	       current_class = 0;
	       Delete(Classprefix);
	       Delete(clsname);
	       Classprefix = 0;
	       prev_symtab = 0;
	       (yyval.node) = 0;

	     }
#line 4779 "y.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 1664 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.node) = new_node("apply");
                    Setattr((yyval.node),"pattern",Getattr((yyvsp[-3].p),"pattern"));
		    appendChild((yyval.node),(yyvsp[-1].p));
               }
#line 4789 "y.tab.c" /* yacc.c:1646  */
    break;

  case 42:
#line 1674 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = new_node("clear");
		 appendChild((yyval.node),(yyvsp[-1].p));
               }
#line 4798 "y.tab.c" /* yacc.c:1646  */
    break;

  case 43:
#line 1685 "parser.y" /* yacc.c:1646  */
    {
		   if (((yyvsp[-1].dtype).type != T_ERROR) && ((yyvsp[-1].dtype).type != T_SYMBOL)) {
		     SwigType *type = NewSwigType((yyvsp[-1].dtype).type);
		     (yyval.node) = new_node("constant");
		     Setattr((yyval.node),"name",(yyvsp[-3].id));
		     Setattr((yyval.node),"type",type);
		     Setattr((yyval.node),"value",(yyvsp[-1].dtype).val);
		     if ((yyvsp[-1].dtype).rawval) Setattr((yyval.node),"rawval", (yyvsp[-1].dtype).rawval);
		     Setattr((yyval.node),"storage","%constant");
		     SetFlag((yyval.node),"feature:immutable");
		     add_symbols((yyval.node));
		     Delete(type);
		   } else {
		     if ((yyvsp[-1].dtype).type == T_ERROR) {
		       Swig_warning(WARN_PARSE_UNSUPPORTED_VALUE,cparse_file,cparse_line,"Unsupported constant value (ignored)\n");
		     }
		     (yyval.node) = 0;
		   }

	       }
#line 4823 "y.tab.c" /* yacc.c:1646  */
    break;

  case 44:
#line 1706 "parser.y" /* yacc.c:1646  */
    {
		 if (((yyvsp[-1].dtype).type != T_ERROR) && ((yyvsp[-1].dtype).type != T_SYMBOL)) {
		   SwigType_push((yyvsp[-3].type),(yyvsp[-2].decl).type);
		   /* Sneaky callback function trick */
		   if (SwigType_isfunction((yyvsp[-3].type))) {
		     SwigType_add_pointer((yyvsp[-3].type));
		   }
		   (yyval.node) = new_node("constant");
		   Setattr((yyval.node),"name",(yyvsp[-2].decl).id);
		   Setattr((yyval.node),"type",(yyvsp[-3].type));
		   Setattr((yyval.node),"value",(yyvsp[-1].dtype).val);
		   if ((yyvsp[-1].dtype).rawval) Setattr((yyval.node),"rawval", (yyvsp[-1].dtype).rawval);
		   Setattr((yyval.node),"storage","%constant");
		   SetFlag((yyval.node),"feature:immutable");
		   add_symbols((yyval.node));
		 } else {
		     if ((yyvsp[-1].dtype).type == T_ERROR) {
		       Swig_warning(WARN_PARSE_UNSUPPORTED_VALUE,cparse_file,cparse_line,"Unsupported constant value\n");
		     }
		   (yyval.node) = 0;
		 }
               }
#line 4850 "y.tab.c" /* yacc.c:1646  */
    break;

  case 45:
#line 1728 "parser.y" /* yacc.c:1646  */
    {
		 Swig_warning(WARN_PARSE_BAD_VALUE,cparse_file,cparse_line,"Bad constant value (ignored).\n");
		 (yyval.node) = 0;
	       }
#line 4859 "y.tab.c" /* yacc.c:1646  */
    break;

  case 46:
#line 1739 "parser.y" /* yacc.c:1646  */
    {
		 char temp[64];
		 Replace((yyvsp[0].str),"$file",cparse_file, DOH_REPLACE_ANY);
		 sprintf(temp,"%d", cparse_line);
		 Replace((yyvsp[0].str),"$line",temp,DOH_REPLACE_ANY);
		 Printf(stderr,"%s\n", (yyvsp[0].str));
		 Delete((yyvsp[0].str));
                 (yyval.node) = 0;
	       }
#line 4873 "y.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 1748 "parser.y" /* yacc.c:1646  */
    {
		 char temp[64];
		 String *s = (yyvsp[0].str);
		 Replace(s,"$file",cparse_file, DOH_REPLACE_ANY);
		 sprintf(temp,"%d", cparse_line);
		 Replace(s,"$line",temp,DOH_REPLACE_ANY);
		 Printf(stderr,"%s\n", s);
		 Delete(s);
                 (yyval.node) = 0;
               }
#line 4888 "y.tab.c" /* yacc.c:1646  */
    break;

  case 48:
#line 1767 "parser.y" /* yacc.c:1646  */
    {
                    skip_balanced('{','}');
		    (yyval.node) = 0;
		    Swig_warning(WARN_DEPRECATED_EXCEPT,cparse_file, cparse_line, "%%except is deprecated.  Use %%exception instead.\n");
	       }
#line 4898 "y.tab.c" /* yacc.c:1646  */
    break;

  case 49:
#line 1773 "parser.y" /* yacc.c:1646  */
    {
                    skip_balanced('{','}');
		    (yyval.node) = 0;
		    Swig_warning(WARN_DEPRECATED_EXCEPT,cparse_file, cparse_line, "%%except is deprecated.  Use %%exception instead.\n");
               }
#line 4908 "y.tab.c" /* yacc.c:1646  */
    break;

  case 50:
#line 1779 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = 0;
		 Swig_warning(WARN_DEPRECATED_EXCEPT,cparse_file, cparse_line, "%%except is deprecated.  Use %%exception instead.\n");
               }
#line 4917 "y.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 1784 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = 0;
		 Swig_warning(WARN_DEPRECATED_EXCEPT,cparse_file, cparse_line, "%%except is deprecated.  Use %%exception instead.\n");
	       }
#line 4926 "y.tab.c" /* yacc.c:1646  */
    break;

  case 52:
#line 1791 "parser.y" /* yacc.c:1646  */
    {		 
                 (yyval.node) = NewHash();
                 Setattr((yyval.node),"value",(yyvsp[-3].str));
		 Setattr((yyval.node),"type",Getattr((yyvsp[-1].p),"type"));
               }
#line 4936 "y.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 1798 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NewHash();
                 Setattr((yyval.node),"value",(yyvsp[0].str));
              }
#line 4945 "y.tab.c" /* yacc.c:1646  */
    break;

  case 54:
#line 1802 "parser.y" /* yacc.c:1646  */
    {
                (yyval.node) = (yyvsp[0].node);
              }
#line 4953 "y.tab.c" /* yacc.c:1646  */
    break;

  case 55:
#line 1815 "parser.y" /* yacc.c:1646  */
    {
                   Hash *p = (yyvsp[-2].node);
		   (yyval.node) = new_node("fragment");
		   Setattr((yyval.node),"value",Getattr((yyvsp[-4].node),"value"));
		   Setattr((yyval.node),"type",Getattr((yyvsp[-4].node),"type"));
		   Setattr((yyval.node),"section",Getattr(p,"name"));
		   Setattr((yyval.node),"kwargs",nextSibling(p));
		   Setattr((yyval.node),"code",(yyvsp[0].str));
                 }
#line 4967 "y.tab.c" /* yacc.c:1646  */
    break;

  case 56:
#line 1824 "parser.y" /* yacc.c:1646  */
    {
		   Hash *p = (yyvsp[-2].node);
		   String *code;
                   skip_balanced('{','}');
		   (yyval.node) = new_node("fragment");
		   Setattr((yyval.node),"value",Getattr((yyvsp[-4].node),"value"));
		   Setattr((yyval.node),"type",Getattr((yyvsp[-4].node),"type"));
		   Setattr((yyval.node),"section",Getattr(p,"name"));
		   Setattr((yyval.node),"kwargs",nextSibling(p));
		   Delitem(scanner_ccode,0);
		   Delitem(scanner_ccode,DOH_END);
		   code = Copy(scanner_ccode);
		   Setattr((yyval.node),"code",code);
		   Delete(code);
                 }
#line 4987 "y.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 1839 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = new_node("fragment");
		   Setattr((yyval.node),"value",Getattr((yyvsp[-2].node),"value"));
		   Setattr((yyval.node),"type",Getattr((yyvsp[-2].node),"type"));
		   Setattr((yyval.node),"emitonly","1");
		 }
#line 4998 "y.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 1852 "parser.y" /* yacc.c:1646  */
    {
                     (yyvsp[-3].loc).filename = Copy(cparse_file);
		     (yyvsp[-3].loc).line = cparse_line;
		     scanner_set_location((yyvsp[-1].str),1);
                     if ((yyvsp[-2].node)) { 
		       String *maininput = Getattr((yyvsp[-2].node), "maininput");
		       if (maininput)
		         scanner_set_main_input_file(NewString(maininput));
		     }
               }
#line 5013 "y.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 1861 "parser.y" /* yacc.c:1646  */
    {
                     String *mname = 0;
                     (yyval.node) = (yyvsp[-1].node);
		     scanner_set_location((yyvsp[-6].loc).filename,(yyvsp[-6].loc).line+1);
		     if (strcmp((yyvsp[-6].loc).type,"include") == 0) set_nodeType((yyval.node),"include");
		     if (strcmp((yyvsp[-6].loc).type,"import") == 0) {
		       mname = (yyvsp[-5].node) ? Getattr((yyvsp[-5].node),"module") : 0;
		       set_nodeType((yyval.node),"import");
		       if (import_mode) --import_mode;
		     }
		     
		     Setattr((yyval.node),"name",(yyvsp[-4].str));
		     /* Search for the module (if any) */
		     {
			 Node *n = firstChild((yyval.node));
			 while (n) {
			     if (Strcmp(nodeType(n),"module") == 0) {
			         if (mname) {
				   Setattr(n,"name", mname);
				   mname = 0;
				 }
				 Setattr((yyval.node),"module",Getattr(n,"name"));
				 break;
			     }
			     n = nextSibling(n);
			 }
			 if (mname) {
			   /* There is no module node in the import
			      node, ie, you imported a .h file
			      directly.  We are forced then to create
			      a new import node with a module node.
			   */			      
			   Node *nint = new_node("import");
			   Node *mnode = new_node("module");
			   Setattr(mnode,"name", mname);
                           Setattr(mnode,"options",(yyvsp[-5].node));
			   appendChild(nint,mnode);
			   Delete(mnode);
			   appendChild(nint,firstChild((yyval.node)));
			   (yyval.node) = nint;
			   Setattr((yyval.node),"module",mname);
			 }
		     }
		     Setattr((yyval.node),"options",(yyvsp[-5].node));
               }
#line 5063 "y.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 1908 "parser.y" /* yacc.c:1646  */
    { (yyval.loc).type = "include"; }
#line 5069 "y.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 1909 "parser.y" /* yacc.c:1646  */
    { (yyval.loc).type = "import"; ++import_mode;}
#line 5075 "y.tab.c" /* yacc.c:1646  */
    break;

  case 62:
#line 1916 "parser.y" /* yacc.c:1646  */
    {
                 String *cpps;
		 if (Namespaceprefix) {
		   Swig_error(cparse_file, cparse_start_line, "%%inline directive inside a namespace is disallowed.\n");
		   (yyval.node) = 0;
		 } else {
		   (yyval.node) = new_node("insert");
		   Setattr((yyval.node),"code",(yyvsp[0].str));
		   /* Need to run through the preprocessor */
		   Seek((yyvsp[0].str),0,SEEK_SET);
		   Setline((yyvsp[0].str),cparse_start_line);
		   Setfile((yyvsp[0].str),cparse_file);
		   cpps = Preprocessor_parse((yyvsp[0].str));
		   start_inline(Char(cpps), cparse_start_line);
		   Delete((yyvsp[0].str));
		   Delete(cpps);
		 }
		 
	       }
#line 5099 "y.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 1935 "parser.y" /* yacc.c:1646  */
    {
                 String *cpps;
		 int start_line = cparse_line;
		 skip_balanced('{','}');
		 if (Namespaceprefix) {
		   Swig_error(cparse_file, cparse_start_line, "%%inline directive inside a namespace is disallowed.\n");
		   
		   (yyval.node) = 0;
		 } else {
		   String *code;
                   (yyval.node) = new_node("insert");
		   Delitem(scanner_ccode,0);
		   Delitem(scanner_ccode,DOH_END);
		   code = Copy(scanner_ccode);
		   Setattr((yyval.node),"code", code);
		   Delete(code);		   
		   cpps=Copy(scanner_ccode);
		   start_inline(Char(cpps), start_line);
		   Delete(cpps);
		 }
               }
#line 5125 "y.tab.c" /* yacc.c:1646  */
    break;

  case 64:
#line 1966 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = new_node("insert");
		 Setattr((yyval.node),"code",(yyvsp[0].str));
	       }
#line 5134 "y.tab.c" /* yacc.c:1646  */
    break;

  case 65:
#line 1970 "parser.y" /* yacc.c:1646  */
    {
		 String *code = NewStringEmpty();
		 (yyval.node) = new_node("insert");
		 Setattr((yyval.node),"section",(yyvsp[-2].id));
		 Setattr((yyval.node),"code",code);
		 if (Swig_insert_file((yyvsp[0].str),code) < 0) {
		   Swig_error(cparse_file, cparse_line, "Couldn't find '%s'.\n", (yyvsp[0].str));
		   (yyval.node) = 0;
		 } 
               }
#line 5149 "y.tab.c" /* yacc.c:1646  */
    break;

  case 66:
#line 1980 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = new_node("insert");
		 Setattr((yyval.node),"section",(yyvsp[-2].id));
		 Setattr((yyval.node),"code",(yyvsp[0].str));
               }
#line 5159 "y.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 1985 "parser.y" /* yacc.c:1646  */
    {
		 String *code;
                 skip_balanced('{','}');
		 (yyval.node) = new_node("insert");
		 Setattr((yyval.node),"section",(yyvsp[-2].id));
		 Delitem(scanner_ccode,0);
		 Delitem(scanner_ccode,DOH_END);
		 code = Copy(scanner_ccode);
		 Setattr((yyval.node),"code", code);
		 Delete(code);
	       }
#line 5175 "y.tab.c" /* yacc.c:1646  */
    break;

  case 68:
#line 2003 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = new_node("module");
		 if ((yyvsp[-1].node)) {
		   Setattr((yyval.node),"options",(yyvsp[-1].node));
		   if (Getattr((yyvsp[-1].node),"directors")) {
		     Wrapper_director_mode_set(1);
		     if (!cparse_cplusplus) {
		       Swig_error(cparse_file, cparse_line, "Directors are not supported for C code and require the -c++ option\n");
		     }
		   } 
		   if (Getattr((yyvsp[-1].node),"dirprot")) {
		     Wrapper_director_protected_mode_set(1);
		   } 
		   if (Getattr((yyvsp[-1].node),"allprotected")) {
		     Wrapper_all_protected_mode_set(1);
		   } 
		   if (Getattr((yyvsp[-1].node),"templatereduce")) {
		     template_reduce = 1;
		   }
		   if (Getattr((yyvsp[-1].node),"notemplatereduce")) {
		     template_reduce = 0;
		   }
		 }
		 if (!ModuleName) ModuleName = NewString((yyvsp[0].id));
		 if (!import_mode) {
		   /* first module included, we apply global
		      ModuleName, which can be modify by -module */
		   String *mname = Copy(ModuleName);
		   Setattr((yyval.node),"name",mname);
		   Delete(mname);
		 } else { 
		   /* import mode, we just pass the idstring */
		   Setattr((yyval.node),"name",(yyvsp[0].id));   
		 }		 
		 if (!module_node) module_node = (yyval.node);
	       }
#line 5216 "y.tab.c" /* yacc.c:1646  */
    break;

  case 69:
#line 2046 "parser.y" /* yacc.c:1646  */
    {
                 Swig_warning(WARN_DEPRECATED_NAME,cparse_file,cparse_line, "%%name is deprecated.  Use %%rename instead.\n");
		 Delete(yyrename);
                 yyrename = NewString((yyvsp[-1].id));
		 (yyval.node) = 0;
               }
#line 5227 "y.tab.c" /* yacc.c:1646  */
    break;

  case 70:
#line 2052 "parser.y" /* yacc.c:1646  */
    {
		 Swig_warning(WARN_DEPRECATED_NAME,cparse_file,cparse_line, "%%name is deprecated.  Use %%rename instead.\n");
		 (yyval.node) = 0;
		 Swig_error(cparse_file,cparse_line,"Missing argument to %%name directive.\n");
	       }
#line 5237 "y.tab.c" /* yacc.c:1646  */
    break;

  case 71:
#line 2065 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = new_node("native");
		 Setattr((yyval.node),"name",(yyvsp[-4].id));
		 Setattr((yyval.node),"wrap:name",(yyvsp[-1].id));
	         add_symbols((yyval.node));
	       }
#line 5248 "y.tab.c" /* yacc.c:1646  */
    break;

  case 72:
#line 2071 "parser.y" /* yacc.c:1646  */
    {
		 if (!SwigType_isfunction((yyvsp[-1].decl).type)) {
		   Swig_error(cparse_file,cparse_line,"%%native declaration '%s' is not a function.\n", (yyvsp[-1].decl).id);
		   (yyval.node) = 0;
		 } else {
		     Delete(SwigType_pop_function((yyvsp[-1].decl).type));
		     /* Need check for function here */
		     SwigType_push((yyvsp[-2].type),(yyvsp[-1].decl).type);
		     (yyval.node) = new_node("native");
	             Setattr((yyval.node),"name",(yyvsp[-5].id));
		     Setattr((yyval.node),"wrap:name",(yyvsp[-1].decl).id);
		     Setattr((yyval.node),"type",(yyvsp[-2].type));
		     Setattr((yyval.node),"parms",(yyvsp[-1].decl).parms);
		     Setattr((yyval.node),"decl",(yyvsp[-1].decl).type);
		 }
	         add_symbols((yyval.node));
	       }
#line 5270 "y.tab.c" /* yacc.c:1646  */
    break;

  case 73:
#line 2097 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = new_node("pragma");
		 Setattr((yyval.node),"lang",(yyvsp[-3].id));
		 Setattr((yyval.node),"name",(yyvsp[-2].id));
		 Setattr((yyval.node),"value",(yyvsp[0].str));
	       }
#line 5281 "y.tab.c" /* yacc.c:1646  */
    break;

  case 74:
#line 2103 "parser.y" /* yacc.c:1646  */
    {
		(yyval.node) = new_node("pragma");
		Setattr((yyval.node),"lang",(yyvsp[-1].id));
		Setattr((yyval.node),"name",(yyvsp[0].id));
	      }
#line 5291 "y.tab.c" /* yacc.c:1646  */
    break;

  case 75:
#line 2110 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[0].str); }
#line 5297 "y.tab.c" /* yacc.c:1646  */
    break;

  case 76:
#line 2111 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[0].str); }
#line 5303 "y.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 2114 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (yyvsp[-1].id); }
#line 5309 "y.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 2115 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (char *) "swig"; }
#line 5315 "y.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 2122 "parser.y" /* yacc.c:1646  */
    {
                SwigType *t = (yyvsp[-2].decl).type;
		Hash *kws = NewHash();
		String *fixname;
		fixname = feature_identifier_fix((yyvsp[-2].decl).id);
		Setattr(kws,"name",(yyvsp[-1].id));
		if (!Len(t)) t = 0;
		/* Special declarator check */
		if (t) {
		  if (SwigType_isfunction(t)) {
		    SwigType *decl = SwigType_pop_function(t);
		    if (SwigType_ispointer(t)) {
		      String *nname = NewStringf("*%s",fixname);
		      if ((yyvsp[-3].intvalue)) {
			Swig_name_rename_add(Namespaceprefix, nname,decl,kws,(yyvsp[-2].decl).parms);
		      } else {
			Swig_name_namewarn_add(Namespaceprefix,nname,decl,kws);
		      }
		      Delete(nname);
		    } else {
		      if ((yyvsp[-3].intvalue)) {
			Swig_name_rename_add(Namespaceprefix,(fixname),decl,kws,(yyvsp[-2].decl).parms);
		      } else {
			Swig_name_namewarn_add(Namespaceprefix,(fixname),decl,kws);
		      }
		    }
		    Delete(decl);
		  } else if (SwigType_ispointer(t)) {
		    String *nname = NewStringf("*%s",fixname);
		    if ((yyvsp[-3].intvalue)) {
		      Swig_name_rename_add(Namespaceprefix,(nname),0,kws,(yyvsp[-2].decl).parms);
		    } else {
		      Swig_name_namewarn_add(Namespaceprefix,(nname),0,kws);
		    }
		    Delete(nname);
		  }
		} else {
		  if ((yyvsp[-3].intvalue)) {
		    Swig_name_rename_add(Namespaceprefix,(fixname),0,kws,(yyvsp[-2].decl).parms);
		  } else {
		    Swig_name_namewarn_add(Namespaceprefix,(fixname),0,kws);
		  }
		}
                (yyval.node) = 0;
		scanner_clear_rename();
              }
#line 5366 "y.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 2168 "parser.y" /* yacc.c:1646  */
    {
		String *fixname;
		Hash *kws = (yyvsp[-4].node);
		SwigType *t = (yyvsp[-2].decl).type;
		fixname = feature_identifier_fix((yyvsp[-2].decl).id);
		if (!Len(t)) t = 0;
		/* Special declarator check */
		if (t) {
		  if ((yyvsp[-1].dtype).qualifier) SwigType_push(t,(yyvsp[-1].dtype).qualifier);
		  if (SwigType_isfunction(t)) {
		    SwigType *decl = SwigType_pop_function(t);
		    if (SwigType_ispointer(t)) {
		      String *nname = NewStringf("*%s",fixname);
		      if ((yyvsp[-6].intvalue)) {
			Swig_name_rename_add(Namespaceprefix, nname,decl,kws,(yyvsp[-2].decl).parms);
		      } else {
			Swig_name_namewarn_add(Namespaceprefix,nname,decl,kws);
		      }
		      Delete(nname);
		    } else {
		      if ((yyvsp[-6].intvalue)) {
			Swig_name_rename_add(Namespaceprefix,(fixname),decl,kws,(yyvsp[-2].decl).parms);
		      } else {
			Swig_name_namewarn_add(Namespaceprefix,(fixname),decl,kws);
		      }
		    }
		    Delete(decl);
		  } else if (SwigType_ispointer(t)) {
		    String *nname = NewStringf("*%s",fixname);
		    if ((yyvsp[-6].intvalue)) {
		      Swig_name_rename_add(Namespaceprefix,(nname),0,kws,(yyvsp[-2].decl).parms);
		    } else {
		      Swig_name_namewarn_add(Namespaceprefix,(nname),0,kws);
		    }
		    Delete(nname);
		  }
		} else {
		  if ((yyvsp[-6].intvalue)) {
		    Swig_name_rename_add(Namespaceprefix,(fixname),0,kws,(yyvsp[-2].decl).parms);
		  } else {
		    Swig_name_namewarn_add(Namespaceprefix,(fixname),0,kws);
		  }
		}
                (yyval.node) = 0;
		scanner_clear_rename();
              }
#line 5417 "y.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 2214 "parser.y" /* yacc.c:1646  */
    {
		if ((yyvsp[-5].intvalue)) {
		  Swig_name_rename_add(Namespaceprefix,(yyvsp[-1].str),0,(yyvsp[-3].node),0);
		} else {
		  Swig_name_namewarn_add(Namespaceprefix,(yyvsp[-1].str),0,(yyvsp[-3].node));
		}
		(yyval.node) = 0;
		scanner_clear_rename();
              }
#line 5431 "y.tab.c" /* yacc.c:1646  */
    break;

  case 82:
#line 2225 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.intvalue) = 1;
                }
#line 5439 "y.tab.c" /* yacc.c:1646  */
    break;

  case 83:
#line 2228 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.intvalue) = 0;
                }
#line 5447 "y.tab.c" /* yacc.c:1646  */
    break;

  case 84:
#line 2255 "parser.y" /* yacc.c:1646  */
    {
                    String *val = (yyvsp[0].str) ? NewString((yyvsp[0].str)) : NewString("1");
                    new_feature((yyvsp[-4].id), val, 0, (yyvsp[-2].decl).id, (yyvsp[-2].decl).type, (yyvsp[-2].decl).parms, (yyvsp[-1].dtype).qualifier);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5458 "y.tab.c" /* yacc.c:1646  */
    break;

  case 85:
#line 2261 "parser.y" /* yacc.c:1646  */
    {
                    String *val = Len((yyvsp[-4].str)) ? (yyvsp[-4].str) : 0;
                    new_feature((yyvsp[-6].id), val, 0, (yyvsp[-2].decl).id, (yyvsp[-2].decl).type, (yyvsp[-2].decl).parms, (yyvsp[-1].dtype).qualifier);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5469 "y.tab.c" /* yacc.c:1646  */
    break;

  case 86:
#line 2267 "parser.y" /* yacc.c:1646  */
    {
                    String *val = (yyvsp[0].str) ? NewString((yyvsp[0].str)) : NewString("1");
                    new_feature((yyvsp[-5].id), val, (yyvsp[-4].node), (yyvsp[-2].decl).id, (yyvsp[-2].decl).type, (yyvsp[-2].decl).parms, (yyvsp[-1].dtype).qualifier);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5480 "y.tab.c" /* yacc.c:1646  */
    break;

  case 87:
#line 2273 "parser.y" /* yacc.c:1646  */
    {
                    String *val = Len((yyvsp[-5].str)) ? (yyvsp[-5].str) : 0;
                    new_feature((yyvsp[-7].id), val, (yyvsp[-4].node), (yyvsp[-2].decl).id, (yyvsp[-2].decl).type, (yyvsp[-2].decl).parms, (yyvsp[-1].dtype).qualifier);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5491 "y.tab.c" /* yacc.c:1646  */
    break;

  case 88:
#line 2281 "parser.y" /* yacc.c:1646  */
    {
                    String *val = (yyvsp[0].str) ? NewString((yyvsp[0].str)) : NewString("1");
                    new_feature((yyvsp[-2].id), val, 0, 0, 0, 0, 0);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5502 "y.tab.c" /* yacc.c:1646  */
    break;

  case 89:
#line 2287 "parser.y" /* yacc.c:1646  */
    {
                    String *val = Len((yyvsp[-2].str)) ? (yyvsp[-2].str) : 0;
                    new_feature((yyvsp[-4].id), val, 0, 0, 0, 0, 0);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5513 "y.tab.c" /* yacc.c:1646  */
    break;

  case 90:
#line 2293 "parser.y" /* yacc.c:1646  */
    {
                    String *val = (yyvsp[0].str) ? NewString((yyvsp[0].str)) : NewString("1");
                    new_feature((yyvsp[-3].id), val, (yyvsp[-2].node), 0, 0, 0, 0);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5524 "y.tab.c" /* yacc.c:1646  */
    break;

  case 91:
#line 2299 "parser.y" /* yacc.c:1646  */
    {
                    String *val = Len((yyvsp[-3].str)) ? (yyvsp[-3].str) : 0;
                    new_feature((yyvsp[-5].id), val, (yyvsp[-2].node), 0, 0, 0, 0);
                    (yyval.node) = 0;
                    scanner_clear_rename();
                  }
#line 5535 "y.tab.c" /* yacc.c:1646  */
    break;

  case 92:
#line 2307 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[0].str); }
#line 5541 "y.tab.c" /* yacc.c:1646  */
    break;

  case 93:
#line 2308 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = 0; }
#line 5547 "y.tab.c" /* yacc.c:1646  */
    break;

  case 94:
#line 2309 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[-2].pl); }
#line 5553 "y.tab.c" /* yacc.c:1646  */
    break;

  case 95:
#line 2312 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = NewHash();
		  Setattr((yyval.node),"name",(yyvsp[-2].id));
		  Setattr((yyval.node),"value",(yyvsp[0].str));
                }
#line 5563 "y.tab.c" /* yacc.c:1646  */
    break;

  case 96:
#line 2317 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = NewHash();
		  Setattr((yyval.node),"name",(yyvsp[-3].id));
		  Setattr((yyval.node),"value",(yyvsp[-1].str));
                  set_nextSibling((yyval.node),(yyvsp[0].node));
                }
#line 5574 "y.tab.c" /* yacc.c:1646  */
    break;

  case 97:
#line 2327 "parser.y" /* yacc.c:1646  */
    {
                 Parm *val;
		 String *name;
		 SwigType *t;
		 if (Namespaceprefix) name = NewStringf("%s::%s", Namespaceprefix, (yyvsp[-2].decl).id);
		 else name = NewString((yyvsp[-2].decl).id);
		 val = (yyvsp[-4].pl);
		 if ((yyvsp[-2].decl).parms) {
		   Setmeta(val,"parms",(yyvsp[-2].decl).parms);
		 }
		 t = (yyvsp[-2].decl).type;
		 if (!Len(t)) t = 0;
		 if (t) {
		   if ((yyvsp[-1].dtype).qualifier) SwigType_push(t,(yyvsp[-1].dtype).qualifier);
		   if (SwigType_isfunction(t)) {
		     SwigType *decl = SwigType_pop_function(t);
		     if (SwigType_ispointer(t)) {
		       String *nname = NewStringf("*%s",name);
		       Swig_feature_set(Swig_cparse_features(), nname, decl, "feature:varargs", val, 0);
		       Delete(nname);
		     } else {
		       Swig_feature_set(Swig_cparse_features(), name, decl, "feature:varargs", val, 0);
		     }
		     Delete(decl);
		   } else if (SwigType_ispointer(t)) {
		     String *nname = NewStringf("*%s",name);
		     Swig_feature_set(Swig_cparse_features(),nname,0,"feature:varargs",val, 0);
		     Delete(nname);
		   }
		 } else {
		   Swig_feature_set(Swig_cparse_features(),name,0,"feature:varargs",val, 0);
		 }
		 Delete(name);
		 (yyval.node) = 0;
              }
#line 5614 "y.tab.c" /* yacc.c:1646  */
    break;

  case 98:
#line 2363 "parser.y" /* yacc.c:1646  */
    { (yyval.pl) = (yyvsp[0].pl); }
#line 5620 "y.tab.c" /* yacc.c:1646  */
    break;

  case 99:
#line 2364 "parser.y" /* yacc.c:1646  */
    { 
		  int i;
		  int n;
		  Parm *p;
		  n = atoi(Char((yyvsp[-2].dtype).val));
		  if (n <= 0) {
		    Swig_error(cparse_file, cparse_line,"Argument count in %%varargs must be positive.\n");
		    (yyval.pl) = 0;
		  } else {
		    String *name = Getattr((yyvsp[0].p), "name");
		    (yyval.pl) = Copy((yyvsp[0].p));
		    if (name)
		      Setattr((yyval.pl), "name", NewStringf("%s%d", name, n));
		    for (i = 1; i < n; i++) {
		      p = Copy((yyvsp[0].p));
		      name = Getattr(p, "name");
		      if (name)
		        Setattr(p, "name", NewStringf("%s%d", name, n-i));
		      set_nextSibling(p,(yyval.pl));
		      Delete((yyval.pl));
		      (yyval.pl) = p;
		    }
		  }
                }
#line 5649 "y.tab.c" /* yacc.c:1646  */
    break;

  case 100:
#line 2399 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = 0;
		   if ((yyvsp[-3].tmap).method) {
		     String *code = 0;
		     (yyval.node) = new_node("typemap");
		     Setattr((yyval.node),"method",(yyvsp[-3].tmap).method);
		     if ((yyvsp[-3].tmap).kwargs) {
		       ParmList *kw = (yyvsp[-3].tmap).kwargs;
                       code = remove_block(kw, (yyvsp[0].str));
		       Setattr((yyval.node),"kwargs", (yyvsp[-3].tmap).kwargs);
		     }
		     code = code ? code : NewString((yyvsp[0].str));
		     Setattr((yyval.node),"code", code);
		     Delete(code);
		     appendChild((yyval.node),(yyvsp[-1].p));
		   }
	       }
#line 5671 "y.tab.c" /* yacc.c:1646  */
    break;

  case 101:
#line 2416 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = 0;
		 if ((yyvsp[-3].tmap).method) {
		   (yyval.node) = new_node("typemap");
		   Setattr((yyval.node),"method",(yyvsp[-3].tmap).method);
		   appendChild((yyval.node),(yyvsp[-1].p));
		 }
	       }
#line 5684 "y.tab.c" /* yacc.c:1646  */
    break;

  case 102:
#line 2424 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = 0;
		   if ((yyvsp[-5].tmap).method) {
		     (yyval.node) = new_node("typemapcopy");
		     Setattr((yyval.node),"method",(yyvsp[-5].tmap).method);
		     Setattr((yyval.node),"pattern", Getattr((yyvsp[-1].p),"pattern"));
		     appendChild((yyval.node),(yyvsp[-3].p));
		   }
	       }
#line 5698 "y.tab.c" /* yacc.c:1646  */
    break;

  case 103:
#line 2437 "parser.y" /* yacc.c:1646  */
    {
		 Hash *p;
		 String *name;
		 p = nextSibling((yyvsp[0].node));
		 if (p && (!Getattr(p,"value"))) {
 		   /* this is the deprecated two argument typemap form */
 		   Swig_warning(WARN_DEPRECATED_TYPEMAP_LANG,cparse_file, cparse_line,
				"Specifying the language name in %%typemap is deprecated - use #ifdef SWIG<LANG> instead.\n");
		   /* two argument typemap form */
		   name = Getattr((yyvsp[0].node),"name");
		   if (!name || (Strcmp(name,typemap_lang))) {
		     (yyval.tmap).method = 0;
		     (yyval.tmap).kwargs = 0;
		   } else {
		     (yyval.tmap).method = Getattr(p,"name");
		     (yyval.tmap).kwargs = nextSibling(p);
		   }
		 } else {
		   /* one-argument typemap-form */
		   (yyval.tmap).method = Getattr((yyvsp[0].node),"name");
		   (yyval.tmap).kwargs = p;
		 }
                }
#line 5726 "y.tab.c" /* yacc.c:1646  */
    break;

  case 104:
#line 2462 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.p) = (yyvsp[-1].p);
		 set_nextSibling((yyval.p),(yyvsp[0].p));
		}
#line 5735 "y.tab.c" /* yacc.c:1646  */
    break;

  case 105:
#line 2468 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.p) = (yyvsp[-1].p);
		 set_nextSibling((yyval.p),(yyvsp[0].p));
                }
#line 5744 "y.tab.c" /* yacc.c:1646  */
    break;

  case 106:
#line 2472 "parser.y" /* yacc.c:1646  */
    { (yyval.p) = 0;}
#line 5750 "y.tab.c" /* yacc.c:1646  */
    break;

  case 107:
#line 2475 "parser.y" /* yacc.c:1646  */
    {
                  Parm *parm;
		  SwigType_push((yyvsp[-1].type),(yyvsp[0].decl).type);
		  (yyval.p) = new_node("typemapitem");
		  parm = NewParmWithoutFileLineInfo((yyvsp[-1].type),(yyvsp[0].decl).id);
		  Setattr((yyval.p),"pattern",parm);
		  Setattr((yyval.p),"parms", (yyvsp[0].decl).parms);
		  Delete(parm);
		  /*		  $$ = NewParmWithoutFileLineInfo($1,$2.id);
				  Setattr($$,"parms",$2.parms); */
                }
#line 5766 "y.tab.c" /* yacc.c:1646  */
    break;

  case 108:
#line 2486 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.p) = new_node("typemapitem");
		  Setattr((yyval.p),"pattern",(yyvsp[-1].pl));
		  /*		  Setattr($$,"multitype",$2); */
               }
#line 5776 "y.tab.c" /* yacc.c:1646  */
    break;

  case 109:
#line 2491 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.p) = new_node("typemapitem");
		 Setattr((yyval.p),"pattern", (yyvsp[-4].pl));
		 /*                 Setattr($$,"multitype",$2); */
		 Setattr((yyval.p),"parms",(yyvsp[-1].pl));
               }
#line 5787 "y.tab.c" /* yacc.c:1646  */
    break;

  case 110:
#line 2504 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = new_node("types");
		   Setattr((yyval.node),"parms",(yyvsp[-2].pl));
                   if ((yyvsp[0].str))
		     Setattr((yyval.node),"convcode",NewString((yyvsp[0].str)));
               }
#line 5798 "y.tab.c" /* yacc.c:1646  */
    break;

  case 111:
#line 2516 "parser.y" /* yacc.c:1646  */
    {
                  Parm *p, *tp;
		  Node *n;
		  Node *outer_class = currentOuterClass;
		  Symtab *tscope = 0;
		  int     specialized = 0;
		  int     variadic = 0;

		  (yyval.node) = 0;

		  tscope = Swig_symbol_current();          /* Get the current scope */

		  /* If the class name is qualified, we need to create or lookup namespace entries */
		  if (!inclass) {
		    (yyvsp[-4].str) = resolve_create_node_scope((yyvsp[-4].str));
		  }
		  if (nscope_inner && Strcmp(nodeType(nscope_inner), "class") == 0) {
		    outer_class	= nscope_inner;
		  }

		  /*
		    We use the new namespace entry 'nscope' only to
		    emit the template node. The template parameters are
		    resolved in the current 'tscope'.

		    This is closer to the C++ (typedef) behavior.
		  */
		  n = Swig_cparse_template_locate((yyvsp[-4].str),(yyvsp[-2].p),tscope);

		  /* Patch the argument types to respect namespaces */
		  p = (yyvsp[-2].p);
		  while (p) {
		    SwigType *value = Getattr(p,"value");
		    if (!value) {
		      SwigType *ty = Getattr(p,"type");
		      if (ty) {
			SwigType *rty = 0;
			int reduce = template_reduce;
			if (reduce || !SwigType_ispointer(ty)) {
			  rty = Swig_symbol_typedef_reduce(ty,tscope);
			  if (!reduce) reduce = SwigType_ispointer(rty);
			}
			ty = reduce ? Swig_symbol_type_qualify(rty,tscope) : Swig_symbol_type_qualify(ty,tscope);
			Setattr(p,"type",ty);
			Delete(ty);
			Delete(rty);
		      }
		    } else {
		      value = Swig_symbol_type_qualify(value,tscope);
		      Setattr(p,"value",value);
		      Delete(value);
		    }

		    p = nextSibling(p);
		  }

		  /* Look for the template */
		  {
                    Node *nn = n;
                    Node *linklistend = 0;
                    while (nn) {
                      Node *templnode = 0;
                      if (Strcmp(nodeType(nn),"template") == 0) {
                        int nnisclass = (Strcmp(Getattr(nn,"templatetype"),"class") == 0); /* if not a templated class it is a templated function */
                        Parm *tparms = Getattr(nn,"templateparms");
                        if (!tparms) {
                          specialized = 1;
                        } else if (Getattr(tparms,"variadic") && strncmp(Char(Getattr(tparms,"variadic")), "1", 1)==0) {
                          variadic = 1;
                        }
                        if (nnisclass && !variadic && !specialized && (ParmList_len((yyvsp[-2].p)) > ParmList_len(tparms))) {
                          Swig_error(cparse_file, cparse_line, "Too many template parameters. Maximum of %d.\n", ParmList_len(tparms));
                        } else if (nnisclass && !specialized && ((ParmList_len((yyvsp[-2].p)) < (ParmList_numrequired(tparms) - (variadic?1:0))))) { /* Variadic parameter is optional */
                          Swig_error(cparse_file, cparse_line, "Not enough template parameters specified. %d required.\n", (ParmList_numrequired(tparms)-(variadic?1:0)) );
                        } else if (!nnisclass && ((ParmList_len((yyvsp[-2].p)) != ParmList_len(tparms)))) {
                          /* must be an overloaded templated method - ignore it as it is overloaded with a different number of template parameters */
                          nn = Getattr(nn,"sym:nextSibling"); /* repeat for overloaded templated functions */
                          continue;
                        } else {
			  String *tname = Copy((yyvsp[-4].str));
                          int def_supplied = 0;
                          /* Expand the template */
			  Node *templ = Swig_symbol_clookup((yyvsp[-4].str),0);
			  Parm *targs = templ ? Getattr(templ,"templateparms") : 0;

                          ParmList *temparms;
                          if (specialized) temparms = CopyParmList((yyvsp[-2].p));
                          else temparms = CopyParmList(tparms);

                          /* Create typedef's and arguments */
                          p = (yyvsp[-2].p);
                          tp = temparms;
                          if (!p && ParmList_len(p) != ParmList_len(temparms)) {
                            /* we have no template parameters supplied in %template for a template that has default args*/
                            p = tp;
                            def_supplied = 1;
                          }

                          while (p) {
                            String *value = Getattr(p,"value");
                            if (def_supplied) {
                              Setattr(p,"default","1");
                            }
                            if (value) {
                              Setattr(tp,"value",value);
                            } else {
                              SwigType *ty = Getattr(p,"type");
                              if (ty) {
                                Setattr(tp,"type",ty);
                              }
                              Delattr(tp,"value");
                            }
			    /* fix default arg values */
			    if (targs) {
			      Parm *pi = temparms;
			      Parm *ti = targs;
			      String *tv = Getattr(tp,"value");
			      if (!tv) tv = Getattr(tp,"type");
			      while(pi != tp && ti && pi) {
				String *name = Getattr(ti,"name");
				String *value = Getattr(pi,"value");
				if (!value) value = Getattr(pi,"type");
				Replaceid(tv, name, value);
				pi = nextSibling(pi);
				ti = nextSibling(ti);
			      }
			    }
                            p = nextSibling(p);
                            tp = nextSibling(tp);
                            if (!p && tp) {
                              p = tp;
                              def_supplied = 1;
                            } else if (p && !tp) { /* Variadic template - tp < p */
			      SWIG_WARN_NODE_BEGIN(nn);
                              Swig_warning(WARN_CPP11_VARIADIC_TEMPLATE,cparse_file, cparse_line,"Only the first variadic template argument is currently supported.\n");
			      SWIG_WARN_NODE_END(nn);
                              break;
                            }
                          }

                          templnode = copy_node(nn);
			  update_nested_classes(templnode); /* update classes nested withing template */
                          /* We need to set the node name based on name used to instantiate */
                          Setattr(templnode,"name",tname);
			  Delete(tname);
                          if (!specialized) {
                            Delattr(templnode,"sym:typename");
                          } else {
                            Setattr(templnode,"sym:typename","1");
                          }
			  /* for now, nested %template is allowed only in the same scope as the template declaration */
                          if ((yyvsp[-6].id) && !(nnisclass && ((outer_class && (outer_class != Getattr(nn, "nested:outer")))
			    ||(extendmode && current_class && (current_class != Getattr(nn, "nested:outer")))))) {
			    /*
			       Comment this out for 1.3.28. We need to
			       re-enable it later but first we need to
			       move %ignore from using %rename to use
			       %feature(ignore).

			       String *symname = Swig_name_make(templnode,0,$3,0,0);
			    */
			    String *symname = NewString((yyvsp[-6].id));
                            Swig_cparse_template_expand(templnode,symname,temparms,tscope);
                            Setattr(templnode,"sym:name",symname);
                          } else {
                            static int cnt = 0;
                            String *nname = NewStringf("__dummy_%d__", cnt++);
                            Swig_cparse_template_expand(templnode,nname,temparms,tscope);
                            Setattr(templnode,"sym:name",nname);
			    Delete(nname);
                            Setattr(templnode,"feature:onlychildren", "typemap,typemapitem,typemapcopy,typedef,types,fragment");
			    if ((yyvsp[-6].id)) {
			      Swig_warning(WARN_PARSE_NESTED_TEMPLATE, cparse_file, cparse_line, "Named nested template instantiations not supported. Processing as if no name was given to %%template().\n");
			    }
                          }
                          Delattr(templnode,"templatetype");
                          Setattr(templnode,"template",nn);
                          Setfile(templnode,cparse_file);
                          Setline(templnode,cparse_line);
                          Delete(temparms);
			  if (outer_class && nnisclass) {
			    SetFlag(templnode, "nested");
			    Setattr(templnode, "nested:outer", outer_class);
			  }
                          add_symbols_copy(templnode);

                          if (Strcmp(nodeType(templnode),"class") == 0) {

                            /* Identify pure abstract methods */
                            Setattr(templnode,"abstracts", pure_abstracts(firstChild(templnode)));

                            /* Set up inheritance in symbol table */
                            {
                              Symtab  *csyms;
                              List *baselist = Getattr(templnode,"baselist");
                              csyms = Swig_symbol_current();
                              Swig_symbol_setscope(Getattr(templnode,"symtab"));
                              if (baselist) {
                                List *bases = Swig_make_inherit_list(Getattr(templnode,"name"),baselist, Namespaceprefix);
                                if (bases) {
                                  Iterator s;
                                  for (s = First(bases); s.item; s = Next(s)) {
                                    Symtab *st = Getattr(s.item,"symtab");
                                    if (st) {
				      Setfile(st,Getfile(s.item));
				      Setline(st,Getline(s.item));
                                      Swig_symbol_inherit(st);
                                    }
                                  }
				  Delete(bases);
                                }
                              }
                              Swig_symbol_setscope(csyms);
                            }

                            /* Merge in %extend methods for this class */

			    /* !!! This may be broken.  We may have to add the
			       %extend methods at the beginning of the class */
                            {
                              String *stmp = 0;
                              String *clsname;
                              Node *am;
                              if (Namespaceprefix) {
                                clsname = stmp = NewStringf("%s::%s", Namespaceprefix, Getattr(templnode,"name"));
                              } else {
                                clsname = Getattr(templnode,"name");
                              }
                              am = Getattr(Swig_extend_hash(),clsname);
                              if (am) {
                                Symtab *st = Swig_symbol_current();
                                Swig_symbol_setscope(Getattr(templnode,"symtab"));
                                /*			    Printf(stdout,"%s: %s %p %p\n", Getattr(templnode,"name"), clsname, Swig_symbol_current(), Getattr(templnode,"symtab")); */
                                Swig_extend_merge(templnode,am);
                                Swig_symbol_setscope(st);
				Swig_extend_append_previous(templnode,am);
                                Delattr(Swig_extend_hash(),clsname);
                              }
			      if (stmp) Delete(stmp);
                            }

                            /* Add to classes hash */
			    if (!classes)
			      classes = NewHash();

			    if (Namespaceprefix) {
			      String *temp = NewStringf("%s::%s", Namespaceprefix, Getattr(templnode,"name"));
			      Setattr(classes,temp,templnode);
			      Delete(temp);
			    } else {
			      String *qs = Swig_symbol_qualifiedscopename(templnode);
			      Setattr(classes, qs,templnode);
			      Delete(qs);
			    }
                          }
                        }

                        /* all the overloaded templated functions are added into a linked list */
                        if (nscope_inner) {
                          /* non-global namespace */
                          if (templnode) {
                            appendChild(nscope_inner,templnode);
			    Delete(templnode);
                            if (nscope) (yyval.node) = nscope;
                          }
                        } else {
                          /* global namespace */
                          if (!linklistend) {
                            (yyval.node) = templnode;
                          } else {
                            set_nextSibling(linklistend,templnode);
			    Delete(templnode);
                          }
                          linklistend = templnode;
                        }
                      }
                      nn = Getattr(nn,"sym:nextSibling"); /* repeat for overloaded templated functions. If a templated class there will never be a sibling. */
                    }
		  }
	          Swig_symbol_setscope(tscope);
		  Delete(Namespaceprefix);
		  Namespaceprefix = Swig_symbol_qualifiedscopename(0);
                }
#line 6086 "y.tab.c" /* yacc.c:1646  */
    break;

  case 112:
#line 2806 "parser.y" /* yacc.c:1646  */
    {
		  Swig_warning(0,cparse_file, cparse_line,"%s\n", (yyvsp[0].str));
		  (yyval.node) = 0;
               }
#line 6095 "y.tab.c" /* yacc.c:1646  */
    break;

  case 113:
#line 2816 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.node) = (yyvsp[0].node); 
                    if ((yyval.node)) {
   		      add_symbols((yyval.node));
                      default_arguments((yyval.node));
   	            }
                }
#line 6107 "y.tab.c" /* yacc.c:1646  */
    break;

  case 114:
#line 2823 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 6113 "y.tab.c" /* yacc.c:1646  */
    break;

  case 115:
#line 2824 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 6119 "y.tab.c" /* yacc.c:1646  */
    break;

  case 116:
#line 2828 "parser.y" /* yacc.c:1646  */
    {
		  if (Strcmp((yyvsp[-1].str),"C") == 0) {
		    cparse_externc = 1;
		  }
		}
#line 6129 "y.tab.c" /* yacc.c:1646  */
    break;

  case 117:
#line 2832 "parser.y" /* yacc.c:1646  */
    {
		  cparse_externc = 0;
		  if (Strcmp((yyvsp[-4].str),"C") == 0) {
		    Node *n = firstChild((yyvsp[-1].node));
		    (yyval.node) = new_node("extern");
		    Setattr((yyval.node),"name",(yyvsp[-4].str));
		    appendChild((yyval.node),n);
		    while (n) {
		      SwigType *decl = Getattr(n,"decl");
		      if (SwigType_isfunction(decl) && !Equal(Getattr(n, "storage"), "typedef")) {
			Setattr(n,"storage","externc");
		      }
		      n = nextSibling(n);
		    }
		  } else {
		     Swig_warning(WARN_PARSE_UNDEFINED_EXTERN,cparse_file, cparse_line,"Unrecognized extern type \"%s\".\n", (yyvsp[-4].str));
		    (yyval.node) = new_node("extern");
		    Setattr((yyval.node),"name",(yyvsp[-4].str));
		    appendChild((yyval.node),firstChild((yyvsp[-1].node)));
		  }
                }
#line 6155 "y.tab.c" /* yacc.c:1646  */
    break;

  case 118:
#line 2853 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = (yyvsp[0].node);
		  SWIG_WARN_NODE_BEGIN((yyval.node));
		  Swig_warning(WARN_CPP11_LAMBDA, cparse_file, cparse_line, "Lambda expressions and closures are not fully supported yet.\n");
		  SWIG_WARN_NODE_END((yyval.node));
		}
#line 6166 "y.tab.c" /* yacc.c:1646  */
    break;

  case 119:
#line 2859 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = new_node("using");
		  Setattr((yyval.node),"name",(yyvsp[-4].str));
		  SwigType_push((yyvsp[-2].type),(yyvsp[-1].decl).type);
		  Setattr((yyval.node),"uname",(yyvsp[-2].type));
		  add_symbols((yyval.node));
		  SWIG_WARN_NODE_BEGIN((yyval.node));
		  Swig_warning(WARN_CPP11_ALIAS_DECLARATION, cparse_file, cparse_line, "The 'using' keyword in type aliasing is not fully supported yet.\n");
		  SWIG_WARN_NODE_END((yyval.node));

		  (yyval.node) = 0; /* TODO - ignored for now */
		}
#line 6183 "y.tab.c" /* yacc.c:1646  */
    break;

  case 120:
#line 2871 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = new_node("using");
		  Setattr((yyval.node),"name",(yyvsp[-4].str));
		  SwigType_push((yyvsp[-2].type),(yyvsp[-1].decl).type);
		  Setattr((yyval.node),"uname",(yyvsp[-2].type));
		  add_symbols((yyval.node));
		  SWIG_WARN_NODE_BEGIN((yyval.node));
		  Swig_warning(WARN_CPP11_ALIAS_TEMPLATE, cparse_file, cparse_line, "The 'using' keyword in template aliasing is not fully supported yet.\n");
		  SWIG_WARN_NODE_END((yyval.node));

		  (yyval.node) = 0; /* TODO - ignored for now */
		}
#line 6200 "y.tab.c" /* yacc.c:1646  */
    break;

  case 121:
#line 2889 "parser.y" /* yacc.c:1646  */
    {
              (yyval.node) = new_node("cdecl");
	      if ((yyvsp[-1].dtype).qualifier) SwigType_push((yyvsp[-2].decl).type,(yyvsp[-1].dtype).qualifier);
	      Setattr((yyval.node),"type",(yyvsp[-3].type));
	      Setattr((yyval.node),"storage",(yyvsp[-4].id));
	      Setattr((yyval.node),"name",(yyvsp[-2].decl).id);
	      Setattr((yyval.node),"decl",(yyvsp[-2].decl).type);
	      Setattr((yyval.node),"parms",(yyvsp[-2].decl).parms);
	      Setattr((yyval.node),"value",(yyvsp[-1].dtype).val);
	      Setattr((yyval.node),"throws",(yyvsp[-1].dtype).throws);
	      Setattr((yyval.node),"throw",(yyvsp[-1].dtype).throwf);
	      Setattr((yyval.node),"noexcept",(yyvsp[-1].dtype).nexcept);
	      if (!(yyvsp[0].node)) {
		if (Len(scanner_ccode)) {
		  String *code = Copy(scanner_ccode);
		  Setattr((yyval.node),"code",code);
		  Delete(code);
		}
	      } else {
		Node *n = (yyvsp[0].node);
		/* Inherit attributes */
		while (n) {
		  String *type = Copy((yyvsp[-3].type));
		  Setattr(n,"type",type);
		  Setattr(n,"storage",(yyvsp[-4].id));
		  n = nextSibling(n);
		  Delete(type);
		}
	      }
	      if ((yyvsp[-1].dtype).bitfield) {
		Setattr((yyval.node),"bitfield", (yyvsp[-1].dtype).bitfield);
	      }

	      /* Look for "::" declarations (ignored) */
	      if (Strstr((yyvsp[-2].decl).id,"::")) {
                /* This is a special case. If the scope name of the declaration exactly
                   matches that of the declaration, then we will allow it. Otherwise, delete. */
                String *p = Swig_scopename_prefix((yyvsp[-2].decl).id);
		if (p) {
		  if ((Namespaceprefix && Strcmp(p,Namespaceprefix) == 0) ||
		      (inclass && Strcmp(p,Classprefix) == 0)) {
		    String *lstr = Swig_scopename_last((yyvsp[-2].decl).id);
		    Setattr((yyval.node),"name",lstr);
		    Delete(lstr);
		    set_nextSibling((yyval.node),(yyvsp[0].node));
		  } else {
		    Delete((yyval.node));
		    (yyval.node) = (yyvsp[0].node);
		  }
		  Delete(p);
		} else {
		  Delete((yyval.node));
		  (yyval.node) = (yyvsp[0].node);
		}
	      } else {
		set_nextSibling((yyval.node),(yyvsp[0].node));
	      }
           }
#line 6263 "y.tab.c" /* yacc.c:1646  */
    break;

  case 122:
#line 2949 "parser.y" /* yacc.c:1646  */
    {
              (yyval.node) = new_node("cdecl");
	      if ((yyvsp[-1].dtype).qualifier) SwigType_push((yyvsp[-4].decl).type,(yyvsp[-1].dtype).qualifier);
	      Setattr((yyval.node),"type",(yyvsp[-2].node));
	      Setattr((yyval.node),"storage",(yyvsp[-6].id));
	      Setattr((yyval.node),"name",(yyvsp[-4].decl).id);
	      Setattr((yyval.node),"decl",(yyvsp[-4].decl).type);
	      Setattr((yyval.node),"parms",(yyvsp[-4].decl).parms);
	      Setattr((yyval.node),"value",(yyvsp[-1].dtype).val);
	      Setattr((yyval.node),"throws",(yyvsp[-1].dtype).throws);
	      Setattr((yyval.node),"throw",(yyvsp[-1].dtype).throwf);
	      Setattr((yyval.node),"noexcept",(yyvsp[-1].dtype).nexcept);
	      if (!(yyvsp[0].node)) {
		if (Len(scanner_ccode)) {
		  String *code = Copy(scanner_ccode);
		  Setattr((yyval.node),"code",code);
		  Delete(code);
		}
	      } else {
		Node *n = (yyvsp[0].node);
		while (n) {
		  String *type = Copy((yyvsp[-2].node));
		  Setattr(n,"type",type);
		  Setattr(n,"storage",(yyvsp[-6].id));
		  n = nextSibling(n);
		  Delete(type);
		}
	      }
	      if ((yyvsp[-1].dtype).bitfield) {
		Setattr((yyval.node),"bitfield", (yyvsp[-1].dtype).bitfield);
	      }

	      if (Strstr((yyvsp[-4].decl).id,"::")) {
                String *p = Swig_scopename_prefix((yyvsp[-4].decl).id);
		if (p) {
		  if ((Namespaceprefix && Strcmp(p,Namespaceprefix) == 0) ||
		      (inclass && Strcmp(p,Classprefix) == 0)) {
		    String *lstr = Swig_scopename_last((yyvsp[-4].decl).id);
		    Setattr((yyval.node),"name",lstr);
		    Delete(lstr);
		    set_nextSibling((yyval.node),(yyvsp[0].node));
		  } else {
		    Delete((yyval.node));
		    (yyval.node) = (yyvsp[0].node);
		  }
		  Delete(p);
		} else {
		  Delete((yyval.node));
		  (yyval.node) = (yyvsp[0].node);
		}
	      } else {
		set_nextSibling((yyval.node),(yyvsp[0].node));
	      }
           }
#line 6322 "y.tab.c" /* yacc.c:1646  */
    break;

  case 123:
#line 3007 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.node) = 0;
                   Clear(scanner_ccode); 
               }
#line 6331 "y.tab.c" /* yacc.c:1646  */
    break;

  case 124:
#line 3011 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = new_node("cdecl");
		 if ((yyvsp[-1].dtype).qualifier) SwigType_push((yyvsp[-2].decl).type,(yyvsp[-1].dtype).qualifier);
		 Setattr((yyval.node),"name",(yyvsp[-2].decl).id);
		 Setattr((yyval.node),"decl",(yyvsp[-2].decl).type);
		 Setattr((yyval.node),"parms",(yyvsp[-2].decl).parms);
		 Setattr((yyval.node),"value",(yyvsp[-1].dtype).val);
		 Setattr((yyval.node),"throws",(yyvsp[-1].dtype).throws);
		 Setattr((yyval.node),"throw",(yyvsp[-1].dtype).throwf);
		 Setattr((yyval.node),"noexcept",(yyvsp[-1].dtype).nexcept);
		 if ((yyvsp[-1].dtype).bitfield) {
		   Setattr((yyval.node),"bitfield", (yyvsp[-1].dtype).bitfield);
		 }
		 if (!(yyvsp[0].node)) {
		   if (Len(scanner_ccode)) {
		     String *code = Copy(scanner_ccode);
		     Setattr((yyval.node),"code",code);
		     Delete(code);
		   }
		 } else {
		   set_nextSibling((yyval.node),(yyvsp[0].node));
		 }
	       }
#line 6359 "y.tab.c" /* yacc.c:1646  */
    break;

  case 125:
#line 3034 "parser.y" /* yacc.c:1646  */
    { 
                   skip_balanced('{','}');
                   (yyval.node) = 0;
               }
#line 6368 "y.tab.c" /* yacc.c:1646  */
    break;

  case 126:
#line 3038 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = 0;
		   if (yychar == RPAREN) {
		       Swig_error(cparse_file, cparse_line, "Unexpected ')'.\n");
		   } else {
		       Swig_error(cparse_file, cparse_line, "Syntax error - possibly a missing semicolon.\n");
		   }
		   exit(1);
               }
#line 6382 "y.tab.c" /* yacc.c:1646  */
    break;

  case 127:
#line 3049 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.dtype) = (yyvsp[0].dtype); 
                   (yyval.dtype).qualifier = 0;
		   (yyval.dtype).throws = 0;
		   (yyval.dtype).throwf = 0;
		   (yyval.dtype).nexcept = 0;
              }
#line 6394 "y.tab.c" /* yacc.c:1646  */
    break;

  case 128:
#line 3056 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.dtype) = (yyvsp[0].dtype); 
		   (yyval.dtype).qualifier = (yyvsp[-1].str);
		   (yyval.dtype).throws = 0;
		   (yyval.dtype).throwf = 0;
		   (yyval.dtype).nexcept = 0;
	      }
#line 6406 "y.tab.c" /* yacc.c:1646  */
    break;

  case 129:
#line 3063 "parser.y" /* yacc.c:1646  */
    { 
		   (yyval.dtype) = (yyvsp[0].dtype); 
                   (yyval.dtype).qualifier = 0;
		   (yyval.dtype).throws = (yyvsp[-1].dtype).throws;
		   (yyval.dtype).throwf = (yyvsp[-1].dtype).throwf;
		   (yyval.dtype).nexcept = (yyvsp[-1].dtype).nexcept;
              }
#line 6418 "y.tab.c" /* yacc.c:1646  */
    break;

  case 130:
#line 3070 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.dtype) = (yyvsp[0].dtype); 
                   (yyval.dtype).qualifier = (yyvsp[-2].str);
		   (yyval.dtype).throws = (yyvsp[-1].dtype).throws;
		   (yyval.dtype).throwf = (yyvsp[-1].dtype).throwf;
		   (yyval.dtype).nexcept = (yyvsp[-1].dtype).nexcept;
              }
#line 6430 "y.tab.c" /* yacc.c:1646  */
    break;

  case 131:
#line 3079 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].type); }
#line 6436 "y.tab.c" /* yacc.c:1646  */
    break;

  case 132:
#line 3080 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].type); }
#line 6442 "y.tab.c" /* yacc.c:1646  */
    break;

  case 133:
#line 3081 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].type); }
#line 6448 "y.tab.c" /* yacc.c:1646  */
    break;

  case 134:
#line 3085 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].type); }
#line 6454 "y.tab.c" /* yacc.c:1646  */
    break;

  case 135:
#line 3086 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].str); }
#line 6460 "y.tab.c" /* yacc.c:1646  */
    break;

  case 136:
#line 3087 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].type); }
#line 6466 "y.tab.c" /* yacc.c:1646  */
    break;

  case 137:
#line 3098 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = new_node("lambda");
		  Setattr((yyval.node),"name",(yyvsp[-8].str));
		  add_symbols((yyval.node));
	        }
#line 6476 "y.tab.c" /* yacc.c:1646  */
    break;

  case 138:
#line 3103 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = new_node("lambda");
		  Setattr((yyval.node),"name",(yyvsp[-10].str));
		  add_symbols((yyval.node));
		}
#line 6486 "y.tab.c" /* yacc.c:1646  */
    break;

  case 139:
#line 3108 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = new_node("lambda");
		  Setattr((yyval.node),"name",(yyvsp[-4].str));
		  add_symbols((yyval.node));
		}
#line 6496 "y.tab.c" /* yacc.c:1646  */
    break;

  case 140:
#line 3115 "parser.y" /* yacc.c:1646  */
    {
		  skip_balanced('[',']');
		  (yyval.node) = 0;
	        }
#line 6505 "y.tab.c" /* yacc.c:1646  */
    break;

  case 141:
#line 3121 "parser.y" /* yacc.c:1646  */
    {
		  skip_balanced('{','}');
		  (yyval.node) = 0;
		}
#line 6514 "y.tab.c" /* yacc.c:1646  */
    break;

  case 142:
#line 3126 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.pl) = 0;
		}
#line 6522 "y.tab.c" /* yacc.c:1646  */
    break;

  case 143:
#line 3129 "parser.y" /* yacc.c:1646  */
    {
		  skip_balanced('(',')');
		}
#line 6530 "y.tab.c" /* yacc.c:1646  */
    break;

  case 144:
#line 3131 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.pl) = 0;
		}
#line 6538 "y.tab.c" /* yacc.c:1646  */
    break;

  case 145:
#line 3142 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = (char *)"enum";
	      }
#line 6546 "y.tab.c" /* yacc.c:1646  */
    break;

  case 146:
#line 3145 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = (char *)"enum class";
	      }
#line 6554 "y.tab.c" /* yacc.c:1646  */
    break;

  case 147:
#line 3148 "parser.y" /* yacc.c:1646  */
    {
		   (yyval.node) = (char *)"enum struct";
	      }
#line 6562 "y.tab.c" /* yacc.c:1646  */
    break;

  case 148:
#line 3157 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = (yyvsp[0].type);
              }
#line 6570 "y.tab.c" /* yacc.c:1646  */
    break;

  case 149:
#line 3160 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 6576 "y.tab.c" /* yacc.c:1646  */
    break;

  case 150:
#line 3167 "parser.y" /* yacc.c:1646  */
    {
		   SwigType *ty = 0;
		   int scopedenum = (yyvsp[-2].id) && !Equal((yyvsp[-3].node), "enum");
		   (yyval.node) = new_node("enumforward");
		   ty = NewStringf("enum %s", (yyvsp[-2].id));
		   Setattr((yyval.node),"enumkey",(yyvsp[-3].node));
		   if (scopedenum)
		     SetFlag((yyval.node), "scopedenum");
		   Setattr((yyval.node),"name",(yyvsp[-2].id));
		   Setattr((yyval.node),"inherit",(yyvsp[-1].node));
		   Setattr((yyval.node),"type",ty);
		   Setattr((yyval.node),"sym:weak", "1");
		   add_symbols((yyval.node));
	      }
#line 6595 "y.tab.c" /* yacc.c:1646  */
    break;

  case 151:
#line 3189 "parser.y" /* yacc.c:1646  */
    {
		  SwigType *ty = 0;
		  int scopedenum = (yyvsp[-5].id) && !Equal((yyvsp[-6].node), "enum");
                  (yyval.node) = new_node("enum");
		  ty = NewStringf("enum %s", (yyvsp[-5].id));
		  Setattr((yyval.node),"enumkey",(yyvsp[-6].node));
		  if (scopedenum)
		    SetFlag((yyval.node), "scopedenum");
		  Setattr((yyval.node),"name",(yyvsp[-5].id));
		  Setattr((yyval.node),"inherit",(yyvsp[-4].node));
		  Setattr((yyval.node),"type",ty);
		  appendChild((yyval.node),(yyvsp[-2].node));
		  add_symbols((yyval.node));      /* Add to tag space */

		  if (scopedenum) {
		    Swig_symbol_newscope();
		    Swig_symbol_setscopename((yyvsp[-5].id));
		    Delete(Namespaceprefix);
		    Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		  }

		  add_symbols((yyvsp[-2].node));      /* Add enum values to appropriate enum or enum class scope */

		  if (scopedenum) {
		    Setattr((yyval.node),"symtab", Swig_symbol_popscope());
		    Delete(Namespaceprefix);
		    Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		  }
               }
#line 6629 "y.tab.c" /* yacc.c:1646  */
    break;

  case 152:
#line 3218 "parser.y" /* yacc.c:1646  */
    {
		 Node *n;
		 SwigType *ty = 0;
		 String   *unnamed = 0;
		 int       unnamedinstance = 0;
		 int scopedenum = (yyvsp[-7].id) && !Equal((yyvsp[-8].node), "enum");

		 (yyval.node) = new_node("enum");
		 Setattr((yyval.node),"enumkey",(yyvsp[-8].node));
		 if (scopedenum)
		   SetFlag((yyval.node), "scopedenum");
		 Setattr((yyval.node),"inherit",(yyvsp[-6].node));
		 if ((yyvsp[-7].id)) {
		   Setattr((yyval.node),"name",(yyvsp[-7].id));
		   ty = NewStringf("enum %s", (yyvsp[-7].id));
		 } else if ((yyvsp[-2].decl).id) {
		   unnamed = make_unnamed();
		   ty = NewStringf("enum %s", unnamed);
		   Setattr((yyval.node),"unnamed",unnamed);
                   /* name is not set for unnamed enum instances, e.g. enum { foo } Instance; */
		   if ((yyvsp[-9].id) && Cmp((yyvsp[-9].id),"typedef") == 0) {
		     Setattr((yyval.node),"name",(yyvsp[-2].decl).id);
                   } else {
                     unnamedinstance = 1;
                   }
		   Setattr((yyval.node),"storage",(yyvsp[-9].id));
		 }
		 if ((yyvsp[-2].decl).id && Cmp((yyvsp[-9].id),"typedef") == 0) {
		   Setattr((yyval.node),"tdname",(yyvsp[-2].decl).id);
                   Setattr((yyval.node),"allows_typedef","1");
                 }
		 appendChild((yyval.node),(yyvsp[-4].node));
		 n = new_node("cdecl");
		 Setattr(n,"type",ty);
		 Setattr(n,"name",(yyvsp[-2].decl).id);
		 Setattr(n,"storage",(yyvsp[-9].id));
		 Setattr(n,"decl",(yyvsp[-2].decl).type);
		 Setattr(n,"parms",(yyvsp[-2].decl).parms);
		 Setattr(n,"unnamed",unnamed);

                 if (unnamedinstance) {
		   SwigType *cty = NewString("enum ");
		   Setattr((yyval.node),"type",cty);
		   SetFlag((yyval.node),"unnamedinstance");
		   SetFlag(n,"unnamedinstance");
		   Delete(cty);
                 }
		 if ((yyvsp[0].node)) {
		   Node *p = (yyvsp[0].node);
		   set_nextSibling(n,p);
		   while (p) {
		     SwigType *cty = Copy(ty);
		     Setattr(p,"type",cty);
		     Setattr(p,"unnamed",unnamed);
		     Setattr(p,"storage",(yyvsp[-9].id));
		     Delete(cty);
		     p = nextSibling(p);
		   }
		 } else {
		   if (Len(scanner_ccode)) {
		     String *code = Copy(scanner_ccode);
		     Setattr(n,"code",code);
		     Delete(code);
		   }
		 }

                 /* Ensure that typedef enum ABC {foo} XYZ; uses XYZ for sym:name, like structs.
                  * Note that class_rename/yyrename are bit of a mess so used this simple approach to change the name. */
                 if ((yyvsp[-2].decl).id && (yyvsp[-7].id) && Cmp((yyvsp[-9].id),"typedef") == 0) {
		   String *name = NewString((yyvsp[-2].decl).id);
                   Setattr((yyval.node), "parser:makename", name);
		   Delete(name);
                 }

		 add_symbols((yyval.node));       /* Add enum to tag space */
		 set_nextSibling((yyval.node),n);
		 Delete(n);

		 if (scopedenum) {
		   Swig_symbol_newscope();
		   Swig_symbol_setscopename((yyvsp[-7].id));
		   Delete(Namespaceprefix);
		   Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		 }

		 add_symbols((yyvsp[-4].node));      /* Add enum values to appropriate enum or enum class scope */

		 if (scopedenum) {
		   Setattr((yyval.node),"symtab", Swig_symbol_popscope());
		   Delete(Namespaceprefix);
		   Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		 }

	         add_symbols(n);
		 Delete(unnamed);
	       }
#line 6730 "y.tab.c" /* yacc.c:1646  */
    break;

  case 153:
#line 3316 "parser.y" /* yacc.c:1646  */
    {
                   /* This is a sick hack.  If the ctor_end has parameters,
                      and the parms parameter only has 1 parameter, this
                      could be a declaration of the form:

                         type (id)(parms)

			 Otherwise it's an error. */
                    int err = 0;
                    (yyval.node) = 0;

		    if ((ParmList_len((yyvsp[-2].pl)) == 1) && (!Swig_scopename_check((yyvsp[-4].type)))) {
		      SwigType *ty = Getattr((yyvsp[-2].pl),"type");
		      String *name = Getattr((yyvsp[-2].pl),"name");
		      err = 1;
		      if (!name) {
			(yyval.node) = new_node("cdecl");
			Setattr((yyval.node),"type",(yyvsp[-4].type));
			Setattr((yyval.node),"storage",(yyvsp[-5].id));
			Setattr((yyval.node),"name",ty);

			if ((yyvsp[0].decl).have_parms) {
			  SwigType *decl = NewStringEmpty();
			  SwigType_add_function(decl,(yyvsp[0].decl).parms);
			  Setattr((yyval.node),"decl",decl);
			  Setattr((yyval.node),"parms",(yyvsp[0].decl).parms);
			  if (Len(scanner_ccode)) {
			    String *code = Copy(scanner_ccode);
			    Setattr((yyval.node),"code",code);
			    Delete(code);
			  }
			}
			if ((yyvsp[0].decl).defarg) {
			  Setattr((yyval.node),"value",(yyvsp[0].decl).defarg);
			}
			Setattr((yyval.node),"throws",(yyvsp[0].decl).throws);
			Setattr((yyval.node),"throw",(yyvsp[0].decl).throwf);
			Setattr((yyval.node),"noexcept",(yyvsp[0].decl).nexcept);
			err = 0;
		      }
		    }
		    if (err) {
		      Swig_error(cparse_file,cparse_line,"Syntax error in input(2).\n");
		      exit(1);
		    }
                }
#line 6781 "y.tab.c" /* yacc.c:1646  */
    break;

  case 154:
#line 3368 "parser.y" /* yacc.c:1646  */
    {  (yyval.node) = (yyvsp[0].node); }
#line 6787 "y.tab.c" /* yacc.c:1646  */
    break;

  case 155:
#line 3369 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 6793 "y.tab.c" /* yacc.c:1646  */
    break;

  case 156:
#line 3370 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 6799 "y.tab.c" /* yacc.c:1646  */
    break;

  case 157:
#line 3371 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 6805 "y.tab.c" /* yacc.c:1646  */
    break;

  case 158:
#line 3372 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 6811 "y.tab.c" /* yacc.c:1646  */
    break;

  case 159:
#line 3373 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 6817 "y.tab.c" /* yacc.c:1646  */
    break;

  case 160:
#line 3378 "parser.y" /* yacc.c:1646  */
    {
                   String *prefix;
                   List *bases = 0;
		   Node *scope = 0;
		   String *code;
		   (yyval.node) = new_node("class");
		   Setline((yyval.node),cparse_start_line);
		   Setattr((yyval.node),"kind",(yyvsp[-3].id));
		   if ((yyvsp[-1].bases)) {
		     Setattr((yyval.node),"baselist", Getattr((yyvsp[-1].bases),"public"));
		     Setattr((yyval.node),"protectedbaselist", Getattr((yyvsp[-1].bases),"protected"));
		     Setattr((yyval.node),"privatebaselist", Getattr((yyvsp[-1].bases),"private"));
		   }
		   Setattr((yyval.node),"allows_typedef","1");

		   /* preserve the current scope */
		   Setattr((yyval.node),"prev_symtab",Swig_symbol_current());
		  
		   /* If the class name is qualified.  We need to create or lookup namespace/scope entries */
		   scope = resolve_create_node_scope((yyvsp[-2].str));
		   /* save nscope_inner to the class - it may be overwritten in nested classes*/
		   Setattr((yyval.node), "nested:innerscope", nscope_inner);
		   Setattr((yyval.node), "nested:nscope", nscope);
		   Setfile(scope,cparse_file);
		   Setline(scope,cparse_line);
		   (yyvsp[-2].str) = scope;
		   Setattr((yyval.node),"name",(yyvsp[-2].str));

		   if (currentOuterClass) {
		     SetFlag((yyval.node), "nested");
		     Setattr((yyval.node), "nested:outer", currentOuterClass);
		     set_access_mode((yyval.node));
		   }
		   Swig_features_get(Swig_cparse_features(), Namespaceprefix, Getattr((yyval.node), "name"), 0, (yyval.node));
		   /* save yyrename to the class attribute, to be used later in add_symbols()*/
		   Setattr((yyval.node), "class_rename", make_name((yyval.node), (yyvsp[-2].str), 0));
		   Setattr((yyval.node), "Classprefix", (yyvsp[-2].str));
		   Classprefix = NewString((yyvsp[-2].str));
		   /* Deal with inheritance  */
		   if ((yyvsp[-1].bases))
		     bases = Swig_make_inherit_list((yyvsp[-2].str),Getattr((yyvsp[-1].bases),"public"),Namespaceprefix);
		   prefix = SwigType_istemplate_templateprefix((yyvsp[-2].str));
		   if (prefix) {
		     String *fbase, *tbase;
		     if (Namespaceprefix) {
		       fbase = NewStringf("%s::%s", Namespaceprefix,(yyvsp[-2].str));
		       tbase = NewStringf("%s::%s", Namespaceprefix, prefix);
		     } else {
		       fbase = Copy((yyvsp[-2].str));
		       tbase = Copy(prefix);
		     }
		     Swig_name_inherit(tbase,fbase);
		     Delete(fbase);
		     Delete(tbase);
		   }
                   if (strcmp((yyvsp[-3].id),"class") == 0) {
		     cplus_mode = CPLUS_PRIVATE;
		   } else {
		     cplus_mode = CPLUS_PUBLIC;
		   }
		   if (!cparse_cplusplus) {
		     set_scope_to_global();
		   }
		   Swig_symbol_newscope();
		   Swig_symbol_setscopename((yyvsp[-2].str));
		   Swig_inherit_base_symbols(bases);
		   Delete(Namespaceprefix);
		   Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		   cparse_start_line = cparse_line;

		   /* If there are active template parameters, we need to make sure they are
                      placed in the class symbol table so we can catch shadows */

		   if (template_parameters) {
		     Parm *tp = template_parameters;
		     while(tp) {
		       String *tpname = Copy(Getattr(tp,"name"));
		       Node *tn = new_node("templateparm");
		       Setattr(tn,"name",tpname);
		       Swig_symbol_cadd(tpname,tn);
		       tp = nextSibling(tp);
		       Delete(tpname);
		     }
		   }
		   Delete(prefix);
		   inclass = 1;
		   currentOuterClass = (yyval.node);
		   if (cparse_cplusplusout) {
		     /* save the structure declaration to declare it in global scope for C++ to see */
		     code = get_raw_text_balanced('{', '}');
		     Setattr((yyval.node), "code", code);
		     Delete(code);
		   }
               }
#line 6916 "y.tab.c" /* yacc.c:1646  */
    break;

  case 161:
#line 3471 "parser.y" /* yacc.c:1646  */
    {
		   Node *p;
		   SwigType *ty;
		   Symtab *cscope;
		   Node *am = 0;
		   String *scpname = 0;
		   (void) (yyvsp[-3].node);
		   (yyval.node) = currentOuterClass;
		   currentOuterClass = Getattr((yyval.node), "nested:outer");
		   nscope_inner = Getattr((yyval.node), "nested:innerscope");
		   nscope = Getattr((yyval.node), "nested:nscope");
		   Delattr((yyval.node), "nested:innerscope");
		   Delattr((yyval.node), "nested:nscope");
		   if (nscope_inner && Strcmp(nodeType(nscope_inner), "class") == 0) { /* actual parent class for this class */
		     Node* forward_declaration = Swig_symbol_clookup_no_inherit(Getattr((yyval.node),"name"), Getattr(nscope_inner, "symtab"));
		     if (forward_declaration) {
		       Setattr((yyval.node), "access", Getattr(forward_declaration, "access"));
		     }
		     Setattr((yyval.node), "nested:outer", nscope_inner);
		     SetFlag((yyval.node), "nested");
                   }
		   if (!currentOuterClass)
		     inclass = 0;
		   cscope = Getattr((yyval.node), "prev_symtab");
		   Delattr((yyval.node), "prev_symtab");
		   
		   /* Check for pure-abstract class */
		   Setattr((yyval.node),"abstracts", pure_abstracts((yyvsp[-2].node)));
		   
		   /* This bit of code merges in a previously defined %extend directive (if any) */
		   {
		     String *clsname = Swig_symbol_qualifiedscopename(0);
		     am = Getattr(Swig_extend_hash(), clsname);
		     if (am) {
		       Swig_extend_merge((yyval.node), am);
		       Delattr(Swig_extend_hash(), clsname);
		     }
		     Delete(clsname);
		   }
		   if (!classes) classes = NewHash();
		   scpname = Swig_symbol_qualifiedscopename(0);
		   Setattr(classes, scpname, (yyval.node));

		   appendChild((yyval.node), (yyvsp[-2].node));
		   
		   if (am) 
		     Swig_extend_append_previous((yyval.node), am);

		   p = (yyvsp[0].node);
		   if (p && !nscope_inner) {
		     if (!cparse_cplusplus && currentOuterClass)
		       appendChild(currentOuterClass, p);
		     else
		      appendSibling((yyval.node), p);
		   }
		   
		   if (nscope_inner) {
		     ty = NewString(scpname); /* if the class is declared out of scope, let the declarator use fully qualified type*/
		   } else if (cparse_cplusplus && !cparse_externc) {
		     ty = NewString((yyvsp[-6].str));
		   } else {
		     ty = NewStringf("%s %s", (yyvsp[-7].id), (yyvsp[-6].str));
		   }
		   while (p) {
		     Setattr(p, "storage", (yyvsp[-8].id));
		     Setattr(p, "type" ,ty);
		     if (!cparse_cplusplus && currentOuterClass && (!Getattr(currentOuterClass, "name"))) {
		       SetFlag(p, "hasconsttype");
		       SetFlag(p, "feature:immutable");
		     }
		     p = nextSibling(p);
		   }
		   if ((yyvsp[0].node) && Cmp((yyvsp[-8].id),"typedef") == 0)
		     add_typedef_name((yyval.node), (yyvsp[0].node), (yyvsp[-6].str), cscope, scpname);
		   Delete(scpname);

		   if (cplus_mode != CPLUS_PUBLIC) {
		   /* we 'open' the class at the end, to allow %template
		      to add new members */
		     Node *pa = new_node("access");
		     Setattr(pa, "kind", "public");
		     cplus_mode = CPLUS_PUBLIC;
		     appendChild((yyval.node), pa);
		     Delete(pa);
		   }
		   if (currentOuterClass)
		     restore_access_mode((yyval.node));
		   Setattr((yyval.node), "symtab", Swig_symbol_popscope());
		   Classprefix = Getattr((yyval.node), "Classprefix");
		   Delattr((yyval.node), "Classprefix");
		   Delete(Namespaceprefix);
		   Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		   if (cplus_mode == CPLUS_PRIVATE) {
		     (yyval.node) = 0; /* skip private nested classes */
		   } else if (cparse_cplusplus && currentOuterClass && ignore_nested_classes && !GetFlag((yyval.node), "feature:flatnested")) {
		     (yyval.node) = nested_forward_declaration((yyvsp[-8].id), (yyvsp[-7].id), (yyvsp[-6].str), Copy((yyvsp[-6].str)), (yyvsp[0].node));
		   } else if (nscope_inner) {
		     /* this is tricky */
		     /* we add the declaration in the original namespace */
		     if (Strcmp(nodeType(nscope_inner), "class") == 0 && cparse_cplusplus && ignore_nested_classes && !GetFlag((yyval.node), "feature:flatnested"))
		       (yyval.node) = nested_forward_declaration((yyvsp[-8].id), (yyvsp[-7].id), (yyvsp[-6].str), Copy((yyvsp[-6].str)), (yyvsp[0].node));
		     appendChild(nscope_inner, (yyval.node));
		     Swig_symbol_setscope(Getattr(nscope_inner, "symtab"));
		     Delete(Namespaceprefix);
		     Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		     yyrename = Copy(Getattr((yyval.node), "class_rename"));
		     add_symbols((yyval.node));
		     Delattr((yyval.node), "class_rename");
		     /* but the variable definition in the current scope */
		     Swig_symbol_setscope(cscope);
		     Delete(Namespaceprefix);
		     Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		     add_symbols((yyvsp[0].node));
		     if (nscope) {
		       (yyval.node) = nscope; /* here we return recreated namespace tower instead of the class itself */
		       if ((yyvsp[0].node)) {
			 appendSibling((yyval.node), (yyvsp[0].node));
		       }
		     } else if (!SwigType_istemplate(ty) && template_parameters == 0) { /* for tempalte we need the class itself */
		       (yyval.node) = (yyvsp[0].node);
		     }
		   } else {
		     Delete(yyrename);
		     yyrename = 0;
		     if (!cparse_cplusplus && currentOuterClass) { /* nested C structs go into global scope*/
		       Node *outer = currentOuterClass;
		       while (Getattr(outer, "nested:outer"))
			 outer = Getattr(outer, "nested:outer");
		       appendSibling(outer, (yyval.node));
		       add_symbols((yyvsp[0].node));
		       set_scope_to_global();
		       Delete(Namespaceprefix);
		       Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		       yyrename = Copy(Getattr((yyval.node), "class_rename"));
		       add_symbols((yyval.node));
		       if (!cparse_cplusplusout)
			 Delattr((yyval.node), "nested:outer");
		       Delattr((yyval.node), "class_rename");
		       (yyval.node) = 0;
		     } else {
		       yyrename = Copy(Getattr((yyval.node), "class_rename"));
		       add_symbols((yyval.node));
		       add_symbols((yyvsp[0].node));
		       Delattr((yyval.node), "class_rename");
		     }
		   }
		   Delete(ty);
		   Swig_symbol_setscope(cscope);
		   Delete(Namespaceprefix);
		   Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	       }
#line 7072 "y.tab.c" /* yacc.c:1646  */
    break;

  case 162:
#line 3625 "parser.y" /* yacc.c:1646  */
    {
	       String *unnamed;
	       String *code;
	       unnamed = make_unnamed();
	       (yyval.node) = new_node("class");
	       Setline((yyval.node),cparse_start_line);
	       Setattr((yyval.node),"kind",(yyvsp[-2].id));
	       if ((yyvsp[-1].bases)) {
		 Setattr((yyval.node),"baselist", Getattr((yyvsp[-1].bases),"public"));
		 Setattr((yyval.node),"protectedbaselist", Getattr((yyvsp[-1].bases),"protected"));
		 Setattr((yyval.node),"privatebaselist", Getattr((yyvsp[-1].bases),"private"));
	       }
	       Setattr((yyval.node),"storage",(yyvsp[-3].id));
	       Setattr((yyval.node),"unnamed",unnamed);
	       Setattr((yyval.node),"allows_typedef","1");
	       if (currentOuterClass) {
		 SetFlag((yyval.node), "nested");
		 Setattr((yyval.node), "nested:outer", currentOuterClass);
		 set_access_mode((yyval.node));
	       }
	       Swig_features_get(Swig_cparse_features(), Namespaceprefix, 0, 0, (yyval.node));
	       /* save yyrename to the class attribute, to be used later in add_symbols()*/
	       Setattr((yyval.node), "class_rename", make_name((yyval.node),0,0));
	       if (strcmp((yyvsp[-2].id),"class") == 0) {
		 cplus_mode = CPLUS_PRIVATE;
	       } else {
		 cplus_mode = CPLUS_PUBLIC;
	       }
	       Swig_symbol_newscope();
	       cparse_start_line = cparse_line;
	       currentOuterClass = (yyval.node);
	       inclass = 1;
	       Classprefix = NewStringEmpty();
	       Delete(Namespaceprefix);
	       Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	       /* save the structure declaration to make a typedef for it later*/
	       code = get_raw_text_balanced('{', '}');
	       Setattr((yyval.node), "code", code);
	       Delete(code);
	     }
#line 7117 "y.tab.c" /* yacc.c:1646  */
    break;

  case 163:
#line 3664 "parser.y" /* yacc.c:1646  */
    {
	       String *unnamed;
               List *bases = 0;
	       String *name = 0;
	       Node *n;
	       Classprefix = 0;
	       (yyval.node) = currentOuterClass;
	       currentOuterClass = Getattr((yyval.node), "nested:outer");
	       if (!currentOuterClass)
		 inclass = 0;
	       else
		 restore_access_mode((yyval.node));
	       unnamed = Getattr((yyval.node),"unnamed");
               /* Check for pure-abstract class */
	       Setattr((yyval.node),"abstracts", pure_abstracts((yyvsp[-2].node)));
	       n = (yyvsp[0].node);
	       if (cparse_cplusplus && currentOuterClass && ignore_nested_classes && !GetFlag((yyval.node), "feature:flatnested")) {
		 String *name = n ? Copy(Getattr(n, "name")) : 0;
		 (yyval.node) = nested_forward_declaration((yyvsp[-7].id), (yyvsp[-6].id), 0, name, n);
		 Swig_symbol_popscope();
	         Delete(Namespaceprefix);
		 Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	       } else if (n) {
	         appendSibling((yyval.node),n);
		 /* If a proper typedef name was given, we'll use it to set the scope name */
		 name = try_to_find_a_name_for_unnamed_structure((yyvsp[-7].id), n);
		 if (name) {
		   String *scpname = 0;
		   SwigType *ty;
		   Setattr((yyval.node),"tdname",name);
		   Setattr((yyval.node),"name",name);
		   Swig_symbol_setscopename(name);
		   if ((yyvsp[-5].bases))
		     bases = Swig_make_inherit_list(name,Getattr((yyvsp[-5].bases),"public"),Namespaceprefix);
		   Swig_inherit_base_symbols(bases);

		     /* If a proper name was given, we use that as the typedef, not unnamed */
		   Clear(unnamed);
		   Append(unnamed, name);
		   if (cparse_cplusplus && !cparse_externc) {
		     ty = NewString(name);
		   } else {
		     ty = NewStringf("%s %s", (yyvsp[-6].id),name);
		   }
		   while (n) {
		     Setattr(n,"storage",(yyvsp[-7].id));
		     Setattr(n, "type", ty);
		     if (!cparse_cplusplus && currentOuterClass && (!Getattr(currentOuterClass, "name"))) {
		       SetFlag(n,"hasconsttype");
		       SetFlag(n,"feature:immutable");
		     }
		     n = nextSibling(n);
		   }
		   n = (yyvsp[0].node);

		   /* Check for previous extensions */
		   {
		     String *clsname = Swig_symbol_qualifiedscopename(0);
		     Node *am = Getattr(Swig_extend_hash(),clsname);
		     if (am) {
		       /* Merge the extension into the symbol table */
		       Swig_extend_merge((yyval.node),am);
		       Swig_extend_append_previous((yyval.node),am);
		       Delattr(Swig_extend_hash(),clsname);
		     }
		     Delete(clsname);
		   }
		   if (!classes) classes = NewHash();
		   scpname = Swig_symbol_qualifiedscopename(0);
		   Setattr(classes,scpname,(yyval.node));
		   Delete(scpname);
		 } else { /* no suitable name was found for a struct */
		   Setattr((yyval.node), "nested:unnamed", Getattr(n, "name")); /* save the name of the first declarator for later use in name generation*/
		   while (n) { /* attach unnamed struct to the declarators, so that they would receive proper type later*/
		     Setattr(n, "nested:unnamedtype", (yyval.node));
		     Setattr(n, "storage", (yyvsp[-7].id));
		     n = nextSibling(n);
		   }
		   n = (yyvsp[0].node);
		   Swig_symbol_setscopename("<unnamed>");
		 }
		 appendChild((yyval.node),(yyvsp[-2].node));
		 /* Pop the scope */
		 Setattr((yyval.node),"symtab",Swig_symbol_popscope());
		 if (name) {
		   Delete(yyrename);
		   yyrename = Copy(Getattr((yyval.node), "class_rename"));
		   Delete(Namespaceprefix);
		   Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		   add_symbols((yyval.node));
		   add_symbols(n);
		   Delattr((yyval.node), "class_rename");
		 }else if (cparse_cplusplus)
		   (yyval.node) = 0; /* ignore unnamed structs for C++ */
	         Delete(unnamed);
	       } else { /* unnamed struct w/o declarator*/
		 Swig_symbol_popscope();
	         Delete(Namespaceprefix);
		 Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		 add_symbols((yyvsp[-2].node));
		 Delete((yyval.node));
		 (yyval.node) = (yyvsp[-2].node); /* pass member list to outer class/namespace (instead of self)*/
	       }
              }
#line 7226 "y.tab.c" /* yacc.c:1646  */
    break;

  case 164:
#line 3770 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 7232 "y.tab.c" /* yacc.c:1646  */
    break;

  case 165:
#line 3771 "parser.y" /* yacc.c:1646  */
    {
                        (yyval.node) = new_node("cdecl");
                        Setattr((yyval.node),"name",(yyvsp[-2].decl).id);
                        Setattr((yyval.node),"decl",(yyvsp[-2].decl).type);
                        Setattr((yyval.node),"parms",(yyvsp[-2].decl).parms);
			set_nextSibling((yyval.node),(yyvsp[0].node));
                    }
#line 7244 "y.tab.c" /* yacc.c:1646  */
    break;

  case 166:
#line 3783 "parser.y" /* yacc.c:1646  */
    {
              if ((yyvsp[-3].id) && (Strcmp((yyvsp[-3].id),"friend") == 0)) {
		/* Ignore */
                (yyval.node) = 0; 
	      } else {
		(yyval.node) = new_node("classforward");
		Setattr((yyval.node),"kind",(yyvsp[-2].id));
		Setattr((yyval.node),"name",(yyvsp[-1].str));
		Setattr((yyval.node),"sym:weak", "1");
		add_symbols((yyval.node));
	      }
             }
#line 7261 "y.tab.c" /* yacc.c:1646  */
    break;

  case 167:
#line 3801 "parser.y" /* yacc.c:1646  */
    { 
		   if (currentOuterClass)
		     Setattr(currentOuterClass, "template_parameters", template_parameters);
		    template_parameters = (yyvsp[-1].tparms); 
		  }
#line 7271 "y.tab.c" /* yacc.c:1646  */
    break;

  case 168:
#line 3805 "parser.y" /* yacc.c:1646  */
    {
			String *tname = 0;
			int     error = 0;

			/* check if we get a namespace node with a class declaration, and retrieve the class */
			Symtab *cscope = Swig_symbol_current();
			Symtab *sti = 0;
			Node *ntop = (yyvsp[0].node);
			Node *ni = ntop;
			SwigType *ntype = ni ? nodeType(ni) : 0;
			while (ni && Strcmp(ntype,"namespace") == 0) {
			  sti = Getattr(ni,"symtab");
			  ni = firstChild(ni);
			  ntype = nodeType(ni);
			}
			if (sti) {
			  Swig_symbol_setscope(sti);
			  Delete(Namespaceprefix);
			  Namespaceprefix = Swig_symbol_qualifiedscopename(0);
			  (yyvsp[0].node) = ni;
			}

			(yyval.node) = (yyvsp[0].node);
			if ((yyval.node)) tname = Getattr((yyval.node),"name");
			
			/* Check if the class is a template specialization */
			if (((yyval.node)) && (Strchr(tname,'<')) && (!is_operator(tname))) {
			  /* If a specialization.  Check if defined. */
			  Node *tempn = 0;
			  {
			    String *tbase = SwigType_templateprefix(tname);
			    tempn = Swig_symbol_clookup_local(tbase,0);
			    if (!tempn || (Strcmp(nodeType(tempn),"template") != 0)) {
			      SWIG_WARN_NODE_BEGIN(tempn);
			      Swig_warning(WARN_PARSE_TEMPLATE_SP_UNDEF, Getfile((yyval.node)),Getline((yyval.node)),"Specialization of non-template '%s'.\n", tbase);
			      SWIG_WARN_NODE_END(tempn);
			      tempn = 0;
			      error = 1;
			    }
			    Delete(tbase);
			  }
			  Setattr((yyval.node),"specialization","1");
			  Setattr((yyval.node),"templatetype",nodeType((yyval.node)));
			  set_nodeType((yyval.node),"template");
			  /* Template partial specialization */
			  if (tempn && ((yyvsp[-3].tparms)) && ((yyvsp[0].node))) {
			    List   *tlist;
			    String *targs = SwigType_templateargs(tname);
			    tlist = SwigType_parmlist(targs);
			    /*			  Printf(stdout,"targs = '%s' %s\n", targs, tlist); */
			    if (!Getattr((yyval.node),"sym:weak")) {
			      Setattr((yyval.node),"sym:typename","1");
			    }
			    
			    if (Len(tlist) != ParmList_len(Getattr(tempn,"templateparms"))) {
			      Swig_error(Getfile((yyval.node)),Getline((yyval.node)),"Inconsistent argument count in template partial specialization. %d %d\n", Len(tlist), ParmList_len(Getattr(tempn,"templateparms")));
			      
			    } else {

			    /* This code builds the argument list for the partial template
			       specialization.  This is a little hairy, but the idea is as
			       follows:

			       $3 contains a list of arguments supplied for the template.
			       For example template<class T>.

			       tlist is a list of the specialization arguments--which may be
			       different.  For example class<int,T>.

			       tp is a copy of the arguments in the original template definition.
       
			       The patching algorithm walks through the list of supplied
			       arguments ($3), finds the position in the specialization arguments
			       (tlist), and then patches the name in the argument list of the
			       original template.
			    */

			    {
			      String *pn;
			      Parm *p, *p1;
			      int i, nargs;
			      Parm *tp = CopyParmList(Getattr(tempn,"templateparms"));
			      nargs = Len(tlist);
			      p = (yyvsp[-3].tparms);
			      while (p) {
				for (i = 0; i < nargs; i++){
				  pn = Getattr(p,"name");
				  if (Strcmp(pn,SwigType_base(Getitem(tlist,i))) == 0) {
				    int j;
				    Parm *p1 = tp;
				    for (j = 0; j < i; j++) {
				      p1 = nextSibling(p1);
				    }
				    Setattr(p1,"name",pn);
				    Setattr(p1,"partialarg","1");
				  }
				}
				p = nextSibling(p);
			      }
			      p1 = tp;
			      i = 0;
			      while (p1) {
				if (!Getattr(p1,"partialarg")) {
				  Delattr(p1,"name");
				  Setattr(p1,"type", Getitem(tlist,i));
				} 
				i++;
				p1 = nextSibling(p1);
			      }
			      Setattr((yyval.node),"templateparms",tp);
			      Delete(tp);
			    }
  #if 0
			    /* Patch the parameter list */
			    if (tempn) {
			      Parm *p,*p1;
			      ParmList *tp = CopyParmList(Getattr(tempn,"templateparms"));
			      p = (yyvsp[-3].tparms);
			      p1 = tp;
			      while (p && p1) {
				String *pn = Getattr(p,"name");
				Printf(stdout,"pn = '%s'\n", pn);
				if (pn) Setattr(p1,"name",pn);
				else Delattr(p1,"name");
				pn = Getattr(p,"type");
				if (pn) Setattr(p1,"type",pn);
				p = nextSibling(p);
				p1 = nextSibling(p1);
			      }
			      Setattr((yyval.node),"templateparms",tp);
			      Delete(tp);
			    } else {
			      Setattr((yyval.node),"templateparms",(yyvsp[-3].tparms));
			    }
  #endif
			    Delattr((yyval.node),"specialization");
			    Setattr((yyval.node),"partialspecialization","1");
			    /* Create a specialized name for matching */
			    {
			      Parm *p = (yyvsp[-3].tparms);
			      String *fname = NewString(Getattr((yyval.node),"name"));
			      String *ffname = 0;
			      ParmList *partialparms = 0;

			      char   tmp[32];
			      int    i, ilen;
			      while (p) {
				String *n = Getattr(p,"name");
				if (!n) {
				  p = nextSibling(p);
				  continue;
				}
				ilen = Len(tlist);
				for (i = 0; i < ilen; i++) {
				  if (Strstr(Getitem(tlist,i),n)) {
				    sprintf(tmp,"$%d",i+1);
				    Replaceid(fname,n,tmp);
				  }
				}
				p = nextSibling(p);
			      }
			      /* Patch argument names with typedef */
			      {
				Iterator tt;
				Parm *parm_current = 0;
				List *tparms = SwigType_parmlist(fname);
				ffname = SwigType_templateprefix(fname);
				Append(ffname,"<(");
				for (tt = First(tparms); tt.item; ) {
				  SwigType *rtt = Swig_symbol_typedef_reduce(tt.item,0);
				  SwigType *ttr = Swig_symbol_type_qualify(rtt,0);

				  Parm *newp = NewParmWithoutFileLineInfo(ttr, 0);
				  if (partialparms)
				    set_nextSibling(parm_current, newp);
				  else
				    partialparms = newp;
				  parm_current = newp;

				  Append(ffname,ttr);
				  tt = Next(tt);
				  if (tt.item) Putc(',',ffname);
				  Delete(rtt);
				  Delete(ttr);
				}
				Delete(tparms);
				Append(ffname,")>");
			      }
			      {
				Node *new_partial = NewHash();
				String *partials = Getattr(tempn,"partials");
				if (!partials) {
				  partials = NewList();
				  Setattr(tempn,"partials",partials);
				  Delete(partials);
				}
				/*			      Printf(stdout,"partial: fname = '%s', '%s'\n", fname, Swig_symbol_typedef_reduce(fname,0)); */
				Setattr(new_partial, "partialparms", partialparms);
				Setattr(new_partial, "templcsymname", ffname);
				Append(partials, new_partial);
			      }
			      Setattr((yyval.node),"partialargs",ffname);
			      Swig_symbol_cadd(ffname,(yyval.node));
			    }
			    }
			    Delete(tlist);
			    Delete(targs);
			  } else {
			    /* An explicit template specialization */
			    /* add default args from primary (unspecialized) template */
			    String *ty = Swig_symbol_template_deftype(tname,0);
			    String *fname = Swig_symbol_type_qualify(ty,0);
			    Swig_symbol_cadd(fname,(yyval.node));
			    Delete(ty);
			    Delete(fname);
			  }
			}  else if ((yyval.node)) {
			  Setattr((yyval.node),"templatetype",nodeType((yyvsp[0].node)));
			  set_nodeType((yyval.node),"template");
			  Setattr((yyval.node),"templateparms", (yyvsp[-3].tparms));
			  if (!Getattr((yyval.node),"sym:weak")) {
			    Setattr((yyval.node),"sym:typename","1");
			  }
			  add_symbols((yyval.node));
			  default_arguments((yyval.node));
			  /* We also place a fully parameterized version in the symbol table */
			  {
			    Parm *p;
			    String *fname = NewStringf("%s<(", Getattr((yyval.node),"name"));
			    p = (yyvsp[-3].tparms);
			    while (p) {
			      String *n = Getattr(p,"name");
			      if (!n) n = Getattr(p,"type");
			      Append(fname,n);
			      p = nextSibling(p);
			      if (p) Putc(',',fname);
			    }
			    Append(fname,")>");
			    Swig_symbol_cadd(fname,(yyval.node));
			  }
			}
			(yyval.node) = ntop;
			Swig_symbol_setscope(cscope);
			Delete(Namespaceprefix);
			Namespaceprefix = Swig_symbol_qualifiedscopename(0);
			if (error || (nscope_inner && Strcmp(nodeType(nscope_inner), "class") == 0)) {
			  (yyval.node) = 0;
			}
			if (currentOuterClass)
			  template_parameters = Getattr(currentOuterClass, "template_parameters");
			else
			  template_parameters = 0;
                }
#line 7529 "y.tab.c" /* yacc.c:1646  */
    break;

  case 169:
#line 4060 "parser.y" /* yacc.c:1646  */
    {
		  Swig_warning(WARN_PARSE_EXPLICIT_TEMPLATE, cparse_file, cparse_line, "Explicit template instantiation ignored.\n");
                  (yyval.node) = 0; 
		}
#line 7538 "y.tab.c" /* yacc.c:1646  */
    break;

  case 170:
#line 4066 "parser.y" /* yacc.c:1646  */
    {
		  Swig_warning(WARN_PARSE_EXPLICIT_TEMPLATE, cparse_file, cparse_line, "Explicit template instantiation ignored.\n");
                  (yyval.node) = 0; 
                }
#line 7547 "y.tab.c" /* yacc.c:1646  */
    break;

  case 171:
#line 4072 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = (yyvsp[0].node);
                }
#line 7555 "y.tab.c" /* yacc.c:1646  */
    break;

  case 172:
#line 4075 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = (yyvsp[0].node);
                }
#line 7563 "y.tab.c" /* yacc.c:1646  */
    break;

  case 173:
#line 4078 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = (yyvsp[0].node);
                }
#line 7571 "y.tab.c" /* yacc.c:1646  */
    break;

  case 174:
#line 4081 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = (yyvsp[0].node);
                }
#line 7579 "y.tab.c" /* yacc.c:1646  */
    break;

  case 175:
#line 4084 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.node) = 0;
                }
#line 7587 "y.tab.c" /* yacc.c:1646  */
    break;

  case 176:
#line 4087 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.node) = (yyvsp[0].node);
                }
#line 7595 "y.tab.c" /* yacc.c:1646  */
    break;

  case 177:
#line 4090 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.node) = (yyvsp[0].node);
                }
#line 7603 "y.tab.c" /* yacc.c:1646  */
    break;

  case 178:
#line 4095 "parser.y" /* yacc.c:1646  */
    {
		   /* Rip out the parameter names */
		  Parm *p = (yyvsp[0].pl);
		  (yyval.tparms) = (yyvsp[0].pl);

		  while (p) {
		    String *name = Getattr(p,"name");
		    if (!name) {
		      /* Hmmm. Maybe it's a 'class T' parameter */
		      char *type = Char(Getattr(p,"type"));
		      /* Template template parameter */
		      if (strncmp(type,"template<class> ",16) == 0) {
			type += 16;
		      }
		      if ((strncmp(type,"class ",6) == 0) || (strncmp(type,"typename ", 9) == 0)) {
			char *t = strchr(type,' ');
			Setattr(p,"name", t+1);
		      } else 
                      /* Variadic template args */
		      if ((strncmp(type,"class... ",9) == 0) || (strncmp(type,"typename... ", 12) == 0)) {
			char *t = strchr(type,' ');
			Setattr(p,"name", t+1);
			Setattr(p,"variadic", "1");
		      } else {
			/*
			 Swig_error(cparse_file, cparse_line, "Missing template parameter name\n");
			 $$.rparms = 0;
			 $$.parms = 0;
			 break; */
		      }
		    }
		    p = nextSibling(p);
		  }
                 }
#line 7642 "y.tab.c" /* yacc.c:1646  */
    break;

  case 179:
#line 4131 "parser.y" /* yacc.c:1646  */
    {
                      set_nextSibling((yyvsp[-1].p),(yyvsp[0].pl));
                      (yyval.pl) = (yyvsp[-1].p);
                   }
#line 7651 "y.tab.c" /* yacc.c:1646  */
    break;

  case 180:
#line 4135 "parser.y" /* yacc.c:1646  */
    { (yyval.pl) = 0; }
#line 7657 "y.tab.c" /* yacc.c:1646  */
    break;

  case 181:
#line 4138 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.p) = NewParmWithoutFileLineInfo(NewString((yyvsp[0].id)), 0);
                  }
#line 7665 "y.tab.c" /* yacc.c:1646  */
    break;

  case 182:
#line 4141 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.p) = (yyvsp[0].p);
                  }
#line 7673 "y.tab.c" /* yacc.c:1646  */
    break;

  case 183:
#line 4146 "parser.y" /* yacc.c:1646  */
    {
                         set_nextSibling((yyvsp[-1].p),(yyvsp[0].pl));
                         (yyval.pl) = (yyvsp[-1].p);
                       }
#line 7682 "y.tab.c" /* yacc.c:1646  */
    break;

  case 184:
#line 4150 "parser.y" /* yacc.c:1646  */
    { (yyval.pl) = 0; }
#line 7688 "y.tab.c" /* yacc.c:1646  */
    break;

  case 185:
#line 4155 "parser.y" /* yacc.c:1646  */
    {
                  String *uname = Swig_symbol_type_qualify((yyvsp[-1].str),0);
		  String *name = Swig_scopename_last((yyvsp[-1].str));
                  (yyval.node) = new_node("using");
		  Setattr((yyval.node),"uname",uname);
		  Setattr((yyval.node),"name", name);
		  Delete(uname);
		  Delete(name);
		  add_symbols((yyval.node));
             }
#line 7703 "y.tab.c" /* yacc.c:1646  */
    break;

  case 186:
#line 4165 "parser.y" /* yacc.c:1646  */
    {
	       Node *n = Swig_symbol_clookup((yyvsp[-1].str),0);
	       if (!n) {
		 Swig_error(cparse_file, cparse_line, "Nothing known about namespace '%s'\n", (yyvsp[-1].str));
		 (yyval.node) = 0;
	       } else {

		 while (Strcmp(nodeType(n),"using") == 0) {
		   n = Getattr(n,"node");
		 }
		 if (n) {
		   if (Strcmp(nodeType(n),"namespace") == 0) {
		     Symtab *current = Swig_symbol_current();
		     Symtab *symtab = Getattr(n,"symtab");
		     (yyval.node) = new_node("using");
		     Setattr((yyval.node),"node",n);
		     Setattr((yyval.node),"namespace", (yyvsp[-1].str));
		     if (current != symtab) {
		       Swig_symbol_inherit(symtab);
		     }
		   } else {
		     Swig_error(cparse_file, cparse_line, "'%s' is not a namespace.\n", (yyvsp[-1].str));
		     (yyval.node) = 0;
		   }
		 } else {
		   (yyval.node) = 0;
		 }
	       }
             }
#line 7737 "y.tab.c" /* yacc.c:1646  */
    break;

  case 187:
#line 4196 "parser.y" /* yacc.c:1646  */
    { 
                Hash *h;
                (yyvsp[-2].node) = Swig_symbol_current();
		h = Swig_symbol_clookup((yyvsp[-1].str),0);
		if (h && ((yyvsp[-2].node) == Getattr(h,"sym:symtab")) && (Strcmp(nodeType(h),"namespace") == 0)) {
		  if (Getattr(h,"alias")) {
		    h = Getattr(h,"namespace");
		    Swig_warning(WARN_PARSE_NAMESPACE_ALIAS, cparse_file, cparse_line, "Namespace alias '%s' not allowed here. Assuming '%s'\n",
				 (yyvsp[-1].str), Getattr(h,"name"));
		    (yyvsp[-1].str) = Getattr(h,"name");
		  }
		  Swig_symbol_setscope(Getattr(h,"symtab"));
		} else {
		  Swig_symbol_newscope();
		  Swig_symbol_setscopename((yyvsp[-1].str));
		}
		Delete(Namespaceprefix);
		Namespaceprefix = Swig_symbol_qualifiedscopename(0);
             }
#line 7761 "y.tab.c" /* yacc.c:1646  */
    break;

  case 188:
#line 4214 "parser.y" /* yacc.c:1646  */
    {
                Node *n = (yyvsp[-1].node);
		set_nodeType(n,"namespace");
		Setattr(n,"name",(yyvsp[-4].str));
                Setattr(n,"symtab", Swig_symbol_popscope());
		Swig_symbol_setscope((yyvsp[-5].node));
		(yyval.node) = n;
		Delete(Namespaceprefix);
		Namespaceprefix = Swig_symbol_qualifiedscopename(0);
		add_symbols((yyval.node));
             }
#line 7777 "y.tab.c" /* yacc.c:1646  */
    break;

  case 189:
#line 4225 "parser.y" /* yacc.c:1646  */
    {
	       Hash *h;
	       (yyvsp[-1].node) = Swig_symbol_current();
	       h = Swig_symbol_clookup("    ",0);
	       if (h && (Strcmp(nodeType(h),"namespace") == 0)) {
		 Swig_symbol_setscope(Getattr(h,"symtab"));
	       } else {
		 Swig_symbol_newscope();
		 /* we don't use "__unnamed__", but a long 'empty' name */
		 Swig_symbol_setscopename("    ");
	       }
	       Namespaceprefix = 0;
             }
#line 7795 "y.tab.c" /* yacc.c:1646  */
    break;

  case 190:
#line 4237 "parser.y" /* yacc.c:1646  */
    {
	       (yyval.node) = (yyvsp[-1].node);
	       set_nodeType((yyval.node),"namespace");
	       Setattr((yyval.node),"unnamed","1");
	       Setattr((yyval.node),"symtab", Swig_symbol_popscope());
	       Swig_symbol_setscope((yyvsp[-4].node));
	       Delete(Namespaceprefix);
	       Namespaceprefix = Swig_symbol_qualifiedscopename(0);
	       add_symbols((yyval.node));
             }
#line 7810 "y.tab.c" /* yacc.c:1646  */
    break;

  case 191:
#line 4247 "parser.y" /* yacc.c:1646  */
    {
	       /* Namespace alias */
	       Node *n;
	       (yyval.node) = new_node("namespace");
	       Setattr((yyval.node),"name",(yyvsp[-3].id));
	       Setattr((yyval.node),"alias",(yyvsp[-1].str));
	       n = Swig_symbol_clookup((yyvsp[-1].str),0);
	       if (!n) {
		 Swig_error(cparse_file, cparse_line, "Unknown namespace '%s'\n", (yyvsp[-1].str));
		 (yyval.node) = 0;
	       } else {
		 if (Strcmp(nodeType(n),"namespace") != 0) {
		   Swig_error(cparse_file, cparse_line, "'%s' is not a namespace\n",(yyvsp[-1].str));
		   (yyval.node) = 0;
		 } else {
		   while (Getattr(n,"alias")) {
		     n = Getattr(n,"namespace");
		   }
		   Setattr((yyval.node),"namespace",n);
		   add_symbols((yyval.node));
		   /* Set up a scope alias */
		   Swig_symbol_alias((yyvsp[-3].id),Getattr(n,"symtab"));
		 }
	       }
             }
#line 7840 "y.tab.c" /* yacc.c:1646  */
    break;

  case 192:
#line 4274 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.node) = (yyvsp[-1].node);
                   /* Insert cpp_member (including any siblings) to the front of the cpp_members linked list */
		   if ((yyval.node)) {
		     Node *p = (yyval.node);
		     Node *pp =0;
		     while (p) {
		       pp = p;
		       p = nextSibling(p);
		     }
		     set_nextSibling(pp,(yyvsp[0].node));
		     if ((yyvsp[0].node))
		       set_previousSibling((yyvsp[0].node), pp);
		   } else {
		     (yyval.node) = (yyvsp[0].node);
		   }
             }
#line 7862 "y.tab.c" /* yacc.c:1646  */
    break;

  case 193:
#line 4291 "parser.y" /* yacc.c:1646  */
    { 
	       extendmode = 1;
	       if (cplus_mode != CPLUS_PUBLIC) {
		 Swig_error(cparse_file,cparse_line,"%%extend can only be used in a public section\n");
	       }
             }
#line 7873 "y.tab.c" /* yacc.c:1646  */
    break;

  case 194:
#line 4296 "parser.y" /* yacc.c:1646  */
    {
	       extendmode = 0;
	     }
#line 7881 "y.tab.c" /* yacc.c:1646  */
    break;

  case 195:
#line 4298 "parser.y" /* yacc.c:1646  */
    {
	       (yyval.node) = new_node("extend");
	       mark_nodes_as_extend((yyvsp[-3].node));
	       appendChild((yyval.node),(yyvsp[-3].node));
	       set_nextSibling((yyval.node),(yyvsp[0].node));
	     }
#line 7892 "y.tab.c" /* yacc.c:1646  */
    break;

  case 196:
#line 4304 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7898 "y.tab.c" /* yacc.c:1646  */
    break;

  case 197:
#line 4305 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0;}
#line 7904 "y.tab.c" /* yacc.c:1646  */
    break;

  case 198:
#line 4306 "parser.y" /* yacc.c:1646  */
    {
	       int start_line = cparse_line;
	       skip_decl();
	       Swig_error(cparse_file,start_line,"Syntax error in input(3).\n");
	       exit(1);
	       }
#line 7915 "y.tab.c" /* yacc.c:1646  */
    break;

  case 199:
#line 4311 "parser.y" /* yacc.c:1646  */
    { 
		 (yyval.node) = (yyvsp[0].node);
   	     }
#line 7923 "y.tab.c" /* yacc.c:1646  */
    break;

  case 200:
#line 4322 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7929 "y.tab.c" /* yacc.c:1646  */
    break;

  case 201:
#line 4323 "parser.y" /* yacc.c:1646  */
    { 
                 (yyval.node) = (yyvsp[0].node); 
		 if (extendmode && current_class) {
		   String *symname;
		   symname= make_name((yyval.node),Getattr((yyval.node),"name"), Getattr((yyval.node),"decl"));
		   if (Strcmp(symname,Getattr((yyval.node),"name")) == 0) {
		     /* No renaming operation.  Set name to class name */
		     Delete(yyrename);
		     yyrename = NewString(Getattr(current_class,"sym:name"));
		   } else {
		     Delete(yyrename);
		     yyrename = symname;
		   }
		 }
		 add_symbols((yyval.node));
                 default_arguments((yyval.node));
             }
#line 7951 "y.tab.c" /* yacc.c:1646  */
    break;

  case 202:
#line 4340 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7957 "y.tab.c" /* yacc.c:1646  */
    break;

  case 203:
#line 4341 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7963 "y.tab.c" /* yacc.c:1646  */
    break;

  case 204:
#line 4342 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7969 "y.tab.c" /* yacc.c:1646  */
    break;

  case 205:
#line 4343 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7975 "y.tab.c" /* yacc.c:1646  */
    break;

  case 206:
#line 4344 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7981 "y.tab.c" /* yacc.c:1646  */
    break;

  case 207:
#line 4345 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7987 "y.tab.c" /* yacc.c:1646  */
    break;

  case 208:
#line 4346 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 7993 "y.tab.c" /* yacc.c:1646  */
    break;

  case 209:
#line 4347 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 7999 "y.tab.c" /* yacc.c:1646  */
    break;

  case 210:
#line 4348 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8005 "y.tab.c" /* yacc.c:1646  */
    break;

  case 211:
#line 4349 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8011 "y.tab.c" /* yacc.c:1646  */
    break;

  case 212:
#line 4350 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 8017 "y.tab.c" /* yacc.c:1646  */
    break;

  case 213:
#line 4351 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8023 "y.tab.c" /* yacc.c:1646  */
    break;

  case 214:
#line 4352 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8029 "y.tab.c" /* yacc.c:1646  */
    break;

  case 215:
#line 4353 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 8035 "y.tab.c" /* yacc.c:1646  */
    break;

  case 216:
#line 4354 "parser.y" /* yacc.c:1646  */
    {(yyval.node) = (yyvsp[0].node); }
#line 8041 "y.tab.c" /* yacc.c:1646  */
    break;

  case 217:
#line 4355 "parser.y" /* yacc.c:1646  */
    {(yyval.node) = (yyvsp[0].node); }
#line 8047 "y.tab.c" /* yacc.c:1646  */
    break;

  case 218:
#line 4356 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 8053 "y.tab.c" /* yacc.c:1646  */
    break;

  case 219:
#line 4365 "parser.y" /* yacc.c:1646  */
    {
              if (inclass || extendmode) {
		SwigType *decl = NewStringEmpty();
		(yyval.node) = new_node("constructor");
		Setattr((yyval.node),"storage",(yyvsp[-5].id));
		Setattr((yyval.node),"name",(yyvsp[-4].type));
		Setattr((yyval.node),"parms",(yyvsp[-2].pl));
		SwigType_add_function(decl,(yyvsp[-2].pl));
		Setattr((yyval.node),"decl",decl);
		Setattr((yyval.node),"throws",(yyvsp[0].decl).throws);
		Setattr((yyval.node),"throw",(yyvsp[0].decl).throwf);
		Setattr((yyval.node),"noexcept",(yyvsp[0].decl).nexcept);
		if (Len(scanner_ccode)) {
		  String *code = Copy(scanner_ccode);
		  Setattr((yyval.node),"code",code);
		  Delete(code);
		}
		SetFlag((yyval.node),"feature:new");
		if ((yyvsp[0].decl).defarg)
		  Setattr((yyval.node),"value",(yyvsp[0].decl).defarg);
	      } else {
		(yyval.node) = 0;
              }
              }
#line 8082 "y.tab.c" /* yacc.c:1646  */
    break;

  case 220:
#line 4393 "parser.y" /* yacc.c:1646  */
    {
               String *name = NewStringf("%s",(yyvsp[-4].str));
	       if (*(Char(name)) != '~') Insert(name,0,"~");
               (yyval.node) = new_node("destructor");
	       Setattr((yyval.node),"name",name);
	       Delete(name);
	       if (Len(scanner_ccode)) {
		 String *code = Copy(scanner_ccode);
		 Setattr((yyval.node),"code",code);
		 Delete(code);
	       }
	       {
		 String *decl = NewStringEmpty();
		 SwigType_add_function(decl,(yyvsp[-2].pl));
		 Setattr((yyval.node),"decl",decl);
		 Delete(decl);
	       }
	       Setattr((yyval.node),"throws",(yyvsp[0].dtype).throws);
	       Setattr((yyval.node),"throw",(yyvsp[0].dtype).throwf);
	       Setattr((yyval.node),"noexcept",(yyvsp[0].dtype).nexcept);
	       if ((yyvsp[0].dtype).val)
	         Setattr((yyval.node),"value",(yyvsp[0].dtype).val);
	       add_symbols((yyval.node));
	      }
#line 8111 "y.tab.c" /* yacc.c:1646  */
    break;

  case 221:
#line 4420 "parser.y" /* yacc.c:1646  */
    {
		String *name;
		(yyval.node) = new_node("destructor");
		Setattr((yyval.node),"storage","virtual");
	        name = NewStringf("%s",(yyvsp[-4].str));
		if (*(Char(name)) != '~') Insert(name,0,"~");
		Setattr((yyval.node),"name",name);
		Delete(name);
		Setattr((yyval.node),"throws",(yyvsp[0].dtype).throws);
		Setattr((yyval.node),"throw",(yyvsp[0].dtype).throwf);
		Setattr((yyval.node),"noexcept",(yyvsp[0].dtype).nexcept);
		if ((yyvsp[0].dtype).val)
		  Setattr((yyval.node),"value",(yyvsp[0].dtype).val);
		if (Len(scanner_ccode)) {
		  String *code = Copy(scanner_ccode);
		  Setattr((yyval.node),"code",code);
		  Delete(code);
		}
		{
		  String *decl = NewStringEmpty();
		  SwigType_add_function(decl,(yyvsp[-2].pl));
		  Setattr((yyval.node),"decl",decl);
		  Delete(decl);
		}

		add_symbols((yyval.node));
	      }
#line 8143 "y.tab.c" /* yacc.c:1646  */
    break;

  case 222:
#line 4451 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = new_node("cdecl");
                 Setattr((yyval.node),"type",(yyvsp[-5].type));
		 Setattr((yyval.node),"name",(yyvsp[-6].str));
		 Setattr((yyval.node),"storage",(yyvsp[-7].id));

		 SwigType_add_function((yyvsp[-4].type),(yyvsp[-2].pl));
		 if ((yyvsp[0].dtype).qualifier) {
		   SwigType_push((yyvsp[-4].type),(yyvsp[0].dtype).qualifier);
		 }
		 Setattr((yyval.node),"decl",(yyvsp[-4].type));
		 Setattr((yyval.node),"parms",(yyvsp[-2].pl));
		 Setattr((yyval.node),"conversion_operator","1");
		 add_symbols((yyval.node));
              }
#line 8163 "y.tab.c" /* yacc.c:1646  */
    break;

  case 223:
#line 4466 "parser.y" /* yacc.c:1646  */
    {
		 SwigType *decl;
                 (yyval.node) = new_node("cdecl");
                 Setattr((yyval.node),"type",(yyvsp[-5].type));
		 Setattr((yyval.node),"name",(yyvsp[-6].str));
		 Setattr((yyval.node),"storage",(yyvsp[-7].id));
		 decl = NewStringEmpty();
		 SwigType_add_reference(decl);
		 SwigType_add_function(decl,(yyvsp[-2].pl));
		 if ((yyvsp[0].dtype).qualifier) {
		   SwigType_push(decl,(yyvsp[0].dtype).qualifier);
		 }
		 Setattr((yyval.node),"decl",decl);
		 Setattr((yyval.node),"parms",(yyvsp[-2].pl));
		 Setattr((yyval.node),"conversion_operator","1");
		 add_symbols((yyval.node));
	       }
#line 8185 "y.tab.c" /* yacc.c:1646  */
    break;

  case 224:
#line 4483 "parser.y" /* yacc.c:1646  */
    {
		 SwigType *decl;
                 (yyval.node) = new_node("cdecl");
                 Setattr((yyval.node),"type",(yyvsp[-5].type));
		 Setattr((yyval.node),"name",(yyvsp[-6].str));
		 Setattr((yyval.node),"storage",(yyvsp[-7].id));
		 decl = NewStringEmpty();
		 SwigType_add_rvalue_reference(decl);
		 SwigType_add_function(decl,(yyvsp[-2].pl));
		 if ((yyvsp[0].dtype).qualifier) {
		   SwigType_push(decl,(yyvsp[0].dtype).qualifier);
		 }
		 Setattr((yyval.node),"decl",decl);
		 Setattr((yyval.node),"parms",(yyvsp[-2].pl));
		 Setattr((yyval.node),"conversion_operator","1");
		 add_symbols((yyval.node));
	       }
#line 8207 "y.tab.c" /* yacc.c:1646  */
    break;

  case 225:
#line 4501 "parser.y" /* yacc.c:1646  */
    {
		 SwigType *decl;
                 (yyval.node) = new_node("cdecl");
                 Setattr((yyval.node),"type",(yyvsp[-6].type));
		 Setattr((yyval.node),"name",(yyvsp[-7].str));
		 Setattr((yyval.node),"storage",(yyvsp[-8].id));
		 decl = NewStringEmpty();
		 SwigType_add_pointer(decl);
		 SwigType_add_reference(decl);
		 SwigType_add_function(decl,(yyvsp[-2].pl));
		 if ((yyvsp[0].dtype).qualifier) {
		   SwigType_push(decl,(yyvsp[0].dtype).qualifier);
		 }
		 Setattr((yyval.node),"decl",decl);
		 Setattr((yyval.node),"parms",(yyvsp[-2].pl));
		 Setattr((yyval.node),"conversion_operator","1");
		 add_symbols((yyval.node));
	       }
#line 8230 "y.tab.c" /* yacc.c:1646  */
    break;

  case 226:
#line 4520 "parser.y" /* yacc.c:1646  */
    {
		String *t = NewStringEmpty();
		(yyval.node) = new_node("cdecl");
		Setattr((yyval.node),"type",(yyvsp[-4].type));
		Setattr((yyval.node),"name",(yyvsp[-5].str));
		 Setattr((yyval.node),"storage",(yyvsp[-6].id));
		SwigType_add_function(t,(yyvsp[-2].pl));
		if ((yyvsp[0].dtype).qualifier) {
		  SwigType_push(t,(yyvsp[0].dtype).qualifier);
		}
		Setattr((yyval.node),"decl",t);
		Setattr((yyval.node),"parms",(yyvsp[-2].pl));
		Setattr((yyval.node),"conversion_operator","1");
		add_symbols((yyval.node));
              }
#line 8250 "y.tab.c" /* yacc.c:1646  */
    break;

  case 227:
#line 4539 "parser.y" /* yacc.c:1646  */
    {
                 skip_balanced('{','}');
                 (yyval.node) = 0;
               }
#line 8259 "y.tab.c" /* yacc.c:1646  */
    break;

  case 228:
#line 4546 "parser.y" /* yacc.c:1646  */
    {
                skip_balanced('(',')');
                (yyval.node) = 0;
              }
#line 8268 "y.tab.c" /* yacc.c:1646  */
    break;

  case 229:
#line 4553 "parser.y" /* yacc.c:1646  */
    { 
                (yyval.node) = new_node("access");
		Setattr((yyval.node),"kind","public");
                cplus_mode = CPLUS_PUBLIC;
              }
#line 8278 "y.tab.c" /* yacc.c:1646  */
    break;

  case 230:
#line 4560 "parser.y" /* yacc.c:1646  */
    { 
                (yyval.node) = new_node("access");
                Setattr((yyval.node),"kind","private");
		cplus_mode = CPLUS_PRIVATE;
	      }
#line 8288 "y.tab.c" /* yacc.c:1646  */
    break;

  case 231:
#line 4568 "parser.y" /* yacc.c:1646  */
    { 
		(yyval.node) = new_node("access");
		Setattr((yyval.node),"kind","protected");
		cplus_mode = CPLUS_PROTECTED;
	      }
#line 8298 "y.tab.c" /* yacc.c:1646  */
    break;

  case 232:
#line 4576 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8304 "y.tab.c" /* yacc.c:1646  */
    break;

  case 233:
#line 4579 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8310 "y.tab.c" /* yacc.c:1646  */
    break;

  case 234:
#line 4583 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8316 "y.tab.c" /* yacc.c:1646  */
    break;

  case 235:
#line 4586 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8322 "y.tab.c" /* yacc.c:1646  */
    break;

  case 236:
#line 4587 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8328 "y.tab.c" /* yacc.c:1646  */
    break;

  case 237:
#line 4588 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8334 "y.tab.c" /* yacc.c:1646  */
    break;

  case 238:
#line 4589 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8340 "y.tab.c" /* yacc.c:1646  */
    break;

  case 239:
#line 4590 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8346 "y.tab.c" /* yacc.c:1646  */
    break;

  case 240:
#line 4591 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8352 "y.tab.c" /* yacc.c:1646  */
    break;

  case 241:
#line 4592 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8358 "y.tab.c" /* yacc.c:1646  */
    break;

  case 242:
#line 4593 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 8364 "y.tab.c" /* yacc.c:1646  */
    break;

  case 243:
#line 4596 "parser.y" /* yacc.c:1646  */
    {
	            Clear(scanner_ccode);
		    (yyval.dtype).val = 0;
		    (yyval.dtype).throws = (yyvsp[-1].dtype).throws;
		    (yyval.dtype).throwf = (yyvsp[-1].dtype).throwf;
		    (yyval.dtype).nexcept = (yyvsp[-1].dtype).nexcept;
               }
#line 8376 "y.tab.c" /* yacc.c:1646  */
    break;

  case 244:
#line 4603 "parser.y" /* yacc.c:1646  */
    {
	            Clear(scanner_ccode);
		    (yyval.dtype).val = (yyvsp[-1].dtype).val;
		    (yyval.dtype).throws = (yyvsp[-3].dtype).throws;
		    (yyval.dtype).throwf = (yyvsp[-3].dtype).throwf;
		    (yyval.dtype).nexcept = (yyvsp[-3].dtype).nexcept;
               }
#line 8388 "y.tab.c" /* yacc.c:1646  */
    break;

  case 245:
#line 4610 "parser.y" /* yacc.c:1646  */
    { 
		    skip_balanced('{','}'); 
		    (yyval.dtype).val = 0;
		    (yyval.dtype).throws = (yyvsp[-1].dtype).throws;
		    (yyval.dtype).throwf = (yyvsp[-1].dtype).throwf;
		    (yyval.dtype).nexcept = (yyvsp[-1].dtype).nexcept;
	       }
#line 8400 "y.tab.c" /* yacc.c:1646  */
    break;

  case 246:
#line 4619 "parser.y" /* yacc.c:1646  */
    { 
                     Clear(scanner_ccode);
                     (yyval.dtype).val = 0;
                     (yyval.dtype).qualifier = (yyvsp[-1].dtype).qualifier;
                     (yyval.dtype).bitfield = 0;
                     (yyval.dtype).throws = (yyvsp[-1].dtype).throws;
                     (yyval.dtype).throwf = (yyvsp[-1].dtype).throwf;
                     (yyval.dtype).nexcept = (yyvsp[-1].dtype).nexcept;
                }
#line 8414 "y.tab.c" /* yacc.c:1646  */
    break;

  case 247:
#line 4628 "parser.y" /* yacc.c:1646  */
    { 
                     Clear(scanner_ccode);
                     (yyval.dtype).val = (yyvsp[-1].dtype).val;
                     (yyval.dtype).qualifier = (yyvsp[-3].dtype).qualifier;
                     (yyval.dtype).bitfield = 0;
                     (yyval.dtype).throws = (yyvsp[-3].dtype).throws; 
                     (yyval.dtype).throwf = (yyvsp[-3].dtype).throwf; 
                     (yyval.dtype).nexcept = (yyvsp[-3].dtype).nexcept; 
               }
#line 8428 "y.tab.c" /* yacc.c:1646  */
    break;

  case 248:
#line 4637 "parser.y" /* yacc.c:1646  */
    { 
                     skip_balanced('{','}');
                     (yyval.dtype).val = 0;
                     (yyval.dtype).qualifier = (yyvsp[-1].dtype).qualifier;
                     (yyval.dtype).bitfield = 0;
                     (yyval.dtype).throws = (yyvsp[-1].dtype).throws; 
                     (yyval.dtype).throwf = (yyvsp[-1].dtype).throwf; 
                     (yyval.dtype).nexcept = (yyvsp[-1].dtype).nexcept; 
               }
#line 8442 "y.tab.c" /* yacc.c:1646  */
    break;

  case 249:
#line 4649 "parser.y" /* yacc.c:1646  */
    { }
#line 8448 "y.tab.c" /* yacc.c:1646  */
    break;

  case 250:
#line 4652 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type);
                  /* Printf(stdout,"primitive = '%s'\n", $$);*/
                }
#line 8456 "y.tab.c" /* yacc.c:1646  */
    break;

  case 251:
#line 4655 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 8462 "y.tab.c" /* yacc.c:1646  */
    break;

  case 252:
#line 4656 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 8468 "y.tab.c" /* yacc.c:1646  */
    break;

  case 253:
#line 4660 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 8474 "y.tab.c" /* yacc.c:1646  */
    break;

  case 254:
#line 4662 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.type) = (yyvsp[0].str);
               }
#line 8482 "y.tab.c" /* yacc.c:1646  */
    break;

  case 255:
#line 4670 "parser.y" /* yacc.c:1646  */
    {
                   if (Strcmp((yyvsp[0].str),"C") == 0) {
		     (yyval.id) = "externc";
                   } else if (Strcmp((yyvsp[0].str),"C++") == 0) {
		     (yyval.id) = "extern";
		   } else {
		     Swig_warning(WARN_PARSE_UNDEFINED_EXTERN,cparse_file, cparse_line,"Unrecognized extern type \"%s\".\n", (yyvsp[0].str));
		     (yyval.id) = 0;
		   }
               }
#line 8497 "y.tab.c" /* yacc.c:1646  */
    break;

  case 256:
#line 4682 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "extern"; }
#line 8503 "y.tab.c" /* yacc.c:1646  */
    break;

  case 257:
#line 4683 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (yyvsp[0].id); }
#line 8509 "y.tab.c" /* yacc.c:1646  */
    break;

  case 258:
#line 4684 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "thread_local"; }
#line 8515 "y.tab.c" /* yacc.c:1646  */
    break;

  case 259:
#line 4685 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "typedef"; }
#line 8521 "y.tab.c" /* yacc.c:1646  */
    break;

  case 260:
#line 4686 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "static"; }
#line 8527 "y.tab.c" /* yacc.c:1646  */
    break;

  case 261:
#line 4687 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "typedef"; }
#line 8533 "y.tab.c" /* yacc.c:1646  */
    break;

  case 262:
#line 4688 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "virtual"; }
#line 8539 "y.tab.c" /* yacc.c:1646  */
    break;

  case 263:
#line 4689 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "friend"; }
#line 8545 "y.tab.c" /* yacc.c:1646  */
    break;

  case 264:
#line 4690 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "explicit"; }
#line 8551 "y.tab.c" /* yacc.c:1646  */
    break;

  case 265:
#line 4691 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "constexpr"; }
#line 8557 "y.tab.c" /* yacc.c:1646  */
    break;

  case 266:
#line 4692 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "explicit constexpr"; }
#line 8563 "y.tab.c" /* yacc.c:1646  */
    break;

  case 267:
#line 4693 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "explicit constexpr"; }
#line 8569 "y.tab.c" /* yacc.c:1646  */
    break;

  case 268:
#line 4694 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "static constexpr"; }
#line 8575 "y.tab.c" /* yacc.c:1646  */
    break;

  case 269:
#line 4695 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "static constexpr"; }
#line 8581 "y.tab.c" /* yacc.c:1646  */
    break;

  case 270:
#line 4696 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "thread_local"; }
#line 8587 "y.tab.c" /* yacc.c:1646  */
    break;

  case 271:
#line 4697 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "static thread_local"; }
#line 8593 "y.tab.c" /* yacc.c:1646  */
    break;

  case 272:
#line 4698 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "static thread_local"; }
#line 8599 "y.tab.c" /* yacc.c:1646  */
    break;

  case 273:
#line 4699 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "extern thread_local"; }
#line 8605 "y.tab.c" /* yacc.c:1646  */
    break;

  case 274:
#line 4700 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "extern thread_local"; }
#line 8611 "y.tab.c" /* yacc.c:1646  */
    break;

  case 275:
#line 4701 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = 0; }
#line 8617 "y.tab.c" /* yacc.c:1646  */
    break;

  case 276:
#line 4708 "parser.y" /* yacc.c:1646  */
    {
                 Parm *p;
		 (yyval.pl) = (yyvsp[0].pl);
		 p = (yyvsp[0].pl);
                 while (p) {
		   Replace(Getattr(p,"type"),"typename ", "", DOH_REPLACE_ANY);
		   p = nextSibling(p);
                 }
               }
#line 8631 "y.tab.c" /* yacc.c:1646  */
    break;

  case 277:
#line 4719 "parser.y" /* yacc.c:1646  */
    {
                  set_nextSibling((yyvsp[-1].p),(yyvsp[0].pl));
                  (yyval.pl) = (yyvsp[-1].p);
		}
#line 8640 "y.tab.c" /* yacc.c:1646  */
    break;

  case 278:
#line 4723 "parser.y" /* yacc.c:1646  */
    { (yyval.pl) = 0; }
#line 8646 "y.tab.c" /* yacc.c:1646  */
    break;

  case 279:
#line 4726 "parser.y" /* yacc.c:1646  */
    {
                 set_nextSibling((yyvsp[-1].p),(yyvsp[0].pl));
		 (yyval.pl) = (yyvsp[-1].p);
                }
#line 8655 "y.tab.c" /* yacc.c:1646  */
    break;

  case 280:
#line 4730 "parser.y" /* yacc.c:1646  */
    { (yyval.pl) = 0; }
#line 8661 "y.tab.c" /* yacc.c:1646  */
    break;

  case 281:
#line 4734 "parser.y" /* yacc.c:1646  */
    {
                   SwigType_push((yyvsp[-1].type),(yyvsp[0].decl).type);
		   (yyval.p) = NewParmWithoutFileLineInfo((yyvsp[-1].type),(yyvsp[0].decl).id);
		   Setfile((yyval.p),cparse_file);
		   Setline((yyval.p),cparse_line);
		   if ((yyvsp[0].decl).defarg) {
		     Setattr((yyval.p),"value",(yyvsp[0].decl).defarg);
		   }
		}
#line 8675 "y.tab.c" /* yacc.c:1646  */
    break;

  case 282:
#line 4744 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.p) = NewParmWithoutFileLineInfo(NewStringf("template<class> %s %s", (yyvsp[-2].id),(yyvsp[-1].str)), 0);
		  Setfile((yyval.p),cparse_file);
		  Setline((yyval.p),cparse_line);
                  if ((yyvsp[0].dtype).val) {
                    Setattr((yyval.p),"value",(yyvsp[0].dtype).val);
                  }
                }
#line 8688 "y.tab.c" /* yacc.c:1646  */
    break;

  case 283:
#line 4752 "parser.y" /* yacc.c:1646  */
    {
		  SwigType *t = NewString("v(...)");
		  (yyval.p) = NewParmWithoutFileLineInfo(t, 0);
		  Setfile((yyval.p),cparse_file);
		  Setline((yyval.p),cparse_line);
		}
#line 8699 "y.tab.c" /* yacc.c:1646  */
    break;

  case 284:
#line 4760 "parser.y" /* yacc.c:1646  */
    {
                 Parm *p;
		 (yyval.p) = (yyvsp[0].p);
		 p = (yyvsp[0].p);
                 while (p) {
		   if (Getattr(p,"type")) {
		     Replace(Getattr(p,"type"),"typename ", "", DOH_REPLACE_ANY);
		   }
		   p = nextSibling(p);
                 }
               }
#line 8715 "y.tab.c" /* yacc.c:1646  */
    break;

  case 285:
#line 4773 "parser.y" /* yacc.c:1646  */
    {
                  set_nextSibling((yyvsp[-1].p),(yyvsp[0].p));
                  (yyval.p) = (yyvsp[-1].p);
		}
#line 8724 "y.tab.c" /* yacc.c:1646  */
    break;

  case 286:
#line 4777 "parser.y" /* yacc.c:1646  */
    { (yyval.p) = 0; }
#line 8730 "y.tab.c" /* yacc.c:1646  */
    break;

  case 287:
#line 4780 "parser.y" /* yacc.c:1646  */
    {
                 set_nextSibling((yyvsp[-1].p),(yyvsp[0].p));
		 (yyval.p) = (yyvsp[-1].p);
                }
#line 8739 "y.tab.c" /* yacc.c:1646  */
    break;

  case 288:
#line 4784 "parser.y" /* yacc.c:1646  */
    { (yyval.p) = 0; }
#line 8745 "y.tab.c" /* yacc.c:1646  */
    break;

  case 289:
#line 4788 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.p) = (yyvsp[0].p);
		  {
		    /* We need to make a possible adjustment for integer parameters. */
		    SwigType *type;
		    Node     *n = 0;

		    while (!n) {
		      type = Getattr((yyvsp[0].p),"type");
		      n = Swig_symbol_clookup(type,0);     /* See if we can find a node that matches the typename */
		      if ((n) && (Strcmp(nodeType(n),"cdecl") == 0)) {
			SwigType *decl = Getattr(n,"decl");
			if (!SwigType_isfunction(decl)) {
			  String *value = Getattr(n,"value");
			  if (value) {
			    String *v = Copy(value);
			    Setattr((yyvsp[0].p),"type",v);
			    Delete(v);
			    n = 0;
			  }
			}
		      } else {
			break;
		      }
		    }
		  }

               }
#line 8778 "y.tab.c" /* yacc.c:1646  */
    break;

  case 290:
#line 4816 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.p) = NewParmWithoutFileLineInfo(0,0);
                  Setfile((yyval.p),cparse_file);
		  Setline((yyval.p),cparse_line);
		  Setattr((yyval.p),"value",(yyvsp[0].dtype).val);
               }
#line 8789 "y.tab.c" /* yacc.c:1646  */
    break;

  case 291:
#line 4824 "parser.y" /* yacc.c:1646  */
    { 
                  (yyval.dtype) = (yyvsp[0].dtype); 
		  if ((yyvsp[0].dtype).type == T_ERROR) {
		    Swig_warning(WARN_PARSE_BAD_DEFAULT,cparse_file, cparse_line, "Can't set default argument (ignored)\n");
		    (yyval.dtype).val = 0;
		    (yyval.dtype).rawval = 0;
		    (yyval.dtype).bitfield = 0;
		    (yyval.dtype).throws = 0;
		    (yyval.dtype).throwf = 0;
		    (yyval.dtype).nexcept = 0;
		  }
               }
#line 8806 "y.tab.c" /* yacc.c:1646  */
    break;

  case 292:
#line 4836 "parser.y" /* yacc.c:1646  */
    { 
		  (yyval.dtype) = (yyvsp[-3].dtype);
		  if ((yyvsp[-3].dtype).type == T_ERROR) {
		    Swig_warning(WARN_PARSE_BAD_DEFAULT,cparse_file, cparse_line, "Can't set default argument (ignored)\n");
		    (yyval.dtype) = (yyvsp[-3].dtype);
		    (yyval.dtype).val = 0;
		    (yyval.dtype).rawval = 0;
		    (yyval.dtype).bitfield = 0;
		    (yyval.dtype).throws = 0;
		    (yyval.dtype).throwf = 0;
		    (yyval.dtype).nexcept = 0;
		  } else {
		    (yyval.dtype).val = NewStringf("%s[%s]",(yyvsp[-3].dtype).val,(yyvsp[-1].dtype).val); 
		  }		  
               }
#line 8826 "y.tab.c" /* yacc.c:1646  */
    break;

  case 293:
#line 4851 "parser.y" /* yacc.c:1646  */
    {
		 skip_balanced('{','}');
		 (yyval.dtype).val = NewString(scanner_ccode);
		 (yyval.dtype).rawval = 0;
                 (yyval.dtype).type = T_INT;
		 (yyval.dtype).bitfield = 0;
		 (yyval.dtype).throws = 0;
		 (yyval.dtype).throwf = 0;
		 (yyval.dtype).nexcept = 0;
	       }
#line 8841 "y.tab.c" /* yacc.c:1646  */
    break;

  case 294:
#line 4861 "parser.y" /* yacc.c:1646  */
    { 
		 (yyval.dtype).val = 0;
		 (yyval.dtype).rawval = 0;
		 (yyval.dtype).type = 0;
		 (yyval.dtype).bitfield = (yyvsp[0].dtype).val;
		 (yyval.dtype).throws = 0;
		 (yyval.dtype).throwf = 0;
		 (yyval.dtype).nexcept = 0;
	       }
#line 8855 "y.tab.c" /* yacc.c:1646  */
    break;

  case 295:
#line 4870 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype).val = 0;
                 (yyval.dtype).rawval = 0;
                 (yyval.dtype).type = T_INT;
		 (yyval.dtype).bitfield = 0;
		 (yyval.dtype).throws = 0;
		 (yyval.dtype).throwf = 0;
		 (yyval.dtype).nexcept = 0;
               }
#line 8869 "y.tab.c" /* yacc.c:1646  */
    break;

  case 296:
#line 4881 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.decl) = (yyvsp[-1].decl);
		 (yyval.decl).defarg = (yyvsp[0].dtype).rawval ? (yyvsp[0].dtype).rawval : (yyvsp[0].dtype).val;
            }
#line 8878 "y.tab.c" /* yacc.c:1646  */
    break;

  case 297:
#line 4885 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[-1].decl);
	      (yyval.decl).defarg = (yyvsp[0].dtype).rawval ? (yyvsp[0].dtype).rawval : (yyvsp[0].dtype).val;
            }
#line 8887 "y.tab.c" /* yacc.c:1646  */
    break;

  case 298:
#line 4889 "parser.y" /* yacc.c:1646  */
    {
   	      (yyval.decl).type = 0;
              (yyval.decl).id = 0;
	      (yyval.decl).defarg = (yyvsp[0].dtype).rawval ? (yyvsp[0].dtype).rawval : (yyvsp[0].dtype).val;
            }
#line 8897 "y.tab.c" /* yacc.c:1646  */
    break;

  case 299:
#line 4896 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.decl) = (yyvsp[0].decl);
		 if (SwigType_isfunction((yyvsp[0].decl).type)) {
		   Delete(SwigType_pop_function((yyvsp[0].decl).type));
		 } else if (SwigType_isarray((yyvsp[0].decl).type)) {
		   SwigType *ta = SwigType_pop_arrays((yyvsp[0].decl).type);
		   if (SwigType_isfunction((yyvsp[0].decl).type)) {
		     Delete(SwigType_pop_function((yyvsp[0].decl).type));
		   } else {
		     (yyval.decl).parms = 0;
		   }
		   SwigType_push((yyvsp[0].decl).type,ta);
		   Delete(ta);
		 } else {
		   (yyval.decl).parms = 0;
		 }
            }
#line 8919 "y.tab.c" /* yacc.c:1646  */
    break;

  case 300:
#line 4913 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      if (SwigType_isfunction((yyvsp[0].decl).type)) {
		Delete(SwigType_pop_function((yyvsp[0].decl).type));
	      } else if (SwigType_isarray((yyvsp[0].decl).type)) {
		SwigType *ta = SwigType_pop_arrays((yyvsp[0].decl).type);
		if (SwigType_isfunction((yyvsp[0].decl).type)) {
		  Delete(SwigType_pop_function((yyvsp[0].decl).type));
		} else {
		  (yyval.decl).parms = 0;
		}
		SwigType_push((yyvsp[0].decl).type,ta);
		Delete(ta);
	      } else {
		(yyval.decl).parms = 0;
	      }
            }
#line 8941 "y.tab.c" /* yacc.c:1646  */
    break;

  case 301:
#line 4930 "parser.y" /* yacc.c:1646  */
    {
   	      (yyval.decl).type = 0;
              (yyval.decl).id = 0;
	      (yyval.decl).parms = 0;
	      }
#line 8951 "y.tab.c" /* yacc.c:1646  */
    break;

  case 302:
#line 4938 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      if ((yyval.decl).type) {
		SwigType_push((yyvsp[-1].type),(yyval.decl).type);
		Delete((yyval.decl).type);
	      }
	      (yyval.decl).type = (yyvsp[-1].type);
           }
#line 8964 "y.tab.c" /* yacc.c:1646  */
    break;

  case 303:
#line 4946 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      SwigType_add_reference((yyvsp[-2].type));
              if ((yyval.decl).type) {
		SwigType_push((yyvsp[-2].type),(yyval.decl).type);
		Delete((yyval.decl).type);
	      }
	      (yyval.decl).type = (yyvsp[-2].type);
           }
#line 8978 "y.tab.c" /* yacc.c:1646  */
    break;

  case 304:
#line 4955 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      SwigType_add_rvalue_reference((yyvsp[-2].type));
              if ((yyval.decl).type) {
		SwigType_push((yyvsp[-2].type),(yyval.decl).type);
		Delete((yyval.decl).type);
	      }
	      (yyval.decl).type = (yyvsp[-2].type);
           }
#line 8992 "y.tab.c" /* yacc.c:1646  */
    break;

  case 305:
#line 4964 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      if (!(yyval.decl).type) (yyval.decl).type = NewStringEmpty();
           }
#line 9001 "y.tab.c" /* yacc.c:1646  */
    break;

  case 306:
#line 4968 "parser.y" /* yacc.c:1646  */
    {
	     (yyval.decl) = (yyvsp[0].decl);
	     (yyval.decl).type = NewStringEmpty();
	     SwigType_add_reference((yyval.decl).type);
	     if ((yyvsp[0].decl).type) {
	       SwigType_push((yyval.decl).type,(yyvsp[0].decl).type);
	       Delete((yyvsp[0].decl).type);
	     }
           }
#line 9015 "y.tab.c" /* yacc.c:1646  */
    break;

  case 307:
#line 4977 "parser.y" /* yacc.c:1646  */
    {
	     /* Introduced in C++11, move operator && */
             /* Adds one S/R conflict */
	     (yyval.decl) = (yyvsp[0].decl);
	     (yyval.decl).type = NewStringEmpty();
	     SwigType_add_rvalue_reference((yyval.decl).type);
	     if ((yyvsp[0].decl).type) {
	       SwigType_push((yyval.decl).type,(yyvsp[0].decl).type);
	       Delete((yyvsp[0].decl).type);
	     }
           }
#line 9031 "y.tab.c" /* yacc.c:1646  */
    break;

  case 308:
#line 4988 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();

	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-2].str));
	     if ((yyval.decl).type) {
	       SwigType_push(t,(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = t;
	     }
#line 9047 "y.tab.c" /* yacc.c:1646  */
    break;

  case 309:
#line 4999 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-2].str));
	     SwigType_push((yyvsp[-3].type),t);
	     if ((yyval.decl).type) {
	       SwigType_push((yyvsp[-3].type),(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = (yyvsp[-3].type);
	     Delete(t);
	   }
#line 9064 "y.tab.c" /* yacc.c:1646  */
    break;

  case 310:
#line 5011 "parser.y" /* yacc.c:1646  */
    { 
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer((yyvsp[-4].type),(yyvsp[-3].str));
	     SwigType_add_reference((yyvsp[-4].type));
	     if ((yyval.decl).type) {
	       SwigType_push((yyvsp[-4].type),(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = (yyvsp[-4].type);
	   }
#line 9079 "y.tab.c" /* yacc.c:1646  */
    break;

  case 311:
#line 5021 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-3].str));
	     SwigType_add_reference(t);
	     if ((yyval.decl).type) {
	       SwigType_push(t,(yyval.decl).type);
	       Delete((yyval.decl).type);
	     } 
	     (yyval.decl).type = t;
	   }
#line 9095 "y.tab.c" /* yacc.c:1646  */
    break;

  case 312:
#line 5035 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      if ((yyval.decl).type) {
		SwigType_push((yyvsp[-4].type),(yyval.decl).type);
		Delete((yyval.decl).type);
	      }
	      (yyval.decl).type = (yyvsp[-4].type);
           }
#line 9108 "y.tab.c" /* yacc.c:1646  */
    break;

  case 313:
#line 5043 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      SwigType_add_reference((yyvsp[-5].type));
              if ((yyval.decl).type) {
		SwigType_push((yyvsp[-5].type),(yyval.decl).type);
		Delete((yyval.decl).type);
	      }
	      (yyval.decl).type = (yyvsp[-5].type);
           }
#line 9122 "y.tab.c" /* yacc.c:1646  */
    break;

  case 314:
#line 5052 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      SwigType_add_rvalue_reference((yyvsp[-5].type));
              if ((yyval.decl).type) {
		SwigType_push((yyvsp[-5].type),(yyval.decl).type);
		Delete((yyval.decl).type);
	      }
	      (yyval.decl).type = (yyvsp[-5].type);
           }
#line 9136 "y.tab.c" /* yacc.c:1646  */
    break;

  case 315:
#line 5061 "parser.y" /* yacc.c:1646  */
    {
              (yyval.decl) = (yyvsp[0].decl);
	      if (!(yyval.decl).type) (yyval.decl).type = NewStringEmpty();
           }
#line 9145 "y.tab.c" /* yacc.c:1646  */
    break;

  case 316:
#line 5065 "parser.y" /* yacc.c:1646  */
    {
	     (yyval.decl) = (yyvsp[0].decl);
	     (yyval.decl).type = NewStringEmpty();
	     SwigType_add_reference((yyval.decl).type);
	     if ((yyvsp[0].decl).type) {
	       SwigType_push((yyval.decl).type,(yyvsp[0].decl).type);
	       Delete((yyvsp[0].decl).type);
	     }
           }
#line 9159 "y.tab.c" /* yacc.c:1646  */
    break;

  case 317:
#line 5074 "parser.y" /* yacc.c:1646  */
    {
	     /* Introduced in C++11, move operator && */
             /* Adds one S/R conflict */
	     (yyval.decl) = (yyvsp[0].decl);
	     (yyval.decl).type = NewStringEmpty();
	     SwigType_add_rvalue_reference((yyval.decl).type);
	     if ((yyvsp[0].decl).type) {
	       SwigType_push((yyval.decl).type,(yyvsp[0].decl).type);
	       Delete((yyvsp[0].decl).type);
	     }
           }
#line 9175 "y.tab.c" /* yacc.c:1646  */
    break;

  case 318:
#line 5085 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();

	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-5].str));
	     if ((yyval.decl).type) {
	       SwigType_push(t,(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = t;
	     }
#line 9191 "y.tab.c" /* yacc.c:1646  */
    break;

  case 319:
#line 5096 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-5].str));
	     SwigType_push((yyvsp[-6].type),t);
	     if ((yyval.decl).type) {
	       SwigType_push((yyvsp[-6].type),(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = (yyvsp[-6].type);
	     Delete(t);
	   }
#line 9208 "y.tab.c" /* yacc.c:1646  */
    break;

  case 320:
#line 5108 "parser.y" /* yacc.c:1646  */
    { 
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer((yyvsp[-7].type),(yyvsp[-6].str));
	     SwigType_add_reference((yyvsp[-7].type));
	     if ((yyval.decl).type) {
	       SwigType_push((yyvsp[-7].type),(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = (yyvsp[-7].type);
	   }
#line 9223 "y.tab.c" /* yacc.c:1646  */
    break;

  case 321:
#line 5118 "parser.y" /* yacc.c:1646  */
    { 
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer((yyvsp[-7].type),(yyvsp[-6].str));
	     SwigType_add_rvalue_reference((yyvsp[-7].type));
	     if ((yyval.decl).type) {
	       SwigType_push((yyvsp[-7].type),(yyval.decl).type);
	       Delete((yyval.decl).type);
	     }
	     (yyval.decl).type = (yyvsp[-7].type);
	   }
#line 9238 "y.tab.c" /* yacc.c:1646  */
    break;

  case 322:
#line 5128 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-6].str));
	     SwigType_add_reference(t);
	     if ((yyval.decl).type) {
	       SwigType_push(t,(yyval.decl).type);
	       Delete((yyval.decl).type);
	     } 
	     (yyval.decl).type = t;
	   }
#line 9254 "y.tab.c" /* yacc.c:1646  */
    break;

  case 323:
#line 5139 "parser.y" /* yacc.c:1646  */
    { 
	     SwigType *t = NewStringEmpty();
	     (yyval.decl) = (yyvsp[0].decl);
	     SwigType_add_memberpointer(t,(yyvsp[-6].str));
	     SwigType_add_rvalue_reference(t);
	     if ((yyval.decl).type) {
	       SwigType_push(t,(yyval.decl).type);
	       Delete((yyval.decl).type);
	     } 
	     (yyval.decl).type = t;
	   }
#line 9270 "y.tab.c" /* yacc.c:1646  */
    break;

  case 324:
#line 5152 "parser.y" /* yacc.c:1646  */
    {
                /* Note: This is non-standard C.  Template declarator is allowed to follow an identifier */
                 (yyval.decl).id = Char((yyvsp[0].str));
		 (yyval.decl).type = 0;
		 (yyval.decl).parms = 0;
		 (yyval.decl).have_parms = 0;
                  }
#line 9282 "y.tab.c" /* yacc.c:1646  */
    break;

  case 325:
#line 5159 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.decl).id = Char(NewStringf("~%s",(yyvsp[0].str)));
                  (yyval.decl).type = 0;
                  (yyval.decl).parms = 0;
                  (yyval.decl).have_parms = 0;
                  }
#line 9293 "y.tab.c" /* yacc.c:1646  */
    break;

  case 326:
#line 5167 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.decl).id = Char((yyvsp[-1].str));
                  (yyval.decl).type = 0;
                  (yyval.decl).parms = 0;
                  (yyval.decl).have_parms = 0;
                  }
#line 9304 "y.tab.c" /* yacc.c:1646  */
    break;

  case 327:
#line 5183 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[-1].decl);
		    if ((yyval.decl).type) {
		      SwigType_push((yyvsp[-2].type),(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = (yyvsp[-2].type);
                  }
#line 9317 "y.tab.c" /* yacc.c:1646  */
    break;

  case 328:
#line 5191 "parser.y" /* yacc.c:1646  */
    {
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-1].decl);
		    t = NewStringEmpty();
		    SwigType_add_memberpointer(t,(yyvsp[-3].str));
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
		    }
#line 9333 "y.tab.c" /* yacc.c:1646  */
    break;

  case 329:
#line 5202 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-2].decl);
		    t = NewStringEmpty();
		    SwigType_add_array(t,"");
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
                  }
#line 9349 "y.tab.c" /* yacc.c:1646  */
    break;

  case 330:
#line 5213 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-3].decl);
		    t = NewStringEmpty();
		    SwigType_add_array(t,(yyvsp[-1].dtype).val);
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
                  }
#line 9365 "y.tab.c" /* yacc.c:1646  */
    break;

  case 331:
#line 5224 "parser.y" /* yacc.c:1646  */
    {
		    SwigType *t;
                    (yyval.decl) = (yyvsp[-3].decl);
		    t = NewStringEmpty();
		    SwigType_add_function(t,(yyvsp[-1].pl));
		    if (!(yyval.decl).have_parms) {
		      (yyval.decl).parms = (yyvsp[-1].pl);
		      (yyval.decl).have_parms = 1;
		    }
		    if (!(yyval.decl).type) {
		      (yyval.decl).type = t;
		    } else {
		      SwigType_push(t, (yyval.decl).type);
		      Delete((yyval.decl).type);
		      (yyval.decl).type = t;
		    }
		  }
#line 9387 "y.tab.c" /* yacc.c:1646  */
    break;

  case 332:
#line 5243 "parser.y" /* yacc.c:1646  */
    {
                /* Note: This is non-standard C.  Template declarator is allowed to follow an identifier */
                 (yyval.decl).id = Char((yyvsp[0].str));
		 (yyval.decl).type = 0;
		 (yyval.decl).parms = 0;
		 (yyval.decl).have_parms = 0;
                  }
#line 9399 "y.tab.c" /* yacc.c:1646  */
    break;

  case 333:
#line 5251 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.decl).id = Char(NewStringf("~%s",(yyvsp[0].str)));
                  (yyval.decl).type = 0;
                  (yyval.decl).parms = 0;
                  (yyval.decl).have_parms = 0;
                  }
#line 9410 "y.tab.c" /* yacc.c:1646  */
    break;

  case 334:
#line 5268 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[-1].decl);
		    if ((yyval.decl).type) {
		      SwigType_push((yyvsp[-2].type),(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = (yyvsp[-2].type);
                  }
#line 9423 "y.tab.c" /* yacc.c:1646  */
    break;

  case 335:
#line 5276 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl) = (yyvsp[-1].decl);
		    if (!(yyval.decl).type) {
		      (yyval.decl).type = NewStringEmpty();
		    }
		    SwigType_add_reference((yyval.decl).type);
                  }
#line 9435 "y.tab.c" /* yacc.c:1646  */
    break;

  case 336:
#line 5283 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl) = (yyvsp[-1].decl);
		    if (!(yyval.decl).type) {
		      (yyval.decl).type = NewStringEmpty();
		    }
		    SwigType_add_rvalue_reference((yyval.decl).type);
                  }
#line 9447 "y.tab.c" /* yacc.c:1646  */
    break;

  case 337:
#line 5290 "parser.y" /* yacc.c:1646  */
    {
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-1].decl);
		    t = NewStringEmpty();
		    SwigType_add_memberpointer(t,(yyvsp[-3].str));
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
		    }
#line 9463 "y.tab.c" /* yacc.c:1646  */
    break;

  case 338:
#line 5301 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-2].decl);
		    t = NewStringEmpty();
		    SwigType_add_array(t,"");
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
                  }
#line 9479 "y.tab.c" /* yacc.c:1646  */
    break;

  case 339:
#line 5312 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-3].decl);
		    t = NewStringEmpty();
		    SwigType_add_array(t,(yyvsp[-1].dtype).val);
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
                  }
#line 9495 "y.tab.c" /* yacc.c:1646  */
    break;

  case 340:
#line 5323 "parser.y" /* yacc.c:1646  */
    {
		    SwigType *t;
                    (yyval.decl) = (yyvsp[-3].decl);
		    t = NewStringEmpty();
		    SwigType_add_function(t,(yyvsp[-1].pl));
		    if (!(yyval.decl).have_parms) {
		      (yyval.decl).parms = (yyvsp[-1].pl);
		      (yyval.decl).have_parms = 1;
		    }
		    if (!(yyval.decl).type) {
		      (yyval.decl).type = t;
		    } else {
		      SwigType_push(t, (yyval.decl).type);
		      Delete((yyval.decl).type);
		      (yyval.decl).type = t;
		    }
                 }
#line 9517 "y.tab.c" /* yacc.c:1646  */
    break;

  case 341:
#line 5343 "parser.y" /* yacc.c:1646  */
    {
		    SwigType *t;
                    Append((yyvsp[-4].str), " "); /* intervening space is mandatory */
                    Append((yyvsp[-4].str), Char((yyvsp[-3].id)));
		    (yyval.decl).id = Char((yyvsp[-4].str));
		    t = NewStringEmpty();
		    SwigType_add_function(t,(yyvsp[-1].pl));
		    if (!(yyval.decl).have_parms) {
		      (yyval.decl).parms = (yyvsp[-1].pl);
		      (yyval.decl).have_parms = 1;
		    }
		    if (!(yyval.decl).type) {
		      (yyval.decl).type = t;
		    } else {
		      SwigType_push(t, (yyval.decl).type);
		      Delete((yyval.decl).type);
		      (yyval.decl).type = t;
		    }
		  }
#line 9541 "y.tab.c" /* yacc.c:1646  */
    break;

  case 342:
#line 5364 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl).type = (yyvsp[0].type);
                    (yyval.decl).id = 0;
		    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
                  }
#line 9552 "y.tab.c" /* yacc.c:1646  */
    break;

  case 343:
#line 5370 "parser.y" /* yacc.c:1646  */
    { 
                     (yyval.decl) = (yyvsp[0].decl);
                     SwigType_push((yyvsp[-1].type),(yyvsp[0].decl).type);
		     (yyval.decl).type = (yyvsp[-1].type);
		     Delete((yyvsp[0].decl).type);
                  }
#line 9563 "y.tab.c" /* yacc.c:1646  */
    break;

  case 344:
#line 5376 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl).type = (yyvsp[-1].type);
		    SwigType_add_reference((yyval.decl).type);
		    (yyval.decl).id = 0;
		    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
		  }
#line 9575 "y.tab.c" /* yacc.c:1646  */
    break;

  case 345:
#line 5383 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl).type = (yyvsp[-1].type);
		    SwigType_add_rvalue_reference((yyval.decl).type);
		    (yyval.decl).id = 0;
		    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
		  }
#line 9587 "y.tab.c" /* yacc.c:1646  */
    break;

  case 346:
#line 5390 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[0].decl);
		    SwigType_add_reference((yyvsp[-2].type));
		    if ((yyval.decl).type) {
		      SwigType_push((yyvsp[-2].type),(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = (yyvsp[-2].type);
                  }
#line 9601 "y.tab.c" /* yacc.c:1646  */
    break;

  case 347:
#line 5399 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[0].decl);
		    SwigType_add_rvalue_reference((yyvsp[-2].type));
		    if ((yyval.decl).type) {
		      SwigType_push((yyvsp[-2].type),(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = (yyvsp[-2].type);
                  }
#line 9615 "y.tab.c" /* yacc.c:1646  */
    break;

  case 348:
#line 5408 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[0].decl);
                  }
#line 9623 "y.tab.c" /* yacc.c:1646  */
    break;

  case 349:
#line 5411 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[0].decl);
		    (yyval.decl).type = NewStringEmpty();
		    SwigType_add_reference((yyval.decl).type);
		    if ((yyvsp[0].decl).type) {
		      SwigType_push((yyval.decl).type,(yyvsp[0].decl).type);
		      Delete((yyvsp[0].decl).type);
		    }
                  }
#line 9637 "y.tab.c" /* yacc.c:1646  */
    break;

  case 350:
#line 5420 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.decl) = (yyvsp[0].decl);
		    (yyval.decl).type = NewStringEmpty();
		    SwigType_add_rvalue_reference((yyval.decl).type);
		    if ((yyvsp[0].decl).type) {
		      SwigType_push((yyval.decl).type,(yyvsp[0].decl).type);
		      Delete((yyvsp[0].decl).type);
		    }
                  }
#line 9651 "y.tab.c" /* yacc.c:1646  */
    break;

  case 351:
#line 5429 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl).id = 0;
                    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
                    (yyval.decl).type = NewStringEmpty();
		    SwigType_add_reference((yyval.decl).type);
                  }
#line 9663 "y.tab.c" /* yacc.c:1646  */
    break;

  case 352:
#line 5436 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl).id = 0;
                    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
                    (yyval.decl).type = NewStringEmpty();
		    SwigType_add_rvalue_reference((yyval.decl).type);
                  }
#line 9675 "y.tab.c" /* yacc.c:1646  */
    break;

  case 353:
#line 5443 "parser.y" /* yacc.c:1646  */
    { 
		    (yyval.decl).type = NewStringEmpty();
                    SwigType_add_memberpointer((yyval.decl).type,(yyvsp[-1].str));
                    (yyval.decl).id = 0;
                    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
      	          }
#line 9687 "y.tab.c" /* yacc.c:1646  */
    break;

  case 354:
#line 5450 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t = NewStringEmpty();
                    (yyval.decl).type = (yyvsp[-2].type);
		    (yyval.decl).id = 0;
		    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
		    SwigType_add_memberpointer(t,(yyvsp[-1].str));
		    SwigType_push((yyval.decl).type,t);
		    Delete(t);
                  }
#line 9702 "y.tab.c" /* yacc.c:1646  */
    break;

  case 355:
#line 5460 "parser.y" /* yacc.c:1646  */
    { 
		    (yyval.decl) = (yyvsp[0].decl);
		    SwigType_add_memberpointer((yyvsp[-3].type),(yyvsp[-2].str));
		    if ((yyval.decl).type) {
		      SwigType_push((yyvsp[-3].type),(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = (yyvsp[-3].type);
                  }
#line 9716 "y.tab.c" /* yacc.c:1646  */
    break;

  case 356:
#line 5471 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-2].decl);
		    t = NewStringEmpty();
		    SwigType_add_array(t,"");
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
                  }
#line 9732 "y.tab.c" /* yacc.c:1646  */
    break;

  case 357:
#line 5482 "parser.y" /* yacc.c:1646  */
    { 
		    SwigType *t;
		    (yyval.decl) = (yyvsp[-3].decl);
		    t = NewStringEmpty();
		    SwigType_add_array(t,(yyvsp[-1].dtype).val);
		    if ((yyval.decl).type) {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		    }
		    (yyval.decl).type = t;
                  }
#line 9748 "y.tab.c" /* yacc.c:1646  */
    break;

  case 358:
#line 5493 "parser.y" /* yacc.c:1646  */
    { 
		    (yyval.decl).type = NewStringEmpty();
		    (yyval.decl).id = 0;
		    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
		    SwigType_add_array((yyval.decl).type,"");
                  }
#line 9760 "y.tab.c" /* yacc.c:1646  */
    break;

  case 359:
#line 5500 "parser.y" /* yacc.c:1646  */
    { 
		    (yyval.decl).type = NewStringEmpty();
		    (yyval.decl).id = 0;
		    (yyval.decl).parms = 0;
		    (yyval.decl).have_parms = 0;
		    SwigType_add_array((yyval.decl).type,(yyvsp[-1].dtype).val);
		  }
#line 9772 "y.tab.c" /* yacc.c:1646  */
    break;

  case 360:
#line 5507 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl) = (yyvsp[-1].decl);
		  }
#line 9780 "y.tab.c" /* yacc.c:1646  */
    break;

  case 361:
#line 5510 "parser.y" /* yacc.c:1646  */
    {
		    SwigType *t;
                    (yyval.decl) = (yyvsp[-3].decl);
		    t = NewStringEmpty();
                    SwigType_add_function(t,(yyvsp[-1].pl));
		    if (!(yyval.decl).type) {
		      (yyval.decl).type = t;
		    } else {
		      SwigType_push(t,(yyval.decl).type);
		      Delete((yyval.decl).type);
		      (yyval.decl).type = t;
		    }
		    if (!(yyval.decl).have_parms) {
		      (yyval.decl).parms = (yyvsp[-1].pl);
		      (yyval.decl).have_parms = 1;
		    }
		  }
#line 9802 "y.tab.c" /* yacc.c:1646  */
    break;

  case 362:
#line 5527 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl).type = NewStringEmpty();
                    SwigType_add_function((yyval.decl).type,(yyvsp[-1].pl));
		    (yyval.decl).parms = (yyvsp[-1].pl);
		    (yyval.decl).have_parms = 1;
		    (yyval.decl).id = 0;
                  }
#line 9814 "y.tab.c" /* yacc.c:1646  */
    break;

  case 363:
#line 5537 "parser.y" /* yacc.c:1646  */
    { 
             (yyval.type) = NewStringEmpty();
             SwigType_add_pointer((yyval.type));
	     SwigType_push((yyval.type),(yyvsp[-1].str));
	     SwigType_push((yyval.type),(yyvsp[0].type));
	     Delete((yyvsp[0].type));
           }
#line 9826 "y.tab.c" /* yacc.c:1646  */
    break;

  case 364:
#line 5544 "parser.y" /* yacc.c:1646  */
    {
	     (yyval.type) = NewStringEmpty();
	     SwigType_add_pointer((yyval.type));
	     SwigType_push((yyval.type),(yyvsp[0].type));
	     Delete((yyvsp[0].type));
	   }
#line 9837 "y.tab.c" /* yacc.c:1646  */
    break;

  case 365:
#line 5550 "parser.y" /* yacc.c:1646  */
    { 
	     (yyval.type) = NewStringEmpty();
	     SwigType_add_pointer((yyval.type));
	     SwigType_push((yyval.type),(yyvsp[0].str));
           }
#line 9847 "y.tab.c" /* yacc.c:1646  */
    break;

  case 366:
#line 5555 "parser.y" /* yacc.c:1646  */
    {
	     (yyval.type) = NewStringEmpty();
	     SwigType_add_pointer((yyval.type));
           }
#line 9856 "y.tab.c" /* yacc.c:1646  */
    break;

  case 367:
#line 5561 "parser.y" /* yacc.c:1646  */
    {
	          (yyval.str) = NewStringEmpty();
	          if ((yyvsp[0].id)) SwigType_add_qualifier((yyval.str),(yyvsp[0].id));
               }
#line 9865 "y.tab.c" /* yacc.c:1646  */
    break;

  case 368:
#line 5565 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.str) = (yyvsp[0].str);
	          if ((yyvsp[-1].id)) SwigType_add_qualifier((yyval.str),(yyvsp[-1].id));
               }
#line 9874 "y.tab.c" /* yacc.c:1646  */
    break;

  case 369:
#line 5571 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "const"; }
#line 9880 "y.tab.c" /* yacc.c:1646  */
    break;

  case 370:
#line 5572 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = "volatile"; }
#line 9886 "y.tab.c" /* yacc.c:1646  */
    break;

  case 371:
#line 5573 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = 0; }
#line 9892 "y.tab.c" /* yacc.c:1646  */
    break;

  case 372:
#line 5579 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.type) = (yyvsp[0].type);
                   Replace((yyval.type),"typename ","", DOH_REPLACE_ANY);
                }
#line 9901 "y.tab.c" /* yacc.c:1646  */
    break;

  case 373:
#line 5585 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.type) = (yyvsp[0].type);
	           SwigType_push((yyval.type),(yyvsp[-1].str));
               }
#line 9910 "y.tab.c" /* yacc.c:1646  */
    break;

  case 374:
#line 5589 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 9916 "y.tab.c" /* yacc.c:1646  */
    break;

  case 375:
#line 5590 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.type) = (yyvsp[-1].type);
	          SwigType_push((yyval.type),(yyvsp[0].str));
	       }
#line 9925 "y.tab.c" /* yacc.c:1646  */
    break;

  case 376:
#line 5594 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.type) = (yyvsp[-1].type);
	          SwigType_push((yyval.type),(yyvsp[0].str));
	          SwigType_push((yyval.type),(yyvsp[-2].str));
	       }
#line 9935 "y.tab.c" /* yacc.c:1646  */
    break;

  case 377:
#line 5601 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type);
                  /* Printf(stdout,"primitive = '%s'\n", $$);*/
               }
#line 9943 "y.tab.c" /* yacc.c:1646  */
    break;

  case 378:
#line 5604 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 9949 "y.tab.c" /* yacc.c:1646  */
    break;

  case 379:
#line 5605 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 9955 "y.tab.c" /* yacc.c:1646  */
    break;

  case 380:
#line 5609 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = NewStringf("enum %s", (yyvsp[0].str)); }
#line 9961 "y.tab.c" /* yacc.c:1646  */
    break;

  case 381:
#line 5610 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 9967 "y.tab.c" /* yacc.c:1646  */
    break;

  case 382:
#line 5612 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.type) = (yyvsp[0].str);
               }
#line 9975 "y.tab.c" /* yacc.c:1646  */
    break;

  case 383:
#line 5615 "parser.y" /* yacc.c:1646  */
    { 
		 (yyval.type) = NewStringf("%s %s", (yyvsp[-1].id), (yyvsp[0].str));
               }
#line 9983 "y.tab.c" /* yacc.c:1646  */
    break;

  case 384:
#line 5618 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.type) = (yyvsp[0].type);
               }
#line 9991 "y.tab.c" /* yacc.c:1646  */
    break;

  case 385:
#line 5623 "parser.y" /* yacc.c:1646  */
    {
                 Node *n = Swig_symbol_clookup((yyvsp[-1].str),0);
                 if (!n) {
		   Swig_error(cparse_file, cparse_line, "Identifier %s not defined.\n", (yyvsp[-1].str));
                   (yyval.type) = (yyvsp[-1].str);
                 } else {
                   (yyval.type) = Getattr(n, "type");
                 }
               }
#line 10005 "y.tab.c" /* yacc.c:1646  */
    break;

  case 386:
#line 5634 "parser.y" /* yacc.c:1646  */
    {
		 if (!(yyvsp[0].ptype).type) (yyvsp[0].ptype).type = NewString("int");
		 if ((yyvsp[0].ptype).us) {
		   (yyval.type) = NewStringf("%s %s", (yyvsp[0].ptype).us, (yyvsp[0].ptype).type);
		   Delete((yyvsp[0].ptype).us);
                   Delete((yyvsp[0].ptype).type);
		 } else {
                   (yyval.type) = (yyvsp[0].ptype).type;
		 }
		 if (Cmp((yyval.type),"signed int") == 0) {
		   Delete((yyval.type));
		   (yyval.type) = NewString("int");
                 } else if (Cmp((yyval.type),"signed long") == 0) {
		   Delete((yyval.type));
                   (yyval.type) = NewString("long");
                 } else if (Cmp((yyval.type),"signed short") == 0) {
		   Delete((yyval.type));
		   (yyval.type) = NewString("short");
		 } else if (Cmp((yyval.type),"signed long long") == 0) {
		   Delete((yyval.type));
		   (yyval.type) = NewString("long long");
		 }
               }
#line 10033 "y.tab.c" /* yacc.c:1646  */
    break;

  case 387:
#line 5659 "parser.y" /* yacc.c:1646  */
    { 
                 (yyval.ptype) = (yyvsp[0].ptype);
               }
#line 10041 "y.tab.c" /* yacc.c:1646  */
    break;

  case 388:
#line 5662 "parser.y" /* yacc.c:1646  */
    {
                    if ((yyvsp[-1].ptype).us && (yyvsp[0].ptype).us) {
		      Swig_error(cparse_file, cparse_line, "Extra %s specifier.\n", (yyvsp[0].ptype).us);
		    }
                    (yyval.ptype) = (yyvsp[0].ptype);
                    if ((yyvsp[-1].ptype).us) (yyval.ptype).us = (yyvsp[-1].ptype).us;
		    if ((yyvsp[-1].ptype).type) {
		      if (!(yyvsp[0].ptype).type) (yyval.ptype).type = (yyvsp[-1].ptype).type;
		      else {
			int err = 0;
			if ((Cmp((yyvsp[-1].ptype).type,"long") == 0)) {
			  if ((Cmp((yyvsp[0].ptype).type,"long") == 0) || (Strncmp((yyvsp[0].ptype).type,"double",6) == 0)) {
			    (yyval.ptype).type = NewStringf("long %s", (yyvsp[0].ptype).type);
			  } else if (Cmp((yyvsp[0].ptype).type,"int") == 0) {
			    (yyval.ptype).type = (yyvsp[-1].ptype).type;
			  } else {
			    err = 1;
			  }
			} else if ((Cmp((yyvsp[-1].ptype).type,"short")) == 0) {
			  if (Cmp((yyvsp[0].ptype).type,"int") == 0) {
			    (yyval.ptype).type = (yyvsp[-1].ptype).type;
			  } else {
			    err = 1;
			  }
			} else if (Cmp((yyvsp[-1].ptype).type,"int") == 0) {
			  (yyval.ptype).type = (yyvsp[0].ptype).type;
			} else if (Cmp((yyvsp[-1].ptype).type,"double") == 0) {
			  if (Cmp((yyvsp[0].ptype).type,"long") == 0) {
			    (yyval.ptype).type = NewString("long double");
			  } else if (Cmp((yyvsp[0].ptype).type,"complex") == 0) {
			    (yyval.ptype).type = NewString("double complex");
			  } else {
			    err = 1;
			  }
			} else if (Cmp((yyvsp[-1].ptype).type,"float") == 0) {
			  if (Cmp((yyvsp[0].ptype).type,"complex") == 0) {
			    (yyval.ptype).type = NewString("float complex");
			  } else {
			    err = 1;
			  }
			} else if (Cmp((yyvsp[-1].ptype).type,"complex") == 0) {
			  (yyval.ptype).type = NewStringf("%s complex", (yyvsp[0].ptype).type);
			} else {
			  err = 1;
			}
			if (err) {
			  Swig_error(cparse_file, cparse_line, "Extra %s specifier.\n", (yyvsp[-1].ptype).type);
			}
		      }
		    }
               }
#line 10097 "y.tab.c" /* yacc.c:1646  */
    break;

  case 389:
#line 5716 "parser.y" /* yacc.c:1646  */
    { 
		    (yyval.ptype).type = NewString("int");
                    (yyval.ptype).us = 0;
               }
#line 10106 "y.tab.c" /* yacc.c:1646  */
    break;

  case 390:
#line 5720 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("short");
                    (yyval.ptype).us = 0;
                }
#line 10115 "y.tab.c" /* yacc.c:1646  */
    break;

  case 391:
#line 5724 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("long");
                    (yyval.ptype).us = 0;
                }
#line 10124 "y.tab.c" /* yacc.c:1646  */
    break;

  case 392:
#line 5728 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("char");
                    (yyval.ptype).us = 0;
                }
#line 10133 "y.tab.c" /* yacc.c:1646  */
    break;

  case 393:
#line 5732 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("wchar_t");
                    (yyval.ptype).us = 0;
                }
#line 10142 "y.tab.c" /* yacc.c:1646  */
    break;

  case 394:
#line 5736 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("float");
                    (yyval.ptype).us = 0;
                }
#line 10151 "y.tab.c" /* yacc.c:1646  */
    break;

  case 395:
#line 5740 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("double");
                    (yyval.ptype).us = 0;
                }
#line 10160 "y.tab.c" /* yacc.c:1646  */
    break;

  case 396:
#line 5744 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).us = NewString("signed");
                    (yyval.ptype).type = 0;
                }
#line 10169 "y.tab.c" /* yacc.c:1646  */
    break;

  case 397:
#line 5748 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).us = NewString("unsigned");
                    (yyval.ptype).type = 0;
                }
#line 10178 "y.tab.c" /* yacc.c:1646  */
    break;

  case 398:
#line 5752 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("complex");
                    (yyval.ptype).us = 0;
                }
#line 10187 "y.tab.c" /* yacc.c:1646  */
    break;

  case 399:
#line 5756 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("__int8");
                    (yyval.ptype).us = 0;
                }
#line 10196 "y.tab.c" /* yacc.c:1646  */
    break;

  case 400:
#line 5760 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("__int16");
                    (yyval.ptype).us = 0;
                }
#line 10205 "y.tab.c" /* yacc.c:1646  */
    break;

  case 401:
#line 5764 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("__int32");
                    (yyval.ptype).us = 0;
                }
#line 10214 "y.tab.c" /* yacc.c:1646  */
    break;

  case 402:
#line 5768 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.ptype).type = NewString("__int64");
                    (yyval.ptype).us = 0;
                }
#line 10223 "y.tab.c" /* yacc.c:1646  */
    break;

  case 403:
#line 5774 "parser.y" /* yacc.c:1646  */
    { /* scanner_check_typedef(); */ }
#line 10229 "y.tab.c" /* yacc.c:1646  */
    break;

  case 404:
#line 5774 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.dtype) = (yyvsp[0].dtype);
		   if ((yyval.dtype).type == T_STRING) {
		     (yyval.dtype).rawval = NewStringf("\"%(escape)s\"",(yyval.dtype).val);
		   } else if ((yyval.dtype).type != T_CHAR && (yyval.dtype).type != T_WSTRING && (yyval.dtype).type != T_WCHAR) {
		     (yyval.dtype).rawval = 0;
		   }
		   (yyval.dtype).qualifier = 0;
		   (yyval.dtype).bitfield = 0;
		   (yyval.dtype).throws = 0;
		   (yyval.dtype).throwf = 0;
		   (yyval.dtype).nexcept = 0;
		   scanner_ignore_typedef();
                }
#line 10248 "y.tab.c" /* yacc.c:1646  */
    break;

  case 405:
#line 5788 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype) = (yyvsp[0].dtype);
		}
#line 10256 "y.tab.c" /* yacc.c:1646  */
    break;

  case 406:
#line 5793 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype) = (yyvsp[0].dtype);
		}
#line 10264 "y.tab.c" /* yacc.c:1646  */
    break;

  case 407:
#line 5796 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype) = (yyvsp[0].dtype);
		}
#line 10272 "y.tab.c" /* yacc.c:1646  */
    break;

  case 408:
#line 5802 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype).val = NewString("delete");
		  (yyval.dtype).rawval = 0;
		  (yyval.dtype).type = T_STRING;
		  (yyval.dtype).qualifier = 0;
		  (yyval.dtype).bitfield = 0;
		  (yyval.dtype).throws = 0;
		  (yyval.dtype).throwf = 0;
		  (yyval.dtype).nexcept = 0;
		}
#line 10287 "y.tab.c" /* yacc.c:1646  */
    break;

  case 409:
#line 5815 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype).val = NewString("default");
		  (yyval.dtype).rawval = 0;
		  (yyval.dtype).type = T_STRING;
		  (yyval.dtype).qualifier = 0;
		  (yyval.dtype).bitfield = 0;
		  (yyval.dtype).throws = 0;
		  (yyval.dtype).throwf = 0;
		  (yyval.dtype).nexcept = 0;
		}
#line 10302 "y.tab.c" /* yacc.c:1646  */
    break;

  case 410:
#line 5829 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (yyvsp[0].id); }
#line 10308 "y.tab.c" /* yacc.c:1646  */
    break;

  case 411:
#line 5830 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (char *) 0;}
#line 10314 "y.tab.c" /* yacc.c:1646  */
    break;

  case 412:
#line 5833 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 10320 "y.tab.c" /* yacc.c:1646  */
    break;

  case 413:
#line 5834 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 10326 "y.tab.c" /* yacc.c:1646  */
    break;

  case 414:
#line 5838 "parser.y" /* yacc.c:1646  */
    {
		 Node *leftSibling = Getattr((yyvsp[-4].node),"_last");
		 set_nextSibling(leftSibling,(yyvsp[-1].node));
		 Setattr((yyvsp[-4].node),"_last",(yyvsp[-1].node));
		 (yyval.node) = (yyvsp[-4].node);
	       }
#line 10337 "y.tab.c" /* yacc.c:1646  */
    break;

  case 415:
#line 5844 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = (yyvsp[-2].node);
	       }
#line 10345 "y.tab.c" /* yacc.c:1646  */
    break;

  case 416:
#line 5847 "parser.y" /* yacc.c:1646  */
    {
		 Setattr((yyvsp[-1].node),"_last",(yyvsp[-1].node));
		 (yyval.node) = (yyvsp[-1].node);
	       }
#line 10354 "y.tab.c" /* yacc.c:1646  */
    break;

  case 417:
#line 5851 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = 0;
	       }
#line 10362 "y.tab.c" /* yacc.c:1646  */
    break;

  case 418:
#line 5856 "parser.y" /* yacc.c:1646  */
    {
		   SwigType *type = NewSwigType(T_INT);
		   (yyval.node) = new_node("enumitem");
		   Setattr((yyval.node),"name",(yyvsp[0].id));
		   Setattr((yyval.node),"type",type);
		   SetFlag((yyval.node),"feature:immutable");
		   Delete(type);
		 }
#line 10375 "y.tab.c" /* yacc.c:1646  */
    break;

  case 419:
#line 5864 "parser.y" /* yacc.c:1646  */
    {
		   SwigType *type = NewSwigType((yyvsp[0].dtype).type == T_BOOL ? T_BOOL : ((yyvsp[0].dtype).type == T_CHAR ? T_CHAR : T_INT));
		   (yyval.node) = new_node("enumitem");
		   Setattr((yyval.node),"name",(yyvsp[-2].id));
		   Setattr((yyval.node),"type",type);
		   SetFlag((yyval.node),"feature:immutable");
		   Setattr((yyval.node),"enumvalue", (yyvsp[0].dtype).val);
		   Setattr((yyval.node),"value",(yyvsp[-2].id));
		   Delete(type);
                 }
#line 10390 "y.tab.c" /* yacc.c:1646  */
    break;

  case 420:
#line 5876 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.dtype) = (yyvsp[0].dtype);
		   if (((yyval.dtype).type != T_INT) && ((yyval.dtype).type != T_UINT) &&
		       ((yyval.dtype).type != T_LONG) && ((yyval.dtype).type != T_ULONG) &&
		       ((yyval.dtype).type != T_LONGLONG) && ((yyval.dtype).type != T_ULONGLONG) &&
		       ((yyval.dtype).type != T_SHORT) && ((yyval.dtype).type != T_USHORT) &&
		       ((yyval.dtype).type != T_SCHAR) && ((yyval.dtype).type != T_UCHAR) &&
		       ((yyval.dtype).type != T_CHAR) && ((yyval.dtype).type != T_BOOL)) {
		     Swig_error(cparse_file,cparse_line,"Type error. Expecting an integral type\n");
		   }
                }
#line 10406 "y.tab.c" /* yacc.c:1646  */
    break;

  case 421:
#line 5891 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10412 "y.tab.c" /* yacc.c:1646  */
    break;

  case 422:
#line 5892 "parser.y" /* yacc.c:1646  */
    {
		 Node *n;
		 (yyval.dtype).val = (yyvsp[0].type);
		 (yyval.dtype).type = T_INT;
		 /* Check if value is in scope */
		 n = Swig_symbol_clookup((yyvsp[0].type),0);
		 if (n) {
                   /* A band-aid for enum values used in expressions. */
                   if (Strcmp(nodeType(n),"enumitem") == 0) {
                     String *q = Swig_symbol_qualified(n);
                     if (q) {
                       (yyval.dtype).val = NewStringf("%s::%s", q, Getattr(n,"name"));
                       Delete(q);
                     }
                   }
		 }
               }
#line 10434 "y.tab.c" /* yacc.c:1646  */
    break;

  case 423:
#line 5911 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10440 "y.tab.c" /* yacc.c:1646  */
    break;

  case 424:
#line 5912 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.dtype).val = (yyvsp[0].str);
                    (yyval.dtype).type = T_STRING;
               }
#line 10449 "y.tab.c" /* yacc.c:1646  */
    break;

  case 425:
#line 5916 "parser.y" /* yacc.c:1646  */
    {
		  SwigType_push((yyvsp[-2].type),(yyvsp[-1].decl).type);
		  (yyval.dtype).val = NewStringf("sizeof(%s)",SwigType_str((yyvsp[-2].type),0));
		  (yyval.dtype).type = T_ULONG;
               }
#line 10459 "y.tab.c" /* yacc.c:1646  */
    break;

  case 426:
#line 5921 "parser.y" /* yacc.c:1646  */
    {
		  SwigType_push((yyvsp[-2].type),(yyvsp[-1].decl).type);
		  (yyval.dtype).val = NewStringf("sizeof...(%s)",SwigType_str((yyvsp[-2].type),0));
		  (yyval.dtype).type = T_ULONG;
               }
#line 10469 "y.tab.c" /* yacc.c:1646  */
    break;

  case 427:
#line 5926 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10475 "y.tab.c" /* yacc.c:1646  */
    break;

  case 428:
#line 5927 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.dtype).val = (yyvsp[0].str);
		    (yyval.dtype).rawval = NewStringf("L\"%s\"", (yyval.dtype).val);
                    (yyval.dtype).type = T_WSTRING;
	       }
#line 10485 "y.tab.c" /* yacc.c:1646  */
    break;

  case 429:
#line 5932 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype).val = NewString((yyvsp[0].str));
		  if (Len((yyval.dtype).val)) {
		    (yyval.dtype).rawval = NewStringf("'%(escape)s'", (yyval.dtype).val);
		  } else {
		    (yyval.dtype).rawval = NewString("'\\0'");
		  }
		  (yyval.dtype).type = T_CHAR;
		  (yyval.dtype).bitfield = 0;
		  (yyval.dtype).throws = 0;
		  (yyval.dtype).throwf = 0;
		  (yyval.dtype).nexcept = 0;
	       }
#line 10503 "y.tab.c" /* yacc.c:1646  */
    break;

  case 430:
#line 5945 "parser.y" /* yacc.c:1646  */
    {
		  (yyval.dtype).val = NewString((yyvsp[0].str));
		  if (Len((yyval.dtype).val)) {
		    (yyval.dtype).rawval = NewStringf("L\'%s\'", (yyval.dtype).val);
		  } else {
		    (yyval.dtype).rawval = NewString("L'\\0'");
		  }
		  (yyval.dtype).type = T_WCHAR;
		  (yyval.dtype).bitfield = 0;
		  (yyval.dtype).throws = 0;
		  (yyval.dtype).throwf = 0;
		  (yyval.dtype).nexcept = 0;
	       }
#line 10521 "y.tab.c" /* yacc.c:1646  */
    break;

  case 431:
#line 5960 "parser.y" /* yacc.c:1646  */
    {
   	            (yyval.dtype).val = NewStringf("(%s)",(yyvsp[-1].dtype).val);
		    (yyval.dtype).type = (yyvsp[-1].dtype).type;
   	       }
#line 10530 "y.tab.c" /* yacc.c:1646  */
    break;

  case 432:
#line 5967 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype) = (yyvsp[0].dtype);
		 if ((yyvsp[0].dtype).type != T_STRING) {
		   switch ((yyvsp[-2].dtype).type) {
		     case T_FLOAT:
		     case T_DOUBLE:
		     case T_LONGDOUBLE:
		     case T_FLTCPLX:
		     case T_DBLCPLX:
		       (yyval.dtype).val = NewStringf("(%s)%s", (yyvsp[-2].dtype).val, (yyvsp[0].dtype).val); /* SwigType_str and decimal points don't mix! */
		       break;
		     default:
		       (yyval.dtype).val = NewStringf("(%s) %s", SwigType_str((yyvsp[-2].dtype).val,0), (yyvsp[0].dtype).val);
		       break;
		   }
		 }
 	       }
#line 10552 "y.tab.c" /* yacc.c:1646  */
    break;

  case 433:
#line 5984 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype) = (yyvsp[0].dtype);
		 if ((yyvsp[0].dtype).type != T_STRING) {
		   SwigType_push((yyvsp[-3].dtype).val,(yyvsp[-2].type));
		   (yyval.dtype).val = NewStringf("(%s) %s", SwigType_str((yyvsp[-3].dtype).val,0), (yyvsp[0].dtype).val);
		 }
 	       }
#line 10564 "y.tab.c" /* yacc.c:1646  */
    break;

  case 434:
#line 5991 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype) = (yyvsp[0].dtype);
		 if ((yyvsp[0].dtype).type != T_STRING) {
		   SwigType_add_reference((yyvsp[-3].dtype).val);
		   (yyval.dtype).val = NewStringf("(%s) %s", SwigType_str((yyvsp[-3].dtype).val,0), (yyvsp[0].dtype).val);
		 }
 	       }
#line 10576 "y.tab.c" /* yacc.c:1646  */
    break;

  case 435:
#line 5998 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype) = (yyvsp[0].dtype);
		 if ((yyvsp[0].dtype).type != T_STRING) {
		   SwigType_add_rvalue_reference((yyvsp[-3].dtype).val);
		   (yyval.dtype).val = NewStringf("(%s) %s", SwigType_str((yyvsp[-3].dtype).val,0), (yyvsp[0].dtype).val);
		 }
 	       }
#line 10588 "y.tab.c" /* yacc.c:1646  */
    break;

  case 436:
#line 6005 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype) = (yyvsp[0].dtype);
		 if ((yyvsp[0].dtype).type != T_STRING) {
		   SwigType_push((yyvsp[-4].dtype).val,(yyvsp[-3].type));
		   SwigType_add_reference((yyvsp[-4].dtype).val);
		   (yyval.dtype).val = NewStringf("(%s) %s", SwigType_str((yyvsp[-4].dtype).val,0), (yyvsp[0].dtype).val);
		 }
 	       }
#line 10601 "y.tab.c" /* yacc.c:1646  */
    break;

  case 437:
#line 6013 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype) = (yyvsp[0].dtype);
		 if ((yyvsp[0].dtype).type != T_STRING) {
		   SwigType_push((yyvsp[-4].dtype).val,(yyvsp[-3].type));
		   SwigType_add_rvalue_reference((yyvsp[-4].dtype).val);
		   (yyval.dtype).val = NewStringf("(%s) %s", SwigType_str((yyvsp[-4].dtype).val,0), (yyvsp[0].dtype).val);
		 }
 	       }
#line 10614 "y.tab.c" /* yacc.c:1646  */
    break;

  case 438:
#line 6021 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype) = (yyvsp[0].dtype);
                 (yyval.dtype).val = NewStringf("&%s",(yyvsp[0].dtype).val);
	       }
#line 10623 "y.tab.c" /* yacc.c:1646  */
    break;

  case 439:
#line 6025 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype) = (yyvsp[0].dtype);
                 (yyval.dtype).val = NewStringf("&&%s",(yyvsp[0].dtype).val);
	       }
#line 10632 "y.tab.c" /* yacc.c:1646  */
    break;

  case 440:
#line 6029 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype) = (yyvsp[0].dtype);
                 (yyval.dtype).val = NewStringf("*%s",(yyvsp[0].dtype).val);
	       }
#line 10641 "y.tab.c" /* yacc.c:1646  */
    break;

  case 441:
#line 6035 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10647 "y.tab.c" /* yacc.c:1646  */
    break;

  case 442:
#line 6036 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10653 "y.tab.c" /* yacc.c:1646  */
    break;

  case 443:
#line 6037 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10659 "y.tab.c" /* yacc.c:1646  */
    break;

  case 444:
#line 6038 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10665 "y.tab.c" /* yacc.c:1646  */
    break;

  case 445:
#line 6039 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10671 "y.tab.c" /* yacc.c:1646  */
    break;

  case 446:
#line 6040 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10677 "y.tab.c" /* yacc.c:1646  */
    break;

  case 447:
#line 6041 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10683 "y.tab.c" /* yacc.c:1646  */
    break;

  case 448:
#line 6042 "parser.y" /* yacc.c:1646  */
    { (yyval.dtype) = (yyvsp[0].dtype); }
#line 10689 "y.tab.c" /* yacc.c:1646  */
    break;

  case 449:
#line 6045 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s+%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10698 "y.tab.c" /* yacc.c:1646  */
    break;

  case 450:
#line 6049 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s-%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10707 "y.tab.c" /* yacc.c:1646  */
    break;

  case 451:
#line 6053 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s*%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10716 "y.tab.c" /* yacc.c:1646  */
    break;

  case 452:
#line 6057 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s/%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10725 "y.tab.c" /* yacc.c:1646  */
    break;

  case 453:
#line 6061 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s%%%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10734 "y.tab.c" /* yacc.c:1646  */
    break;

  case 454:
#line 6065 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s&%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10743 "y.tab.c" /* yacc.c:1646  */
    break;

  case 455:
#line 6069 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s|%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10752 "y.tab.c" /* yacc.c:1646  */
    break;

  case 456:
#line 6073 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s^%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type,(yyvsp[0].dtype).type);
	       }
#line 10761 "y.tab.c" /* yacc.c:1646  */
    break;

  case 457:
#line 6077 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s << %s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote_type((yyvsp[-2].dtype).type);
	       }
#line 10770 "y.tab.c" /* yacc.c:1646  */
    break;

  case 458:
#line 6081 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s >> %s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = promote_type((yyvsp[-2].dtype).type);
	       }
#line 10779 "y.tab.c" /* yacc.c:1646  */
    break;

  case 459:
#line 6085 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s&&%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = cparse_cplusplus ? T_BOOL : T_INT;
	       }
#line 10788 "y.tab.c" /* yacc.c:1646  */
    break;

  case 460:
#line 6089 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s||%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = cparse_cplusplus ? T_BOOL : T_INT;
	       }
#line 10797 "y.tab.c" /* yacc.c:1646  */
    break;

  case 461:
#line 6093 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s==%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = cparse_cplusplus ? T_BOOL : T_INT;
	       }
#line 10806 "y.tab.c" /* yacc.c:1646  */
    break;

  case 462:
#line 6097 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s!=%s",(yyvsp[-2].dtype).val,(yyvsp[0].dtype).val);
		 (yyval.dtype).type = cparse_cplusplus ? T_BOOL : T_INT;
	       }
#line 10815 "y.tab.c" /* yacc.c:1646  */
    break;

  case 463:
#line 6111 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s >= %s", (yyvsp[-2].dtype).val, (yyvsp[0].dtype).val);
		 (yyval.dtype).type = cparse_cplusplus ? T_BOOL : T_INT;
	       }
#line 10824 "y.tab.c" /* yacc.c:1646  */
    break;

  case 464:
#line 6115 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s <= %s", (yyvsp[-2].dtype).val, (yyvsp[0].dtype).val);
		 (yyval.dtype).type = cparse_cplusplus ? T_BOOL : T_INT;
	       }
#line 10833 "y.tab.c" /* yacc.c:1646  */
    break;

  case 465:
#line 6119 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("%s?%s:%s", (yyvsp[-4].dtype).val, (yyvsp[-2].dtype).val, (yyvsp[0].dtype).val);
		 /* This may not be exactly right, but is probably good enough
		  * for the purposes of parsing constant expressions. */
		 (yyval.dtype).type = promote((yyvsp[-2].dtype).type, (yyvsp[0].dtype).type);
	       }
#line 10844 "y.tab.c" /* yacc.c:1646  */
    break;

  case 466:
#line 6125 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("-%s",(yyvsp[0].dtype).val);
		 (yyval.dtype).type = (yyvsp[0].dtype).type;
	       }
#line 10853 "y.tab.c" /* yacc.c:1646  */
    break;

  case 467:
#line 6129 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype).val = NewStringf("+%s",(yyvsp[0].dtype).val);
		 (yyval.dtype).type = (yyvsp[0].dtype).type;
	       }
#line 10862 "y.tab.c" /* yacc.c:1646  */
    break;

  case 468:
#line 6133 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.dtype).val = NewStringf("~%s",(yyvsp[0].dtype).val);
		 (yyval.dtype).type = (yyvsp[0].dtype).type;
	       }
#line 10871 "y.tab.c" /* yacc.c:1646  */
    break;

  case 469:
#line 6137 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.dtype).val = NewStringf("!%s",(yyvsp[0].dtype).val);
		 (yyval.dtype).type = T_INT;
	       }
#line 10880 "y.tab.c" /* yacc.c:1646  */
    break;

  case 470:
#line 6141 "parser.y" /* yacc.c:1646  */
    {
		 String *qty;
                 skip_balanced('(',')');
		 qty = Swig_symbol_type_qualify((yyvsp[-1].type),0);
		 if (SwigType_istemplate(qty)) {
		   String *nstr = SwigType_namestr(qty);
		   Delete(qty);
		   qty = nstr;
		 }
		 (yyval.dtype).val = NewStringf("%s%s",qty,scanner_ccode);
		 Clear(scanner_ccode);
		 (yyval.dtype).type = T_INT;
		 Delete(qty);
               }
#line 10899 "y.tab.c" /* yacc.c:1646  */
    break;

  case 471:
#line 6157 "parser.y" /* yacc.c:1646  */
    {
	        (yyval.str) = NewString("...");
	      }
#line 10907 "y.tab.c" /* yacc.c:1646  */
    break;

  case 472:
#line 6162 "parser.y" /* yacc.c:1646  */
    {
	        (yyval.str) = (yyvsp[0].str);
	      }
#line 10915 "y.tab.c" /* yacc.c:1646  */
    break;

  case 473:
#line 6165 "parser.y" /* yacc.c:1646  */
    {
	        (yyval.str) = 0;
	      }
#line 10923 "y.tab.c" /* yacc.c:1646  */
    break;

  case 474:
#line 6170 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.bases) = (yyvsp[0].bases);
               }
#line 10931 "y.tab.c" /* yacc.c:1646  */
    break;

  case 475:
#line 6175 "parser.y" /* yacc.c:1646  */
    { inherit_list = 1; }
#line 10937 "y.tab.c" /* yacc.c:1646  */
    break;

  case 476:
#line 6175 "parser.y" /* yacc.c:1646  */
    { (yyval.bases) = (yyvsp[0].bases); inherit_list = 0; }
#line 10943 "y.tab.c" /* yacc.c:1646  */
    break;

  case 477:
#line 6176 "parser.y" /* yacc.c:1646  */
    { (yyval.bases) = 0; }
#line 10949 "y.tab.c" /* yacc.c:1646  */
    break;

  case 478:
#line 6179 "parser.y" /* yacc.c:1646  */
    {
		   Hash *list = NewHash();
		   Node *base = (yyvsp[0].node);
		   Node *name = Getattr(base,"name");
		   List *lpublic = NewList();
		   List *lprotected = NewList();
		   List *lprivate = NewList();
		   Setattr(list,"public",lpublic);
		   Setattr(list,"protected",lprotected);
		   Setattr(list,"private",lprivate);
		   Delete(lpublic);
		   Delete(lprotected);
		   Delete(lprivate);
		   Append(Getattr(list,Getattr(base,"access")),name);
	           (yyval.bases) = list;
               }
#line 10970 "y.tab.c" /* yacc.c:1646  */
    break;

  case 479:
#line 6196 "parser.y" /* yacc.c:1646  */
    {
		   Hash *list = (yyvsp[-2].bases);
		   Node *base = (yyvsp[0].node);
		   Node *name = Getattr(base,"name");
		   Append(Getattr(list,Getattr(base,"access")),name);
                   (yyval.bases) = list;
               }
#line 10982 "y.tab.c" /* yacc.c:1646  */
    break;

  case 480:
#line 6205 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.intvalue) = cparse_line;
	       }
#line 10990 "y.tab.c" /* yacc.c:1646  */
    break;

  case 481:
#line 6207 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = NewHash();
		 Setfile((yyval.node),cparse_file);
		 Setline((yyval.node),(yyvsp[-2].intvalue));
		 Setattr((yyval.node),"name",(yyvsp[-1].str));
		 Setfile((yyvsp[-1].str),cparse_file);
		 Setline((yyvsp[-1].str),(yyvsp[-2].intvalue));
                 if (last_cpptype && (Strcmp(last_cpptype,"struct") != 0)) {
		   Setattr((yyval.node),"access","private");
		   Swig_warning(WARN_PARSE_NO_ACCESS, Getfile((yyval.node)), Getline((yyval.node)), "No access specifier given for base class '%s' (ignored).\n", SwigType_namestr((yyvsp[-1].str)));
                 } else {
		   Setattr((yyval.node),"access","public");
		 }
		 if ((yyvsp[0].str))
		   SetFlag((yyval.node), "variadic");
               }
#line 11011 "y.tab.c" /* yacc.c:1646  */
    break;

  case 482:
#line 6223 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.intvalue) = cparse_line;
	       }
#line 11019 "y.tab.c" /* yacc.c:1646  */
    break;

  case 483:
#line 6225 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = NewHash();
		 Setfile((yyval.node),cparse_file);
		 Setline((yyval.node),(yyvsp[-3].intvalue));
		 Setattr((yyval.node),"name",(yyvsp[-1].str));
		 Setfile((yyvsp[-1].str),cparse_file);
		 Setline((yyvsp[-1].str),(yyvsp[-3].intvalue));
		 Setattr((yyval.node),"access",(yyvsp[-4].id));
	         if (Strcmp((yyvsp[-4].id),"public") != 0) {
		   Swig_warning(WARN_PARSE_PRIVATE_INHERIT, Getfile((yyval.node)), Getline((yyval.node)), "%s inheritance from base '%s' (ignored).\n", (yyvsp[-4].id), SwigType_namestr((yyvsp[-1].str)));
		 }
		 if ((yyvsp[0].str))
		   SetFlag((yyval.node), "variadic");
               }
#line 11038 "y.tab.c" /* yacc.c:1646  */
    break;

  case 484:
#line 6241 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (char*)"public"; }
#line 11044 "y.tab.c" /* yacc.c:1646  */
    break;

  case 485:
#line 6242 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (char*)"private"; }
#line 11050 "y.tab.c" /* yacc.c:1646  */
    break;

  case 486:
#line 6243 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (char*)"protected"; }
#line 11056 "y.tab.c" /* yacc.c:1646  */
    break;

  case 487:
#line 6247 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.id) = (char*)"class"; 
		   if (!inherit_list) last_cpptype = (yyval.id);
               }
#line 11065 "y.tab.c" /* yacc.c:1646  */
    break;

  case 488:
#line 6251 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.id) = (char *)"typename"; 
		   if (!inherit_list) last_cpptype = (yyval.id);
               }
#line 11074 "y.tab.c" /* yacc.c:1646  */
    break;

  case 489:
#line 6255 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.id) = (char *)"class..."; 
		   if (!inherit_list) last_cpptype = (yyval.id);
               }
#line 11083 "y.tab.c" /* yacc.c:1646  */
    break;

  case 490:
#line 6259 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.id) = (char *)"typename..."; 
		   if (!inherit_list) last_cpptype = (yyval.id);
               }
#line 11092 "y.tab.c" /* yacc.c:1646  */
    break;

  case 491:
#line 6265 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.id) = (yyvsp[0].id);
               }
#line 11100 "y.tab.c" /* yacc.c:1646  */
    break;

  case 492:
#line 6268 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.id) = (char*)"struct"; 
		   if (!inherit_list) last_cpptype = (yyval.id);
               }
#line 11109 "y.tab.c" /* yacc.c:1646  */
    break;

  case 493:
#line 6272 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.id) = (char*)"union"; 
		   if (!inherit_list) last_cpptype = (yyval.id);
               }
#line 11118 "y.tab.c" /* yacc.c:1646  */
    break;

  case 496:
#line 6282 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = 0;
	       }
#line 11126 "y.tab.c" /* yacc.c:1646  */
    break;

  case 497:
#line 6285 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = 0;
	       }
#line 11134 "y.tab.c" /* yacc.c:1646  */
    break;

  case 498:
#line 6288 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = 0;
	       }
#line 11142 "y.tab.c" /* yacc.c:1646  */
    break;

  case 499:
#line 6291 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = 0;
	       }
#line 11150 "y.tab.c" /* yacc.c:1646  */
    break;

  case 500:
#line 6296 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.dtype).throws = (yyvsp[-1].pl);
                    (yyval.dtype).throwf = NewString("1");
                    (yyval.dtype).nexcept = 0;
	       }
#line 11160 "y.tab.c" /* yacc.c:1646  */
    break;

  case 501:
#line 6301 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.dtype).throws = 0;
                    (yyval.dtype).throwf = 0;
                    (yyval.dtype).nexcept = NewString("true");
	       }
#line 11170 "y.tab.c" /* yacc.c:1646  */
    break;

  case 502:
#line 6306 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.dtype).throws = 0;
                    (yyval.dtype).throwf = 0;
                    (yyval.dtype).nexcept = 0;
	       }
#line 11180 "y.tab.c" /* yacc.c:1646  */
    break;

  case 503:
#line 6311 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.dtype).throws = 0;
                    (yyval.dtype).throwf = 0;
                    (yyval.dtype).nexcept = NewString("true");
	       }
#line 11190 "y.tab.c" /* yacc.c:1646  */
    break;

  case 504:
#line 6316 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.dtype).throws = 0;
                    (yyval.dtype).throwf = 0;
                    (yyval.dtype).nexcept = (yyvsp[-1].dtype).val;
	       }
#line 11200 "y.tab.c" /* yacc.c:1646  */
    break;

  case 505:
#line 6323 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.dtype).throws = 0;
                    (yyval.dtype).throwf = 0;
                    (yyval.dtype).nexcept = 0;
                    (yyval.dtype).qualifier = (yyvsp[0].str);
               }
#line 11211 "y.tab.c" /* yacc.c:1646  */
    break;

  case 506:
#line 6329 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.dtype) = (yyvsp[0].dtype);
                    (yyval.dtype).qualifier = 0;
               }
#line 11220 "y.tab.c" /* yacc.c:1646  */
    break;

  case 507:
#line 6333 "parser.y" /* yacc.c:1646  */
    {
		    (yyval.dtype) = (yyvsp[0].dtype);
                    (yyval.dtype).qualifier = (yyvsp[-1].str);
               }
#line 11229 "y.tab.c" /* yacc.c:1646  */
    break;

  case 508:
#line 6337 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.dtype).throws = 0;
                    (yyval.dtype).throwf = 0;
                    (yyval.dtype).nexcept = 0;
                    (yyval.dtype).qualifier = 0; 
               }
#line 11240 "y.tab.c" /* yacc.c:1646  */
    break;

  case 509:
#line 6345 "parser.y" /* yacc.c:1646  */
    { 
                    Clear(scanner_ccode); 
                    (yyval.decl).have_parms = 0; 
                    (yyval.decl).defarg = 0; 
		    (yyval.decl).throws = (yyvsp[-2].dtype).throws;
		    (yyval.decl).throwf = (yyvsp[-2].dtype).throwf;
		    (yyval.decl).nexcept = (yyvsp[-2].dtype).nexcept;
               }
#line 11253 "y.tab.c" /* yacc.c:1646  */
    break;

  case 510:
#line 6353 "parser.y" /* yacc.c:1646  */
    { 
                    skip_balanced('{','}'); 
                    (yyval.decl).have_parms = 0; 
                    (yyval.decl).defarg = 0; 
                    (yyval.decl).throws = (yyvsp[-2].dtype).throws;
                    (yyval.decl).throwf = (yyvsp[-2].dtype).throwf;
                    (yyval.decl).nexcept = (yyvsp[-2].dtype).nexcept;
               }
#line 11266 "y.tab.c" /* yacc.c:1646  */
    break;

  case 511:
#line 6361 "parser.y" /* yacc.c:1646  */
    { 
                    Clear(scanner_ccode); 
                    (yyval.decl).parms = (yyvsp[-2].pl); 
                    (yyval.decl).have_parms = 1; 
                    (yyval.decl).defarg = 0; 
		    (yyval.decl).throws = 0;
		    (yyval.decl).throwf = 0;
		    (yyval.decl).nexcept = 0;
               }
#line 11280 "y.tab.c" /* yacc.c:1646  */
    break;

  case 512:
#line 6370 "parser.y" /* yacc.c:1646  */
    {
                    skip_balanced('{','}'); 
                    (yyval.decl).parms = (yyvsp[-2].pl); 
                    (yyval.decl).have_parms = 1; 
                    (yyval.decl).defarg = 0; 
                    (yyval.decl).throws = 0;
                    (yyval.decl).throwf = 0;
                    (yyval.decl).nexcept = 0;
               }
#line 11294 "y.tab.c" /* yacc.c:1646  */
    break;

  case 513:
#line 6379 "parser.y" /* yacc.c:1646  */
    { 
                    (yyval.decl).have_parms = 0; 
                    (yyval.decl).defarg = (yyvsp[-1].dtype).val; 
                    (yyval.decl).throws = 0;
                    (yyval.decl).throwf = 0;
                    (yyval.decl).nexcept = 0;
               }
#line 11306 "y.tab.c" /* yacc.c:1646  */
    break;

  case 514:
#line 6386 "parser.y" /* yacc.c:1646  */
    {
                    (yyval.decl).have_parms = 0;
                    (yyval.decl).defarg = (yyvsp[-1].dtype).val;
                    (yyval.decl).throws = (yyvsp[-3].dtype).throws;
                    (yyval.decl).throwf = (yyvsp[-3].dtype).throwf;
                    (yyval.decl).nexcept = (yyvsp[-3].dtype).nexcept;
               }
#line 11318 "y.tab.c" /* yacc.c:1646  */
    break;

  case 521:
#line 6405 "parser.y" /* yacc.c:1646  */
    {
		  skip_balanced('(',')');
		  Clear(scanner_ccode);
		}
#line 11327 "y.tab.c" /* yacc.c:1646  */
    break;

  case 522:
#line 6417 "parser.y" /* yacc.c:1646  */
    {
		  skip_balanced('{','}');
		  Clear(scanner_ccode);
		}
#line 11336 "y.tab.c" /* yacc.c:1646  */
    break;

  case 523:
#line 6423 "parser.y" /* yacc.c:1646  */
    {
                     String *s = NewStringEmpty();
                     SwigType_add_template(s,(yyvsp[-1].p));
                     (yyval.id) = Char(s);
		     scanner_last_id(1);
                }
#line 11347 "y.tab.c" /* yacc.c:1646  */
    break;

  case 524:
#line 6432 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (yyvsp[0].id); }
#line 11353 "y.tab.c" /* yacc.c:1646  */
    break;

  case 525:
#line 6433 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = Swig_copy_string("override"); }
#line 11359 "y.tab.c" /* yacc.c:1646  */
    break;

  case 526:
#line 6434 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = Swig_copy_string("final"); }
#line 11365 "y.tab.c" /* yacc.c:1646  */
    break;

  case 527:
#line 6437 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (yyvsp[0].id); }
#line 11371 "y.tab.c" /* yacc.c:1646  */
    break;

  case 528:
#line 6438 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = Char((yyvsp[0].dtype).val); }
#line 11377 "y.tab.c" /* yacc.c:1646  */
    break;

  case 529:
#line 6439 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = Char((yyvsp[0].str)); }
#line 11383 "y.tab.c" /* yacc.c:1646  */
    break;

  case 530:
#line 6442 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = (yyvsp[0].id); }
#line 11389 "y.tab.c" /* yacc.c:1646  */
    break;

  case 531:
#line 6443 "parser.y" /* yacc.c:1646  */
    { (yyval.id) = 0; }
#line 11395 "y.tab.c" /* yacc.c:1646  */
    break;

  case 532:
#line 6446 "parser.y" /* yacc.c:1646  */
    { 
                  (yyval.str) = 0;
		  if (!(yyval.str)) (yyval.str) = NewStringf("%s%s", (yyvsp[-1].str),(yyvsp[0].str));
      	          Delete((yyvsp[0].str));
               }
#line 11405 "y.tab.c" /* yacc.c:1646  */
    break;

  case 533:
#line 6451 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewStringf("::%s%s",(yyvsp[-1].str),(yyvsp[0].str));
                 Delete((yyvsp[0].str));
               }
#line 11414 "y.tab.c" /* yacc.c:1646  */
    break;

  case 534:
#line 6455 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewString((yyvsp[0].str));
   	       }
#line 11422 "y.tab.c" /* yacc.c:1646  */
    break;

  case 535:
#line 6458 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewStringf("::%s",(yyvsp[0].str));
               }
#line 11430 "y.tab.c" /* yacc.c:1646  */
    break;

  case 536:
#line 6461 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.str) = NewStringf("%s", (yyvsp[0].str));
	       }
#line 11438 "y.tab.c" /* yacc.c:1646  */
    break;

  case 537:
#line 6464 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.str) = NewStringf("%s%s", (yyvsp[-1].str), (yyvsp[0].id));
	       }
#line 11446 "y.tab.c" /* yacc.c:1646  */
    break;

  case 538:
#line 6467 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.str) = NewStringf("::%s",(yyvsp[0].str));
               }
#line 11454 "y.tab.c" /* yacc.c:1646  */
    break;

  case 539:
#line 6472 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("::%s%s",(yyvsp[-1].str),(yyvsp[0].str));
		   Delete((yyvsp[0].str));
               }
#line 11463 "y.tab.c" /* yacc.c:1646  */
    break;

  case 540:
#line 6476 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("::%s",(yyvsp[0].str));
               }
#line 11471 "y.tab.c" /* yacc.c:1646  */
    break;

  case 541:
#line 6479 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("::%s",(yyvsp[0].str));
               }
#line 11479 "y.tab.c" /* yacc.c:1646  */
    break;

  case 542:
#line 6486 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewStringf("::~%s",(yyvsp[0].str));
               }
#line 11487 "y.tab.c" /* yacc.c:1646  */
    break;

  case 543:
#line 6492 "parser.y" /* yacc.c:1646  */
    {
		(yyval.str) = NewStringf("%s", (yyvsp[0].id));
	      }
#line 11495 "y.tab.c" /* yacc.c:1646  */
    break;

  case 544:
#line 6495 "parser.y" /* yacc.c:1646  */
    {
		(yyval.str) = NewStringf("%s%s", (yyvsp[-1].id), (yyvsp[0].id));
	      }
#line 11503 "y.tab.c" /* yacc.c:1646  */
    break;

  case 545:
#line 6500 "parser.y" /* yacc.c:1646  */
    {
		(yyval.str) = (yyvsp[0].str);
	      }
#line 11511 "y.tab.c" /* yacc.c:1646  */
    break;

  case 546:
#line 6503 "parser.y" /* yacc.c:1646  */
    {
		(yyval.str) = NewStringf("%s%s", (yyvsp[-1].id), (yyvsp[0].id));
	      }
#line 11519 "y.tab.c" /* yacc.c:1646  */
    break;

  case 547:
#line 6509 "parser.y" /* yacc.c:1646  */
    {
                  (yyval.str) = 0;
		  if (!(yyval.str)) (yyval.str) = NewStringf("%s%s", (yyvsp[-1].id),(yyvsp[0].str));
      	          Delete((yyvsp[0].str));
               }
#line 11529 "y.tab.c" /* yacc.c:1646  */
    break;

  case 548:
#line 6514 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewStringf("::%s%s",(yyvsp[-1].id),(yyvsp[0].str));
                 Delete((yyvsp[0].str));
               }
#line 11538 "y.tab.c" /* yacc.c:1646  */
    break;

  case 549:
#line 6518 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewString((yyvsp[0].id));
   	       }
#line 11546 "y.tab.c" /* yacc.c:1646  */
    break;

  case 550:
#line 6521 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewStringf("::%s",(yyvsp[0].id));
               }
#line 11554 "y.tab.c" /* yacc.c:1646  */
    break;

  case 551:
#line 6524 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.str) = NewString((yyvsp[0].str));
	       }
#line 11562 "y.tab.c" /* yacc.c:1646  */
    break;

  case 552:
#line 6527 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.str) = NewStringf("::%s",(yyvsp[0].str));
               }
#line 11570 "y.tab.c" /* yacc.c:1646  */
    break;

  case 553:
#line 6532 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("::%s%s",(yyvsp[-1].id),(yyvsp[0].str));
		   Delete((yyvsp[0].str));
               }
#line 11579 "y.tab.c" /* yacc.c:1646  */
    break;

  case 554:
#line 6536 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("::%s",(yyvsp[0].id));
               }
#line 11587 "y.tab.c" /* yacc.c:1646  */
    break;

  case 555:
#line 6539 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("::%s",(yyvsp[0].str));
               }
#line 11595 "y.tab.c" /* yacc.c:1646  */
    break;

  case 556:
#line 6542 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = NewStringf("::~%s",(yyvsp[0].id));
               }
#line 11603 "y.tab.c" /* yacc.c:1646  */
    break;

  case 557:
#line 6548 "parser.y" /* yacc.c:1646  */
    { 
                   (yyval.str) = NewStringf("%s%s", (yyvsp[-1].str), (yyvsp[0].id));
               }
#line 11611 "y.tab.c" /* yacc.c:1646  */
    break;

  case 558:
#line 6551 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = NewString((yyvsp[0].id));}
#line 11617 "y.tab.c" /* yacc.c:1646  */
    break;

  case 559:
#line 6554 "parser.y" /* yacc.c:1646  */
    {
                   (yyval.str) = NewStringf("%s%s", (yyvsp[-1].str), (yyvsp[0].id));
               }
#line 11625 "y.tab.c" /* yacc.c:1646  */
    break;

  case 560:
#line 6562 "parser.y" /* yacc.c:1646  */
    { (yyval.str) = NewString((yyvsp[0].id));}
#line 11631 "y.tab.c" /* yacc.c:1646  */
    break;

  case 561:
#line 6565 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = (yyvsp[0].str);
               }
#line 11639 "y.tab.c" /* yacc.c:1646  */
    break;

  case 562:
#line 6568 "parser.y" /* yacc.c:1646  */
    {
                  skip_balanced('{','}');
		  (yyval.str) = NewString(scanner_ccode);
               }
#line 11648 "y.tab.c" /* yacc.c:1646  */
    break;

  case 563:
#line 6572 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = (yyvsp[0].str);
              }
#line 11656 "y.tab.c" /* yacc.c:1646  */
    break;

  case 564:
#line 6577 "parser.y" /* yacc.c:1646  */
    {
                  Hash *n;
                  (yyval.node) = NewHash();
                  n = (yyvsp[-1].node);
                  while(n) {
                     String *name, *value;
                     name = Getattr(n,"name");
                     value = Getattr(n,"value");
		     if (!value) value = (String *) "1";
                     Setattr((yyval.node),name, value);
		     n = nextSibling(n);
		  }
               }
#line 11674 "y.tab.c" /* yacc.c:1646  */
    break;

  case 565:
#line 6590 "parser.y" /* yacc.c:1646  */
    { (yyval.node) = 0; }
#line 11680 "y.tab.c" /* yacc.c:1646  */
    break;

  case 566:
#line 6594 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = NewHash();
		 Setattr((yyval.node),"name",(yyvsp[-2].id));
		 Setattr((yyval.node),"value",(yyvsp[0].str));
               }
#line 11690 "y.tab.c" /* yacc.c:1646  */
    break;

  case 567:
#line 6599 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.node) = NewHash();
		 Setattr((yyval.node),"name",(yyvsp[-4].id));
		 Setattr((yyval.node),"value",(yyvsp[-2].str));
		 set_nextSibling((yyval.node),(yyvsp[0].node));
               }
#line 11701 "y.tab.c" /* yacc.c:1646  */
    break;

  case 568:
#line 6605 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NewHash();
                 Setattr((yyval.node),"name",(yyvsp[0].id));
	       }
#line 11710 "y.tab.c" /* yacc.c:1646  */
    break;

  case 569:
#line 6609 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = NewHash();
                 Setattr((yyval.node),"name",(yyvsp[-2].id));
                 set_nextSibling((yyval.node),(yyvsp[0].node));
               }
#line 11720 "y.tab.c" /* yacc.c:1646  */
    break;

  case 570:
#line 6614 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = (yyvsp[0].node);
		 Setattr((yyval.node),"name",(yyvsp[-2].id));
               }
#line 11729 "y.tab.c" /* yacc.c:1646  */
    break;

  case 571:
#line 6618 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.node) = (yyvsp[-2].node);
		 Setattr((yyval.node),"name",(yyvsp[-4].id));
		 set_nextSibling((yyval.node),(yyvsp[0].node));
               }
#line 11739 "y.tab.c" /* yacc.c:1646  */
    break;

  case 572:
#line 6625 "parser.y" /* yacc.c:1646  */
    {
		 (yyval.str) = (yyvsp[0].str);
               }
#line 11747 "y.tab.c" /* yacc.c:1646  */
    break;

  case 573:
#line 6628 "parser.y" /* yacc.c:1646  */
    {
                 (yyval.str) = Char((yyvsp[0].dtype).val);
               }
#line 11755 "y.tab.c" /* yacc.c:1646  */
    break;


#line 11759 "y.tab.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 6635 "parser.y" /* yacc.c:1906  */


SwigType *Swig_cparse_type(String *s) {
   String *ns;
   ns = NewStringf("%s;",s);
   Seek(ns,0,SEEK_SET);
   scanner_file(ns);
   top = 0;
   scanner_next_token(PARSETYPE);
   yyparse();
   /*   Printf(stdout,"typeparse: '%s' ---> '%s'\n", s, top); */
   return top;
}


Parm *Swig_cparse_parm(String *s) {
   String *ns;
   ns = NewStringf("%s;",s);
   Seek(ns,0,SEEK_SET);
   scanner_file(ns);
   top = 0;
   scanner_next_token(PARSEPARM);
   yyparse();
   /*   Printf(stdout,"typeparse: '%s' ---> '%s'\n", s, top); */
   Delete(ns);
   return top;
}


ParmList *Swig_cparse_parms(String *s, Node *file_line_node) {
   String *ns;
   char *cs = Char(s);
   if (cs && cs[0] != '(') {
     ns = NewStringf("(%s);",s);
   } else {
     ns = NewStringf("%s;",s);
   }
   Setfile(ns, Getfile(file_line_node));
   Setline(ns, Getline(file_line_node));
   Seek(ns,0,SEEK_SET);
   scanner_file(ns);
   top = 0;
   scanner_next_token(PARSEPARMS);
   yyparse();
   /*   Printf(stdout,"typeparse: '%s' ---> '%s'\n", s, top); */
   return top;
}

