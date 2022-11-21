# -*- Mode:makefile-gmake; tab-width:8 -*-

# see below the licence for usage instructions.

# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org>

##############################################
#
#    first, set some variables before including Makefile.inc.
#
# OBJDIR= <subdir, such as "obj">
#    this specifies where all build products will go. it is assumed
#    to be the name of a subdirectory relative to the current directory.
#
# CC, CXX, AR, RANLIB, BISON, FLEX, PROTOC_PATH
#    these variables affect every build target of this makefile.
#    Makefile.inc supplies reasonable defaults for these but you can
#    override them if you need to.
#
# $(target)_{CC,CXX,AR,RANLIB,BISON,FLEX,PROTOC_PATH}
#    if none of these variables exist, the global ones above will be
#    used.  but you can supply per-target customizations of these
#    variables, for instance if you want to use this makefile to
#    compile one target for the host machine's CPU and cross-compile
#    another target for a different architecture.
#    NOTE these values *replace* their global counterparts, if specified.
#
# CFLAGS, CXXFLAGS
#    command line arguments to $(CC) or $(CXX) respectively. applied
#    before $(target)_CFLAGS or $(target)_CXXFLAGS.
#    e.g. if you want assembler listings from your C or CC files, add
#       -Wa,-ahls=$$(@:.o=.L)
#    to CFLAGS, CXXFLAGS, $(target)_CFLAGS, and/or $(target)_CXXFLAGS
#    (assuming your assembler is gnu gas, of course)
#    NOTE these values are specified *in addition to*
#         their target-specific counterparts, with the globals coming
#         first on the compiler command line.
#
# LDFLAGS
#    flags applied to program linker, i.e. -rdynamic.  applied to all
#    targets in PROG_TARGETS, applied before $(target)_LDFLAGS.
#    NOTE these values are specified *in addition to*
#         their target-specific counterparts, with the globals coming
#         first on the linker command line.
#
# INCS, DEFS
#    cpp-type arguments. INCS should be -I's, DEFS should be -D's.
#    NOTE these are global for all LIB and PROG targets! the
#    $(target)_INCS is applied to the command line *before* the global
#    $(INCS) so a header file in the $(target)_INCS with the same file
#    name as a header file from $(INCS) can be found by a specific
#    build target.  on the other hand, $(target)_DEFS is applied
#    *after* the global $(DEFS) so a target can override a global
#    $(DEFS) variable definition.  e.g.  you can set
#    DEFS="-D_FORTIFY_SOURCE" to test functions with the "warn_unused"
#    attribute (on ubuntu at least).
#
# PREPROC_TARGETS
#    if you have files to preprocess before computing dependencies,
#    here's your hook to add target recipes. of course this makefile
#    doesn't do any work for you, you have to write the target
#    recipes. this is invoked after objdirs but before deps.  if
#    you're using this to do "cpp" type operations, it is recommended
#    to include the global $(INCS) and $(DEFS) rules.
#
# POSTALL
#    if you have more recipes you want to run after the "all" rule in
#    this makefile as run (i.e. after all PREPROC, LIB, and PROG) then
#    this is your opportunity to name more recipe rules to invoke.
#
# EXTRA_CLEAN
#    'make clean' will blow away the $(OBJDIR) and dox directories,
#    but if you have more you'd like to clean, make another recipe and
#    add the recipe name(s) to $(EXTRA_CLEAN).
#
# LIB_TARGETS = example somelib someotherlib
# PROG_TARGETS = prog1 phils_prog testprog
#    you MUST tell Makefile.inc what you want to build. you can build
#    libraries, or programs. make a list of target names. put those
#    target names into a variable LIB_TARGETS or PROG_TARGETS (depending
#    on whether each target is a library or program). don't worry about
#    the actual filenames produced yet, these target names are just used
#    for specifying other makefile variable names specific to that target.
#
#    each target name is used as the prefix for another set of
#    variables, e.g.  if you have a library target named "thingy",
#    Makefile.inc will looking for a variable called "thingy_CXXSRCS"
#    to see if that library includes C++ sources.  the list of
#    $(target)_xxx variables you can set is listed below. for this
#    example, we're specifying variables for the "somelib" and "prog1"
#    target examples we specified above.
#
# somelib_TARGET = $(OBJDIR)/libSOMELIB.a    # required
# somelib_CXXSRCS = one_file.cc  another_file.cc
# prog1_TARGET = $(OBJDIR)/program_one       # required
# prog1_CSRCS = a_c_file.c
#
#    the full list variables you can set (replace "$(target)" with
#    the name of the target you want to build):
#
# $(target)_TARGET = <library or executable filename to build, required>
# $(target)_CC = <target-specific compiler, uses $(CC), if not specified>
# $(target)_CXX = <target-specific compiler, uses $(CXX), if not specified>
# $(target)_AR = <t-s archiver, uses $(AR), ins>
# $(target)_RANLIB = <t-s library indexer, uses $(RANLIB), ins>
# $(target)_BISON = <t-s parser generator, uses $(BISON), ins>
# $(target)_FLEX = <t-s lexical scanner, uses $(FLEX), ins>
# $(target)_PROTOC_PATH = <t-s protobuf compiler, uses $(PROTOC_PATH), ins>
# $(target)_CSRCS = <a list of "c" files to pass to $(CC)>
# $(target)_HDRS = <a list of "h" files; only used for cscope>
# $(target)_CXXSRCS = <a list of "cc" files to pass to $(CXX)>
# $(target)_YSRCS = <a list of "y" files to pass to $(BISON)>
# $(target)_LSRCS = <a list of "l" files to pass to $(FLEX)>
# $(target)_YYSRCS = <a list of "yy" files to pass to $(BISON) (C++)>
# $(target)_LLSRCS = <a list of "ll" files to pass to $(FLEX) (C++)>
# $(target)_PROTOSRCS = <a list of "proto" files to pass to $(PROTOC_PATH)>
# $(target)_CFLAGS = <compiler options to $(CC)>
# $(target)_CXXFLAGS = <compiler options to $(CXX)>
# $(target)_INCS = -I/path <a list of include dir directives>
# $(target)_DEFS = -DVAR=VALUE <a list of macro defines>
# $(target)_EXTRAOBJS = <a list of ".o" files built by other recipes>
# $(target)_POSTINSTALL = <a recipe name to run after installing>
# $(target)_PREMAKE = <a recipe name to run before making _TARGET>
# $(target)_POSTMAKE = <a recipe name to run after making _TARGET>
#
# NOTE Makefile.inc provides two make targets 'cscope' and 'cscope.files'
# which are fed by *_CSRCS, *_CXXSRCS, and *_HDRS. They will autogenerate
# a 'cscope.files' list and run 'cscope -bk' based on all the sources
# and headers from all the libraries and programs in your Makefile. NOTE
# if you have conditionals which alter the list of sources and headers
# which are built or alter the LIB_TARGETS or PROG_TARGETS lists, this
# will impact 'cscope.files'; in other words, the cscope database will
# be built ONLY over the source files actually being built.
#
# NOTE if you define $(target)_PROTOSRCS with a list of proto files,
# there will be an autodefined variable produced for each proto source
# of the form  "$(target)_$(proto_filename)_HDR"  which contains the
# path to the autogenerated header file created from that proto file.
#
# example:
#         LIB_TARGETS += testProto
#         testProto_TARGET = $(OBJDIR)/libtestProto.a
#         testProto_PROTOSRCS = test1.proto test2.proto
#
# this will result in the following variables being defined:
#         testProto_test1.proto_HDR = $(OBJDIR)/testProto-test1.pb.h
#         testProto_test2.proto_HDR = $(OBJDIR)/testProto-test2.pb.h
#
# you can see debug $(info) statements which tell you exactly what the
# _HDR variable names are going to look like using this:
#         DEBUG_H_MACRO_GENERATION=y
#
# these macros are then suitable to put in a C file like this:
#         testProto_CXXSRCS = test1.cc
#         testProto_DEFS = -DTEST_PROTO_HDR=\"$(testProto_test1.proto_HDR)\"
#
# and then in the file test1.cc:
#         #include TEST_PROTO_HDR
#
#    LIB_TARGETS can also have:
#
# $(target)_INSTALL_HDRS = <list of header files to be installed>
#
#    PROG_TARGETS can also have:
#
# $(target)_DEPLIBS = $(somelib_TARGET) <a list of _TARGET dependencies>
# $(target)_LIBS = -L/path -lpthread <a list of libraries to link against>
# $(target)_LDFLAGS = -rdynamic <a list of options passed to linker>
# $(target)_INSTALL=1   # only if you want this prog installed
#
#    doxyen targets can define:
#
# $(target)_DOXYFILE = Doxyfile
#
#    now that you have set all these variables, you can include
#    this file.
#
# include /path/to/Makefile.inc
#
#    now, you can specify any additional make recipes you need.
#    NOTE you can't put any make recipes before the include, because
#    you want the "all" target in Makefile.inc to be the first one,
#    the default one run if you type "make" with no args.
#
#    happy hacking!
#
##############################################

# all artifacts produced by this makefile go under
# an objects tree rooted at this directory.
# default: specific to this os and processor.
ifeq ($(OBJDIR),)
# neat bug: if you use OBJDIR = $(shell xxx) then the shell cmd is
#           executed EVERY time $(OBJDIR) is evaluated; on complex
#           targets, this could be hundreds or thousands of invocations
#           of "uname".
#           if you use OBJDIR := $(shell xxx) then the shell cmd is
#           executed only once and the output reused for every $(OBJDIR) ref.
# ugh. cygwin puts slashes and parens in uname -r !!

UNAMER := $(shell uname -r | sed -e 's,/,_,g' -e 's,[(|)],_,g')
OBJDIR := obj.$(shell uname -m).$(shell uname -s).$(UNAMER)
endif

ifeq ($(OBJDIR),$(filter /%,$(OBJDIR)))
# objdir is absolute path.
OBJDIR_FULLPATH := $(OBJDIR)
else
# objdir is relative path.
OBJDIR_FULLPATH := $(PWD)/$(OBJDIR)
endif

# additional subdirs of $(OBJDIR) to create, if your source tree
# has has a tree of relpath "dir/file.c" sources.
OBJDIRS_TOMAKE ?=

# common tools, reasonable defaults.
CC ?= gcc
CXX ?= g++
AR ?= ar
RANLIB ?= ranlib
BISON ?= bison
FLEX ?= flex

# on platforms that have protoc as a managed package,
# it is in one of three places.
POSSIBLE_PROTOC_PATHS = /bin/protoc /usr/bin/protoc /usr/local/bin/protoc
PROTOC_PATH ?= $(firstword $(wildcard $(POSSIBLE_PROTOC_PATHS)))

# cflags and cxxflags should not include defines or includes;
# this should be options to the compiler like optimization, debug,
# pedantics, warnflags, and the like (i.e. stuff that only cc1 or cc1plus
# would consume, but not stuff cpp would consume).
ifeq ($(DBG),1)
CFLAGS  += -O0 -g3
CXXFLAGS += -O0 -g3
OBJDIR := $(OBJDIR).dbg
else
CFLAGS ?= -O2
CXXFLAGS ?= -O2
endif

LDFLAGS ?= 
INCS ?=
DEFS ?=
PREPROC_TARGETS ?=
LIB_TARGETS ?=
PROG_TARGETS ?=
DOXYGEN_TARGETS ?=
POSTALL ?= 
EXTRA_CLEAN ?=
CONFIG_TXT ?= $(OBJDIR)/config.txt

ifeq ($(VERBOSE),1)
Q=
else
Q=@
endif
export VERBOSE

all:
	$(Q)+make objdirs echoconfig preprocs protobufs
	$(Q)make deps
	$(Q)+make $(MAKEJOBS) __INCLUDE_DEPS=1 _all

include $(INCLUDE_MAKEFILES)

echoconfig:
	@echo CONFIG=$(CONFIG) > $(CONFIG_TXT)
	@echo PFKARCH=$(PFKARCH) >> $(CONFIG_TXT)
	@echo OBJDIR=$(OBJDIR) >> $(CONFIG_TXT)
	@echo PREPROC_TARGETS=$(PREPROC_TARGETS) >> $(CONFIG_TXT)
	@echo LIB_TARGETS=$(LIB_TARGETS) >> $(CONFIG_TXT)
	@echo PROG_TARGETS=$(PROG_TARGETS) >> $(CONFIG_TXT)
	@echo MAKEJOBS=$(MAKEJOBS) >> $(CONFIG_TXT)
	@echo PROTOC_PATH=$(PROTOC_PATH) >> $(CONFIG_TXT)
	@echo PROTOBUF_INC=$(PROTOBUF_INC) >> $(CONFIG_TXT)
	@echo PROTOBUF_LIB=$(PROTOBUF_LIB) >> $(CONFIG_TXT)
	@echo MBEDTLS_INCS=$(MBEDTLS_INCS) >> $(CONFIG_TXT)
	@echo MBEDTLS_LIBS=$(MBEDTLS_LIBS) >> $(CONFIG_TXT)
	@echo CC=$(CC) >> $(CONFIG_TXT)
	@echo CXX=$(CXX) >> $(CONFIG_TXT)
	@echo AR=$(AR) >> $(CONFIG_TXT)
	@echo RANLIB=$(RANLIB) >> $(CONFIG_TXT)
	@echo BISON=$(BISON) >> $(CONFIG_TXT)
	@echo FLEX=$(FLEX) >> $(CONFIG_TXT)
	@echo CFLAGS=$(CFLAGS) >> $(CONFIG_TXT)
	@echo CXXFLAGS=$(CXXFLAGS) >> $(CONFIG_TXT)
	@echo LDFLAGS=$(LDFLAGS) >> $(CONFIG_TXT)
	@echo INCS=$(INCS) >> $(CONFIG_TXT)
	@echo -n DEFS=$(DEFS) >> $(CONFIG_TXT)
	@echo -n -e $(CUSTOM_TOOLS) >> $(CONFIG_TXT)
	@echo -n -e $(CUSTOM_INCS) >> $(CONFIG_TXT)
	@echo -n -e $(CUSTOM_DEFS) >> $(CONFIG_TXT)
	@echo -n -e $(CUSTOM_CFLAGS) >> $(CONFIG_TXT)
	@echo  -e $(CUSTOM_CXXFLAGS) >> $(CONFIG_TXT)
	@echo TARGETS=$(LIB_TARGETS) $(PROG_TARGETS)
	@echo recording configuration in $(CONFIG_TXT)

objdirs:
	$(Q)mkdir -p $(OBJDIR) $(foreach d,$(OBJDIRS_TOMAKE),$(OBJDIR)/$(d))

##############################################

# $(call FROM_X_TO_Y,cc,o,dirA/dirB/file.cc) == objdir/target-dirA_dirB_file.o

FROM_X_TO_Y = $(patsubst %.$(1), $(OBJDIR_FULLPATH)/$(target)-%.$(2), $(subst /,_,$(3)))

FROM_C_TO_O      = $(call FROM_X_TO_Y,c,o,$(1))
FROM_C_TO_D      = $(call FROM_X_TO_Y,c,c.d,$(1))
FROM_CC_TO_O     = $(call FROM_X_TO_Y,cc,o,$(1))
FROM_CC_TO_D     = $(call FROM_X_TO_Y,cc,cc.d,$(1))
FROM_Y_TO_C      = $(call FROM_X_TO_Y,y,c,$(1))
FROM_Y_TO_H      = $(call FROM_X_TO_Y,y,h,$(1))
FROM_Y_TO_D      = $(call FROM_X_TO_Y,y,c.d,$(1))
FROM_Y_TO_O      = $(call FROM_X_TO_Y,y,o,$(1))
FROM_YY_TO_CC    = $(call FROM_X_TO_Y,yy,cc,$(1))
FROM_YY_TO_HH    = $(call FROM_X_TO_Y,yy,hh,$(1))
FROM_YY_TO_D     = $(call FROM_X_TO_Y,yy,cc.d,$(1))
FROM_YY_TO_O     = $(call FROM_X_TO_Y,yy,o,$(1))
FROM_L_TO_C      = $(call FROM_X_TO_Y,l,c,$(1))
FROM_L_TO_D      = $(call FROM_X_TO_Y,l,c.d,$(1))
FROM_L_TO_O      = $(call FROM_X_TO_Y,l,o,$(1))
FROM_LL_TO_CC    = $(call FROM_X_TO_Y,ll,cc,$(1))
FROM_LL_TO_D     = $(call FROM_X_TO_Y,ll,cc.d,$(1))
FROM_LL_TO_O     = $(call FROM_X_TO_Y,ll,o,$(1))
FROM_PROTO_TO_CC = $(call FROM_X_TO_Y,proto,pb.cc,$(1))
FROM_PROTO_TO_H  = $(call FROM_X_TO_Y,proto,pb.h,$(1))
FROM_PROTO_TO_D  = $(call FROM_X_TO_Y,proto,pb.cc.d,$(1))
FROM_PROTO_TO_O  = $(call FROM_X_TO_Y,proto,pb.o,$(1))

define TARGET_VARS

$(target)_COBJS        = $(call FROM_C_TO_O,$($(target)_CSRCS))
$(target)_CDEPS        = $(call FROM_C_TO_D,$($(target)_CSRCS))
$(target)_CXXOBJS      = $(call FROM_CC_TO_O,$($(target)_CXXSRCS))
$(target)_CXXDEPS      = $(call FROM_CC_TO_D,$($(target)_CXXSRCS))
$(target)_YGENSRCS     = $(call FROM_Y_TO_C,$($(target)_YSRCS))
$(target)_YGENDEPS     = $(call FROM_Y_TO_D,$($(target)_YSRCS))
$(target)_YGENOBJS     = $(call FROM_Y_TO_O,$($(target)_YSRCS))
$(target)_LGENSRCS     = $(call FROM_L_TO_C,$($(target)_LSRCS))
$(target)_LGENDEPS     = $(call FROM_L_TO_D,$($(target)_LSRCS))
$(target)_LGENOBJS     = $(call FROM_L_TO_O,$($(target)_LSRCS))
$(target)_YYGENSRCS    = $(call FROM_YY_TO_CC,$($(target)_YYSRCS))
$(target)_YYGENDEPS    = $(call FROM_YY_TO_D,$($(target)_YYSRCS))
$(target)_YYGENOBJS    = $(call FROM_YY_TO_O,$($(target)_YYSRCS))
$(target)_LLGENSRCS    = $(call FROM_LL_TO_CC,$($(target)_LLSRCS))
$(target)_LLGENDEPS    = $(call FROM_LL_TO_D,$($(target)_LLSRCS))
$(target)_LLGENOBJS    = $(call FROM_LL_TO_O,$($(target)_LLSRCS))
$(target)_PROTOGENSRCS = $(call FROM_PROTO_TO_CC,$($(target)_PROTOSRCS))
$(target)_PROTOGENHDRS = $(call FROM_PROTO_TO_H,$($(target)_PROTOSRCS))
$(target)_PROTOGENDEPS = $(call FROM_PROTO_TO_D,$($(target)_PROTOSRCS))
$(target)_PROTOGENOBJS = $(call FROM_PROTO_TO_O,$($(target)_PROTOSRCS))

$(foreach src,$($(target)_YSRCS),
$(target)_$(src)_HDR := $(notdir $(call FROM_Y_TO_H, $(src)))
)

$(foreach src,$($(target)_YYSRCS),
$(target)_$(src)_HDR := $(notdir $(call FROM_YY_TO_HH, $(src)))
)

$(foreach src,$($(target)_PROTOSRCS),
$(target)_$(src)_HDR := $(notdir $(call FROM_PROTO_TO_H, $(src))))

endef

$(eval $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS),$(TARGET_VARS)))

ifeq ($(DEBUG_H_MACRO_GENERATION),y)

define DEBUG_TARGET_VARS
$(foreach src,$($(target)_YSRCS),
$(info $(src) --> $(target)_$(src)_HDR = $(notdir $(call FROM_Y_TO_H, $(src))))
)

$(foreach src,$($(target)_YYSRCS),
$(info $(src) --> $(target)_$(src)_HDR := $(notdir $(call FROM_YY_TO_HH, $(src))))
)

$(foreach src,$($(target)_PROTOSRCS),
$(info $(src) --> $(target)_$(src)_HDR = $(notdir $(call FROM_PROTO_TO_H, $(src))))
)

endef

$(eval $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS),$(DEBUG_TARGET_VARS)))

endif


##############################################

define TARGET_RULES
$($(target)_LLGENSRCS): $($(target)_YYGENSRCS)
$($(target)_LLGENSRCS): $($(target)_LLSRCS)
$($(target)_YYGENSRCS): $($(target)_YYSRCS)

$($(target)_LGENSRCS): $($(target)_YGENSRCS)
$($(target)_LGENSRCS): $($(target)_LSRCS)
$($(target)_YGENSRCS): $($(target)_YSRCS)

CGENSRCS += $($(target)_YGENSRCS) $($(target)_LGENSRCS)
CXXGENSRCS += $($(target)_YYGENSRCS) $($(target)_LLGENSRCS) \
		$($(target)_PROTOGENSRCS)

CDEPS += $($(target)_CDEPS)
CXXDEPS += $($(target)_CXXDEPS)

CGENDEPS += $($(target)_YGENDEPS) $($(target)_LGENDEPS)
CXXGENDEPS += $($(target)_YYGENDEPS) $($(target)_LLGENDEPS) \
		$($(target)_PROTOGENDEPS)

# for cscope
HDRS += $($(target)_HDRS)
CSRCS += $($(target)_CSRCS) $($(target)_YGENSRCS) $($(target)_LGENSRCS)
CXXSRCS += $($(target)_CXXSRCS) $($(target)_YYGENSRCS) $($(target)_LLGENSRCS)

# the 'echoconfig' target uses 'echo -e' so we can use command sequences
# like "\n" to make newlines.
$(if $(subst undefined,,$(origin $(target)_CC)),
  $(eval CUSTOM_TOOLS += \\n$(target)_CC=$($(target)_CC)))
$(if $(subst undefined,,$(origin $(target)_CXX)),
  $(eval CUSTOM_TOOLS += \\n$(target)_CXX=$($(target)_CXX)))
$(if $(subst undefined,,$(origin $(target)_AR)),
  $(eval CUSTOM_TOOLS += \\n$(target)_AR=$($(target)_AR)))
$(if $(subst undefined,,$(origin $(target)_RANLIB)),
  $(eval CUSTOM_TOOLS += \\n$(target)_RANLIB=$($(target)_RANLIB)))
$(if $(subst undefined,,$(origin $(target)_BISON)),
  $(eval CUSTOM_TOOLS += \\n$(target)_BISON=$($(target)_BISON)))
$(if $(subst undefined,,$(origin $(target)_FLEX)),
  $(eval CUSTOM_TOOLS += \\n$(target)_FLEX=$($(target)_FLEX)))
$(if $(subst undefined,,$(origin $(target)_PROTOC_PATH)),
  $(eval CUSTOM_TOOLS += \\n$(target)_PROTOC_PATH=$($(target)_PROTOC_PATH)))
$(if $(subst undefined,,$(origin $(target)_INCS)),
  $(eval CUSTOM_INCS += \\n$(target)_INCS=\"$($(target)_INCS)\"))
$(if $(subst undefined,,$(origin $(target)_DEFS)),
  $(eval CUSTOM_DEFS += \\n$(target)_DEFS=\"$($(target)_DEFS)\"))
$(if $(subst undefined,,$(origin $(target)_CFLAGS)),
  $(eval CUSTOM_CFLAGS += \\n$(target)_CFLAGS=\"$($(target)_CFLAGS)\"))
$(if $(subst undefined,,$(origin $(target)_CXXFLAGS)),
  $(eval CUSTOM_CXXFLAGS += \\n$(target)_CXXFLAGS=\"$($(target)_CXXFLAGS)\"))

$(eval $(target)_CC ?= $(CC))
$(eval $(target)_CXX ?= $(CXX))
$(eval $(target)_AR ?= $(AR))
$(eval $(target)_RANLIB ?= $(RANLIB))
$(eval $(target)_BISON ?= $(BISON))
$(eval $(target)_FLEX ?= $(FLEX))
$(eval $(target)_PROTOC_PATH ?= $(PROTOC_PATH))

# handle C files

$(foreach src,$($(target)_CSRCS),$(call FROM_C_TO_O, $(src)): $(src)
	@echo compiling $$<
	$(Q)$($(target)_CC) -c -I$(OBJDIR) $(CFLAGS) $($(target)_CFLAGS) \
		$($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) $$< -o $$@
)

$(foreach src,$($(target)_CSRCS),$(call FROM_C_TO_D, $(src)): $(src)
	@echo depending $$<
	$(Q)$($(target)_CC) -I$(OBJDIR) $($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_C_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

# handle CC files

$(foreach src,$($(target)_CXXSRCS),$(call FROM_CC_TO_O, $(src)): $(src)
	@echo compiling $$<
	$(Q)$($(target)_CXX) -c -I$(OBJDIR) $(CXXFLAGS) $($(target)_CXXFLAGS) \
		$($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) \
		$$< -o $$@
)


$(foreach src,$($(target)_CXXSRCS),$(call FROM_CC_TO_D, $(src)): $(src)
	@echo depending $$<
	$(Q)$($(target)_CXX) -I$(OBJDIR) $($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_CC_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

# handle Y files

$(foreach src,$($(target)_YSRCS),$(call FROM_Y_TO_O, $(src)): $(call FROM_Y_TO_C, $(src))
	@echo compiling $$<
	$(Q)$($(target)_CC) -c -I$(OBJDIR) $(CFLAGS) $($(target)_CFLAGS) \
		$($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) \
		$$< -o $$@
)

$(foreach src,$($(target)_YSRCS),$(call FROM_Y_TO_C, $(src)) $(call FROM_Y_TO_H, $(src)): $(src)
	@echo making $$@
	$(Q)$($(target)_BISON) -d $$< -o $$@
)

$(foreach src,$($(target)_YSRCS),$(call FROM_Y_TO_D, $(src)): $(call FROM_Y_TO_C, $(src)) $(call FROM_Y_TO_H, $(src))
	@echo depending $$<
	$(Q)$($(target)_CC) -I$(OBJDIR) $($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_Y_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

# handle YY files

$(foreach src,$($(target)_YYSRCS),$(call FROM_YY_TO_CC, $(src)) $(call FROM_YY_TO_HH, $(src)): $(src)
	@echo making $$@
	$(Q)$($(target)_BISON) -d $$< -o $$@
)

$(foreach src,$($(target)_YYSRCS),$(call FROM_YY_TO_D, $(src)): $(call FROM_YY_TO_CC, $(src))
	@echo depending $$<
	$(Q)$($(target)_CXX) -I$(OBJDIR) $($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_YY_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

$(foreach src,$($(target)_YYSRCS),$(call FROM_YY_TO_O, $(src)): $(call FROM_YY_TO_CC, $(src)) $(call FROM_YY_TO_HH, $(src))
	@echo compiling $$<
	$(Q)$($(target)_CXX) -c -I$(OBJDIR) $(CXXFLAGS) $($(target)_CXXFLAGS) \
		$($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) $$< -o $$@
)

# handle L files

$(foreach src,$($(target)_LSRCS),$(call FROM_L_TO_C, $(src)): $(src)
	@echo making $$@
	$(Q)$($(target)_FLEX) --stdout $$<  > $$@
)

$(foreach src,$($(target)_LSRCS),$(call FROM_L_TO_D, $(src)): $(call FROM_L_TO_C, $(src))
	@echo depending $$<
	$(Q)$($(target)_CXX) -I$(OBJDIR) $($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_L_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

$(foreach src,$($(target)_LSRCS),$(call FROM_L_TO_O, $(src)): $(call FROM_L_TO_C, $(src))
	@echo compiling $$<
	$(Q)$($(target)_CC) -c -I$(OBJDIR) $(CFLAGS) $($(target)_CFLAGS) \
		$($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) \
		$$< -o $$@
)

# handle LL files

$(foreach src,$($(target)_LLSRCS),$(call FROM_LL_TO_CC, $(src)): $(src)
	@echo making $$@
	$(Q)$($(target)_FLEX) --stdout $$<  > $$@
)

$(foreach src,$($(target)_LLSRCS),$(call FROM_LL_TO_O, $(src)): $(call FROM_LL_TO_CC, $(src))
	@echo compiling $$<
	$(Q)$($(target)_CXX) -c -I$(OBJDIR) $(CXXFLAGS) $($(target)_CXXFLAGS) \
		$($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) $$< -o $$@
)

$(foreach src,$($(target)_LLSRCS),$(call FROM_LL_TO_D, $(src)): $(call FROM_LL_TO_CC, $(src))
	@echo depending $$<
	$(Q)$($(target)_CXX) -I$(OBJDIR) $($(target)_INCS) $(INCS) \
		$(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_LL_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

# handle PROTO files

# note that protoc turns file.proto into file.pb.h and file.pb.cc,
# but we really want obj/$(target)-directory_directory_file.pb.cc and .h
# but also note protoc spits out the .pb.cc file with a #include looking for file.pb.h,
# so we use a sed-expression to replace that with $(target)-dir_dir_file_pb.h

$(foreach src,$($(target)_PROTOSRCS),

$(call FROM_PROTO_TO_CC, $(src)): $(src)
	@echo making $$@
	$(Q)cd $$(dir $$<) && $($(target)_PROTOC_PATH) \
		--cpp_out=$$(dir $$@) $$(notdir $$<)
	$(Q)mv $(OBJDIR)/$$(notdir $(src:.proto=.pb.h)) $$(@:.pb.cc=.pb.h)
	$(Q)sed -e s,$$(notdir $(src:.proto=.pb.h)),$$(notdir $$(@:.pb.cc=.pb.h)), \
		<  $(OBJDIR)/$$(notdir $(src:.proto=.pb.cc)) \
		> $$(@).TEMP
	$(Q)mv $$(@).TEMP $$(@)
)

$(foreach src,$($(target)_PROTOSRCS),$(call FROM_PROTO_TO_O, $(src)): $(call FROM_PROTO_TO_CC, $(src))
	@echo compiling $$<
	$(Q)$($(target)_CXX) -c -I$(OBJDIR) $(CXXFLAGS) $($(target)_CXXFLAGS) \
		$($(target)_INCS) $(PROTOBUF_INC) \
		$(INCS) $(DEFS) $($(target)_DEFS) $$< -o $$@
)

$(foreach src,$($(target)_PROTOSRCS),$(call FROM_PROTO_TO_D, $(src)): $(call FROM_PROTO_TO_CC, $(src))
	@echo depending $$<
	$(Q)$($(target)_CXX) -I$(OBJDIR) $($(target)_INCS) $(PROTOBUF_INC) \
		$(INCS) $(DEFS) $($(target)_DEFS) -DDEPENDING=1 \
		-M $$< -MT $(call FROM_PROTO_TO_O,$(src)) -MF $$@.tmp
	$(Q)mv $$@.tmp $$@
)

# here for reference
#$($(target)_PROTOGENSRCS): $(OBJDIR)/%.pb.cc : %.proto
#	@echo making $$@
#	@cd $$(dir $$<) && $($(target)_PROTOC_PATH) \
#		--cpp_out=$$(dir $(PWD)/$$@) $$(notdir $$<)

endef

define TARGET_OBJ_LIST

$(target)_OBJS = \
	$($(target)_COBJS)        $($(target)_CXXOBJS) \
	$($(target)_YGENOBJS)     $($(target)_LGENOBJS) \
	$($(target)_YYGENOBJS)    $($(target)_LLGENOBJS) \
	$($(target)_PROTOGENOBJS) $($(target)_EXTRAOBJS)

endef

define LIB_TARGET_RULES

$($(target)_TARGET): $($(target)_OBJS)
	@echo linking $($(target)_TARGET)
	$(Q)rm -f $($(target)_TARGET)
	$(Q)$($(target)_AR) cq $($(target)_TARGET) $($(target)_OBJS)
	$(Q)$($(target)_RANLIB) $($(target)_TARGET)

$(target)_install: $($(target)_TARGET)
	$(Q)set -e ; if [ "x$($(target)_INSTALL_HDRS)" != "x" ] ; then \
		echo installing $($(target)_TARGET) and headers ; \
		cp $($(target)_TARGET) $(INSTALL_LIB_DIR) ; \
		tar cf - $($(target)_INSTALL_HDRS) | \
			tar -C $(INSTALL_INC_DIR) -xf - ; \
	fi

endef

define PROG_TARGET_RULES

$($(target)_TARGET): $($(target)_OBJS) $($(target)_DEPLIBS)
	@echo linking $($(target)_TARGET)
	$(Q)$($(target)_CXX) -o $($(target)_TARGET) $($(target)_OBJS) \
		$($(target)_DEPLIBS) \
		$(LDFLAGS) $($(target)_LDFLAGS) \
		$($(target)_LIBS)

$(target)_install: $($(target)_TARGET)
	$(Q)set -e ; if [ "x$($(target)_INSTALL)" = "x1" ] ; then \
		echo installing $($(target)_TARGET) ; \
		FNAME="$(notdir $($(target)_TARGET))" ; \
		if [ -f $(INSTALL_BIN_DIR)/$$$$FNAME ] ; then \
			mv -f $(INSTALL_BIN_DIR)/$$$$FNAME \
				$(INSTALL_BIN_DIR)/$$$$FNAME.old ;\
		fi ; \
		cp $($(target)_TARGET) $(INSTALL_BIN_DIR)/$$$$FNAME ; \
	fi

endef

PROTOGENSRCS := $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS), \
	$($(target)_PROTOGENSRCS))

$(eval $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS),$(TARGET_OBJ_LIST)))
$(eval $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS),$(TARGET_RULES)))
$(eval $(foreach target,$(LIB_TARGETS),$(LIB_TARGET_RULES)))
$(eval $(foreach target,$(PROG_TARGETS),$(PROG_TARGET_RULES)))

ALL_LIB_TARGETS := $(foreach target,$(LIB_TARGETS),$($(target)_TARGET))
ALL_PROG_TARGETS := $(foreach target,$(PROG_TARGETS),$($(target)_TARGET))
ALL_TARGETS := $(ALL_LIB_TARGETS) $(ALL_PROG_TARGETS)

##############################################

define DOXYGEN_TARGET_RULES
$(target)_doxygen:
	$(foreach dox,$($(target)_DOXYFILE),doxygen $(dox) &&) true

$(target)_doxygen-install:
	@echo making $(target)_doxygen-install is not yet supported

endef

$(eval $(foreach target,$(DOXYGEN_TARGETS),$(DOXYGEN_TARGET_RULES)))

##############################################

preprocs: $(PREPROC_TARGETS)

##############################################

protobufs: $(PROTOGENSRCS)

##############################################

deps: $(CGENDEPS) $(CXXGENDEPS) $(CDEPS) $(CXXDEPS)

ifeq ($(__INCLUDE_DEPS),1)
include $(CDEPS) $(CXXDEPS) $(CGENDEPS) $(CXXGENDEPS)
endif

##############################################

_all: $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS),$($(target)_PREMAKE) $($(target)_TARGET) $($(target)_POSTMAKE)) $(POSTALL)

cscope.files: Makefile $(INCLUDE_MAKEFILES)
	@echo making cscope.files
	@rm -f cscope.files ; touch cscope.files
	@$(foreach f,$(HDRS) $(CSRCS) $(CXXSRCS),echo $(f) >> cscope.files ;)

cscope: cscope.files $(HDRS) $(CSRCS) $(CXXSRCS)
	@echo making cscope.out
	@cscope -bk

install: installdirs $(foreach target,$(LIB_TARGETS) $(PROG_TARGETS),\
		$(target)_install) $(foreach target,$(LIB_TARGETS) \
		$(PROG_TARGETS),$($(target)_POSTINSTALL)) \
		$(POSTINSTALL)

doxygen: $(foreach target,$(DOXYGEN_TARGETS),$(target)_doxygen)

doxygen-install: $(foreach target,$(DOXYGEN_TARGETS),$(target)_doxygen-install)

clean: $(EXTRA_CLEAN)
	rm -f $(ALL_TARGETS)
	rm -rf $(OBJDIR) dox/*
