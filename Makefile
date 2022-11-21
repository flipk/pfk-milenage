
OBJDIR = obj

# --- library with rijndael and milenage

LIB_TARGETS += milenage

milenage_TARGET = $(OBJDIR)/libmilenage.a
milenage_CXXSRCS = Rijndael.cc Milenage35206.cc xor34108.cc

# --- test program for milenage

PROG_TARGETS += test_mil

test_mil_TARGET = $(OBJDIR)/test_mil
test_mil_CXXSRCS = main.cc
test_mil_DEPLIBS = $(milenage_TARGET)

include Makefile.inc
