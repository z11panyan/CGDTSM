
#
# General
#
#
CC=clang
CXX=clang++

# Directories
LIBS_DIR=../BUILD
LIBFUZZER=../Fuzzer/libFuzzer.a

CERT_DIR=certs
OUT_DIR=out
CORPUS_DIR=corpus_dir
LIBDIR=lib
ROOT_DIR=/home/username/tls-diff-testing/tls-diff-testing
LIB_CRYPTOPP=/home/username/tls-diff-testing/cryptopp
LIB_DIRS   = $(ROOT_DIR)/bitman/build $(ROOT_DIR)/cryptoman/build $(ROOT_DIR)/middleman/build $(LIB_CRYPTOPP)
EXTRALIBS       = middleman cryptoman bitman cryptopp
LDFLAGS =  $(foreach d, $(LIB_DIRS), -L$d) $(foreach d, $(EXTRALIBS), -l$d)
INC_DIRS   = -I$(ROOT_DIR)/bitman/inc -I$(ROOT_DIR)/cryptoman/inc -I$(ROOT_DIR)/middleman/inc -I$(LIB_CRYPTOPP)/../ -I../Fuzzer/src
# List of SSL libraries
#OPENSSL=/home/username/test/openssl-1.0.2h/build
#LIBRESSL=/home/username/test/libressl-2.4.0/build
#BORINGSSL=/home/username/test/impl_boringssl-2883

OPENSSL=/home/username/test/openssl_build
LIBRESSL=/home/username/test/libressl-3.2.1/build
BORINGSSL=/home/username/test/boringssl
WOLFSSL=/home/username/test/wolfSSL4.5.0/build

#OPENSSL=/home/username/test/openssl_build
#LIBRESSL=/home/username/test/openssl_1_1_0/build
#BORINGSSL=/home/username/test/openssl_1_0_2/build


#
#
# Configuration
#
#

# All possible libs: do not remove from this list, just set the appropriate
# USE_LIB_XXX flag, if you want to include this lib in the build
ALL_LIBS = boringssl openssl libressl wolfssl

USE_LIB_OPENSSL=1
# CONFIG: Select libraries to include
USE_LIB_BORINGSSL=1
USE_LIB_LIBRESSL=1
USE_LIB_WOLFSSL=1

# populate based on selection above
LIBS =
CONFIG_USE_LIBS =

LIBS=$(foreach l, \
	 $(ALL_LIBS), \
	 $(if $(filter 1,$(USE_LIB_$(shell echo $l | tr a-z A-Z))),$l))

CONFIG_USE_LIBS=$(foreach l, \
				$(ALL_LIBS), \
				$(if $(filter 1,$(USE_LIB_$(shell echo $l | tr a-z A-Z))),\
				-DCONFIG_USE_$(shell echo $l | tr a-z A-Z)))

# CONFIG: Indicate if we are compiling with the main() function for testing
# (Do not set when compiling with libFuzzer)
DBG_MAIN=0
ifeq ($(DBG_MAIN), 1)
CONFIG_DBG_MAIN=-DCONFIG_DBG_MAIN
endif


# this cannot be passed at runtime for the tests
# because they are created dynamically

CONFIG_USE_DER=-DCONFIG_USE_DER

# CONFIG: Enable debugging logs
DBG_LOG=0
ifeq ($(DBG_LOG), 1)
CONFIG_DEBUG=-DCONFIG_DEBUG
BIN_SUFFIX=.out.dbg
else
BIN_SUFFIX=.out
endif

SUM=0
ifeq ($(SUM), 1)
CONFIG_DEBUG=-DCONFIG_SUMMARY
endif

OPTIONS=$(CONFIG_DBG_MAIN) $(CONFIG_USE_DER) $(CONFIG_DEBUG)
DBGFLAGS=-g -ggdb3
CFLAGS=-O0 -Wall $(DBGFLAGS) $(OPTIONS)
CFLAGS_SHARED_O=-fPIC -fvisibility=hidden
CFLAGS_SHARED_LIB=$(CFLAGS_SHARED_O) -rdynamic -shared
COV_FLAGS=-O0 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div
#
#
# Flags
#
#
INC_BORINGSSL= -I$(BORINGSSL)/include
LD_BORINGSSL=-L$(BORINGSSL)/build/ssl -lssl -L$(BORINGSSL)/build/crypto -L$(BORINGSSL)/crypto -lcrypto -pthread -Wl,-static -lcrypto -Wl,-Bdynamic
#INC_BORINGSSL = -I$(BORINGSSL)/include
#LD_BORINGSSL = -L$(BORINGSSL)/lib -lssl -lcrypto

INC_OPENSSL= -I$(OPENSSL)/include
LD_OPENSSL= -L$(OPENSSL)/lib -lssl -lcrypto


INC_LIBRESSL= -I$(LIBRESSL)/include
LD_LIBRESSL= -L$(LIBRESSL)/lib -lssl -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic


INC_WOLFSSL= -I$(WOLFSSL)/include
LD_WOLFSSL= -L$(WOLFSSL)/lib -lwolfssl -lcrypto -Wl

LD_MAIN=-ldl -lstdc++ -pthread
#
#
# Make Rules
#
#
TARGET=diff$(BIN_SUFFIX)

.PHONY:all
all: prelim $(TARGET)

.PHONY:prelim
prelim:
	mkdir -p $(LIBDIR) $(OUT_DIR)

define mk_libs
lib$1.so: $1.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_O) $(INC_$(shell echo $1 | tr a-z A-Z)) \
		$(COV_FLAGS) -c -o $1.o $1.cpp

	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_LIB) $(COV_FLAGS) \
		-o lib$1.so $1.o $(LD_$(shell echo $1 | tr a-z A-Z))
	mv lib$1.so $(LIBDIR)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_libs,$(l))) \
)

$(TARGET): diff.cpp $(foreach l, $(LIBS), lib$(l).so)
	$(CXX) $(CFLAGS) $() \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z))) $(INC_DIRS) -L./lib\
			$(COV_FLAGS) $(CONFIG_USE_LIBS) $< $(LIBFUZZER) $(LDFLAGS) \
			$(LD_MAIN) -o $@


#
#
# Test rules
#
#

TEST_CERT=test_cert.$(CA_FORMAT)
TEST_COMMON=main_test.cpp
# mbedTLS does not accept 1024!
KEY_SZ=2048

.PHONY: mk_all_tests
mk_all_tests: $(foreach l, $(LIBS), test_$(l))

.PHONY: run_all_tests
run_all_tests: $(foreach l, $(LIBS), run_test_$(l))

define mk_tests
test_$1:
	$(CXX) $(COV_FLAGS) -DCONFIG_TEST_$(shell echo $1 | tr a-z A-Z) \
	-DCONFIG_DBG_MAIN $(CFLAGS) $(INC_$(shell echo $1 | tr a-z A-Z)) \
	$(TEST_COMMON) $1.cpp -o test_$1$(BIN_SUFFIX) \
	$(LD_$(shell echo $1 | tr a-z A-Z))
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_tests,$(l))) \
)

define mk_run_tests
run_test_$1:
	ASAN_OPTIONS=halt_on_error=0 ./test_$1$(BIN_SUFFIX) \
				 $(CERT_DIR)/$(TEST_CERT)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_run_tests,$(l))) \
)



# Trial-run of fuzzing with corpus with no mutation
.PHONY: fuzz_big
fuzz_big: $(BIG_CORPUS)
	./$(TARGET) $(BIG_CORPUS) -max_len=1500 -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=-1 -detect_leaks=0 -rss_limit_mb=4096

.PHONY: fuzz_small
fuzz_small: $(SMALL_CORPUS)
	./$(TARGET) $(SMALL_CORPUS) -max_len=1500 -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=-1 -detect_leaks=0 -rss_limit_mb=4096 -jobs=10 \
-workers=4

.PHONY: fuzz_test
fuzz_test: $(SMALL_CORPUS)
	ASAN_OPTIONS=coverage=1:html_cov_report=1:detect_leaks=0 \
	./$(TARGET) $(SMALL_CORPUS) -max_len=1500 -artifact_prefix=$(OUT_DIR)/ \
-print_final_stats=1 -runs=0 -detect_leaks=0 -jobs=1

# Test code coverage of corpus
.PHONY: cov
cov:
	ASAN_OPTIONS=coverage=1:html_cov_report=1:detect_leaks=0 \
./$(TARGET) $(CORPUS_DIR) -jobs=1 -workers=1 -runs=0


.PHONY: test
test:
	rm -rf corpus out/*
	#cp -R /home/username/tls-diff-testing/tls-diff-testing/generator/iteration-001 corpus
	cp -R sample_seed corpus 
	#cp -R diff_new corpus
	./generate.sh
	ASAN_OPTIONS=halt_on_error=0 ./diff.out ./corpus\
				 -artifact_prefix=out/ -diff_mode=1 \
				 -print_final_stats=1 -runs=10000 -detect_leaks=1

#
#
# Clean rules
#
#
.PHONY:clean
clean:
	rm -rf *.o *.a $(LIBDIR) diff.out* test_* \
			\ fuzzdiff*
