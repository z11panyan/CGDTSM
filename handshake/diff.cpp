#include <assert.h>
//#include <pthread.h>
#include <stdint.h>

#include "common.h"
#include "func.h"

// include generic structures for diff-based fuzzing
#include "diff.h"


//tls-diff 
#include "DataUnit.h"
#include "EnumerationField.h"
#include "VectorBuffer.h"
#include "TCPClientSocket.h"
#include "TCPServerSocket.h"
#include "UDPClientSocket.h"
#include "BufferStreamReader.h"
#include "PropertyNode.h"
#include "FileStreamReader.h"
#include "DecisionReader.h"
#include "DataUnitFilter.h"
#include "DataUnitCursor.h"
#include "DataUnitVisitor.h"
#include "FuzzOperator.h"
#include "DataUnitOperator.h"
#include "VoidField.h"
#include "../../tls-definitions.h"
#include "SHA256.h"
#include "TCPBatchClientSocket.h"
/* TODO: Add description */
int test_servers(string inputRandomFile, string outputFile, size_t N, size_t nMaxOp, const vector<bool>& opEnable);

int mutate(string inputRandomFile,uint8_t* CurrentUnitData,size_t size);

/* TODO: Add description */
void writeToFile(const string& filename, const string& text, bool append = false);


using namespace std;




/*
 * ___________________________________________________________________________
 */
class GlobalFilter : public DataUnitFilter {

public:

	bool apply(const DataUnit& dataUnit) const {

		return dataUnit.getDistanceToRoot() > 1 && /*dataUnit.getLength() > 0 &&*/ dataUnit.getName() != "CipherSuite";
	}

};


/*
 * ___________________________________________________________________________
 */
class MyFilter3 : public DataUnitFilter {

public:

	bool apply(const DataUnit& dataUnit) const {

		return (dataUnit.hasParent() && dataUnit.getParent()->containsType(VectorDataUnit::typeDescriptor())) ||
				!dataUnit.hasNext();
	}

};



/*
 * ___________________________________________________________________________
 */
class VectorElementFilter : public DataUnitFilter {

public:

	bool apply(const DataUnit& dataUnit) const {

		return dataUnit.hasParent() && dataUnit.getParent()->containsType(VectorDataUnit::typeDescriptor());
	}

};


/*
 * ___________________________________________________________________________
 */
class DynamicLengthFilter : public DataUnitFilter {

public:

	bool apply(const DataUnit& dataUnit) const {

		int dynlen = 0;
		dataUnit.propGet<int>("_dynlen", dynlen);
		return dynlen > 0;
	}

};


/*
 * ___________________________________________________________________________
 */
class GeneratingFuzzOpFilter : public DataUnitFilter {

public:

	bool apply(const DataUnit& dataUnit) const {

        bool accept = false;

        if (dataUnit.isOfType(TStruct_Extension::typeDescriptor())) {
            accept = true;
        } else if (dataUnit.isOfType(TStruct_ClientHello_extensions::typeDescriptor())) {
            accept = true;
        } else if (dataUnit.isOfType(TStruct_ClientHello_cipher_suites::typeDescriptor())) {
            accept = true;
        }   

        return accept;
	}

};


/*
 * ___________________________________________________________________________
 */
size_t applyOperators(DecisionReader& decisionReader, DataUnit& operand, string& summary, int nMaxOp, const vector<bool>& opEnable) {

	size_t nOp = 0;

	VoidingOperator voidOp;
	DuplicatingOperator duplOp;
	DeletingOperator delOp;
	FuzzIntOperator fuzzIntOp(decisionReader);
	TruncationFuzzOperator truncFuzzOp(decisionReader);
	FuzzDataOperator fuzzDataOp(decisionReader, true);
	AppendingFuzzOperator appFuzzOp(decisionReader);
	GeneratingFuzzOperator genFuzzOp(decisionReader);

	DynamicLengthFilter dynLenFilter;
	VectorElementFilter vecItemFilter;
    GeneratingFuzzOpFilter genFuzzOpFilter;

	vector<DataUnitOperator*> operators;
	vector<DataUnitFilter*> filters;

    if (opEnable.size() <= 0 || opEnable[0]) {
	    operators.push_back(&voidOp);
	    filters.push_back(&dynLenFilter);
    }
    if (opEnable.size() <= 1 || opEnable[1]) {
	    operators.push_back(&duplOp);
	    filters.push_back(&vecItemFilter);
    }
    if (opEnable.size() <= 2 || opEnable[2]) {
	    operators.push_back(&delOp);
	    filters.push_back(&vecItemFilter);
    }
    if (opEnable.size() <= 3 || opEnable[3]) {
	    operators.push_back(&fuzzIntOp);
	    filters.push_back(0);
    }
    if (opEnable.size() <= 4 || opEnable[4]) {
	    operators.push_back(&truncFuzzOp);
	    filters.push_back(&dynLenFilter);
    }
    if (opEnable.size() <= 5 || opEnable[5]) {
	    operators.push_back(&fuzzDataOp);
	    filters.push_back(0);
    }
    if (opEnable.size() <= 6 || opEnable[6]) {
	    operators.push_back(&appFuzzOp);
	    filters.push_back(&dynLenFilter);
    }
    if (opEnable.size() <= 7 || opEnable[7]) {
	    operators.push_back(&genFuzzOp);
	    filters.push_back(&genFuzzOpFilter);
    }


	GlobalFilter globalFilter;


    do {

	    /* select a operator at random */
        if (operators.size() == 0) {
            cout << "No operators" << endl;
            break;
        }
	    size_t iOp = decisionReader.readUIntUniform(operators.size());
	    DataUnitOperator* op = operators[iOp];
	    DataUnitFilter* opFilter = filters[iOp];

	    /* select a data unit to operate on at random */
	    ConjunctionDataUnitFilter filter(globalFilter,
			    op->getApplicationFilter(), *opFilter);

	    String line;

	    DataUnitCursor cursor(operand);

	    size_t nDu = cursor.count(filter);
        if (nDu == 0) {
            continue;
        }

    	bool applyRecursive = false;

		size_t iDu = decisionReader.readUIntUniform(nDu);
		cursor.seekByIndex(iDu, filter);

		if (op->apply(cursor)) {

            /* path operator has been applied at */
		    String path = cursor.getCurrent().getPath();

            /* operator name */
			PropertyNode& opLog = op->getLastOperationLog();
			string opType = "unknown";
			opLog.propGet<string>("operator.type", opType);

		    line = String::format("%s@%s: ", opType.c_str(), path.c_str());

			bool repair = true;

			if (opType == "VoidingOperator") {

				line.append("voided");

			} else if (opType == "DuplicatingOperator") {

				line.append("duplicated");
				applyRecursive = true;

			} else if (opType == "DeletingOperator") {

				line.append("deleted");

			} else if (opType == "TruncationFuzzOperator") {

				line.appendFormat("truncated %s -> %s",
						opLog.propGet<string>("operand.length").c_str(),
						opLog.propGet<string>("operand.length.after").c_str());

			} else if (opType == "FuzzDataOperator") {

				repair = false;
				line.appendFormat("random content -> %s",
						opLog.propGet<string>("operand.length.after").c_str());

			} else if (opType == "FuzzIntOperator") {

				repair = false;
				line.appendFormat("%s --> %s",
						opLog.propGetDefault<string>("int.before", "##").c_str(),
						opLog.propGet<string>("int.after").c_str());

			} else if (opType == "AppendingFuzzOperator") {

				line.append("AppendingFuzzOperator");

			} else if (opType == "GeneratingFuzzOperator") {

				line.append("GeneratingFuzzOperator");
				applyRecursive = true;

			} else if (opType == "unknown") {

				line.append("unknown operator");

			}

			if (repair) {
				RepairingFuzzOperator repOp(decisionReader);
				repOp.apply(cursor);
				line.append(" ");
				line.append(repOp.getLastOperationLog().propGet<string>("operator.repairtrace"));
			}

			nOp += 1;
		    if (summary.length() > 0) {
			    summary.append("\n");
		    }
		    summary.append(line);

            if (decisionReader.readBoolUniform()
                    && cursor.valid()
                    && applyRecursive
                    && ((nMaxOp < 0) || (nOp < (size_t)nMaxOp))) {

	            nOp += applyOperators(decisionReader, cursor.getCurrent(),
                        summary, nMaxOp < 0 ? nMaxOp : nMaxOp - nOp, opEnable);
            }
		}

    } while (((nMaxOp < 0) || (nOp < (size_t)nMaxOp))
//            && (decisionReader.readUIntUniform(256) < 200));
            && decisionReader.readBoolUniform());

	return nOp;
}

int mutate(string inputRandomFile,uint8_t* CurrentUnitData,size_t size) {
	vector<bool> opEnable;
	size_t nMaxOp = -1;
 	/*
	for (size_t ic = 0; ic < 8; ic++) {
		opEnable.push_back(true);
	}*/	
	String tmp;
        for(size_t i = 0;i < size; i++)
	{
		char buf[3];
		sprintf(buf,"%02x",CurrentUnitData[i]);
		tmp.append(buf);
	}

	/* load the ClientHello template */
	VectorBuffer inBuf;
	inBuf.appendFromString(tmp);
	/* dissect and print original ClientHello */
	TVector_MainType printRec;
	printRec.dissector().dissectFromBuffer(inBuf);
	//printRec.print();

	/* fuzzing infrastructure */
	FileStreamReader ctrlStream(inputRandomFile);
	DecisionReader selector(ctrlStream);


	String line;
	std::map<string, bool> hashMap;
        size_t nDuplicates = 0;

	
	TVector_MainType outRec;
	outRec.dissector().dissectFromBuffer(inBuf);
	VectorBuffer outBuf;
        size_t nOp = 0;
	String summary;

        nOp = applyOperators(selector, outRec, summary, nMaxOp, opEnable);

        outRec.copyTo(outBuf);
	
	const uint8_t* tmp_data = outBuf.getDataPointer();
	BC BC_length = outBuf.getLength();
	size_t length = BC_length.byteCeil();
	for(int i = 0; i < length; i++)
	{
		CurrentUnitData[i] = tmp_data[i];
	}
	return length;
}


void writeToFile(const string& filename, const string& text, bool append) {

	ios_base::openmode mode = std::ofstream::out;
	if (append) {
		mode |= std::ios_base::app;
	}

	std::ofstream ofs(filename.data(),  mode);
	if (ofs.is_open()) {
		ofs << text << endl;
		ofs.close();
	}
}

//above code is based on tls-diff 

/*#ifndef CONFIG_USE_OPENSSL
// just in case openssl is not in the build
int ret_openssl = FAILURE_INTERNAL;
#endif
*/
#define INCLUDE(name) \
static fp_t do_handshake_ ##name = NULL; \
static void *h_ ##name = NULL; \
int ret_ ##name = FAILURE_INTERNAL; \

#ifdef CONFIG_USE_OPENSSL
#include "openssl.h"
INCLUDE(openssl)
#endif

#ifdef CONFIG_USE_LIBRESSL
#include "libressl.h"
INCLUDE(libressl)
#endif

#ifdef CONFIG_USE_BORINGSSL
#include "boringssl.h"
INCLUDE(boringssl)
#endif

#ifdef CONFIG_USE_WOLFSSL
#include "wolfssl.h"
INCLUDE(wolfssl)
#endif

#ifdef CONFIG_USE_MBEDTLS
#include "mbedtls.h"
INCLUDE(mbedtls)
#endif

#ifdef CONFIG_USE_GNUTLS
#include "gnutls.h"
INCLUDE(gnutls)
#endif


#define INIT_LIB(name, NAME) \
  if (!do_handshake_ ##name) { \
    do_handshake_ ##name = \
      (fp_t)get_interface_fn(h_ ##name, LIB_ ##NAME, FN_DO_HANDSHAKE); \
    fprintf(stderr, #name " %p\n", do_handshake_ ##name); \
    if (!do_handshake_ ##name) \
      DBG("ERROR resolving function from: %s\n", LIB_ ##NAME); \
  } \
  assert(do_handshake_ ##name != NULL);

#define DO_HANDSHAKE_ONE(name) \
  ret_ ##name = do_handshake_ ##name(Data, Size);

struct GlobalInitializer {
  GlobalInitializer() {

#ifdef CONFIG_USE_OPENSSL
    INIT_LIB(openssl, OPENSSL)
#endif
#ifdef CONFIG_USE_LIBRESSL
    INIT_LIB(libressl, LIBRESSL)
#endif
#ifdef CONFIG_USE_LIBRESSL
    INIT_LIB(boringssl, BORINGSSL)
#endif
#ifdef CONFIG_USE_WOLFSSL
    INIT_LIB(wolfssl, WOLFSSL)
#endif
    // initialize all diff-based structures
    // diff_init();
  }

    ~GlobalInitializer() { }
};

static GlobalInitializer g_initializer;

typedef int (*UserCallback)(const uint8_t *Data, size_t Size);
struct UserCallbacks {
  UserCallback *callbacks;
  int size;
} callback_cont = { NULL, 0 };

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  
  DO_HANDSHAKE_ONE(openssl)
  return ret_openssl;

}

extern "C" int Callback2(const uint8_t *Data, size_t Size) {

  DO_HANDSHAKE_ONE(libressl)
  return ret_libressl;
}

extern "C" int Callback3(const uint8_t *Data, size_t Size) {

  DO_HANDSHAKE_ONE(boringssl)
  return ret_boringssl;
}

extern "C" int Callback4(const uint8_t *Data, size_t Size) {

  DO_HANDSHAKE_ONE(wolfssl)
  return ret_wolfssl;
}

UserCallback gl_callbacks[4] = { LLVMFuzzerTestOneInput, Callback2, Callback3, Callback4 };
extern "C" UserCallbacks *LLVMFuzzerCustomCallbacks() {
  callback_cont.callbacks = gl_callbacks;
  callback_cont.size = 4;
  return &callback_cont;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  char message[100];
  sprintf(message,"./random/random%d.bin",rand()%1000+1);
  return mutate(message,Data,Size);
}
