#ifndef GENERATE_H
#define GENERATE_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <ios>
#include <string>
#include <sstream>
#include <netdb.h>
#include <map>
#include <utility>
#include <vector>
#include <cmath>
#include "errno.h"
#include <time.h>

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

#endif  // GENERATE_H
