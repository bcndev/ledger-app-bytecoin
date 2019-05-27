/*******************************************************************************
*   Bytecoin Wallet for Ledger Nano S
*   (c) 2018 - 2019 The Bytecoin developers
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef BYTECOIN_DEBUG_H
#define BYTECOIN_DEBUG_H

#include "os.h"

#define STR(x)  #x
#define XSTR(x) STR(x)

#define PRINT_PRIMITIVE(primitive) \
    PRINTF(XSTR(primitive)": %.*h\n", sizeof((primitive).data), (primitive).data);
#define PRINT_BUF(buf) \
    PRINTF(XSTR(buf)": %.*h\n", sizeof(buf), (buf));

#endif // BYTECOIN_DEBUG_H
