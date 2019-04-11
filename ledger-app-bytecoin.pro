TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

#export BOLOS_ENV = ~/bolos-devenv
#export BOLOS_SDK = ~/bolos-devenv/nanos-secure-sdk

DEFINES += OS_IO_SEPROXYHAL
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BAGL HAVE_SPRINTF
DEFINES += HAVE_PRINTF PRINTF=screen_printf
#DEFINES += PRINTF\(...\)=
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
#DEFINES += HAVE_BLE
DEFINES += HAVE_USB_CLASS_CCID
DEFINES += BYTECOIN_DEBUG_SEED


#DEFINES += IOCRYPT
## Debug options
#DEFINES += DEBUG_HWDEVICE
#DEFINES += IODUMMYCRYPT
DEFINES += IONOCRYPT
#DEFINES += TESTKEY

DEFINES += USB_SEGMENT_SIZE=64
#DEFINES += HAVE_IO_U2F HAVE_U2F

INCLUDEPATH += ../bolos-devenv/nanos-secure-sdk/include

SOURCES += \
    src/bytecoin_main.c \
    src/bytecoin_crypto.c \
    src/bytecoin_sig.c \
    src/bytecoin_apdu.c \
    src/bytecoin_wallet.c \
    src/bytecoin_fe.c \
    src/bytecoin_io.c \
    src/bytecoin_keys.c \
    src/bytecoin_keccak.c \
    src/bytecoin_vars.c \
    src/bytecoin_ui.c \
    src/glyphs.c

HEADERS += \
    src/bytecoin_crypto.h \
    src/bytecoin_sig.h \
    src/bytecoin_vars.h \
    src/bytecoin_apdu.h \
    src/bytecoin_io.h \
    src/bytecoin_wallet.h \
    src/bytecoin_fe.h \
    src/bytecoin_keys.h \
    src/bytecoin_ledger_api.h \
    src/bytecoin_keccak.h \
    src/bytecoin_ui.h \
    src/glyphs.h

