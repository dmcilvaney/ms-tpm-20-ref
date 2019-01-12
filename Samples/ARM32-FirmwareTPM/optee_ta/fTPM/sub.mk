WARNS ?= 1
NOWERROR ?= 1
CFG_TA_DEBUG ?= n
CFG_TEE_TA_LOG_LEVEL ?= 1
CFG_TA_AUTHVAR_HIGH_PERFORMANCE_MODE ?= n

FTPM_FLAGS = -DGCC -DUSE_WOLFCRYPT -DSIMULATION=NO -DUSE_PLATFORM_EPS -DVTPM
FTPM_DEBUG =  -DCOMPILER_CHECKS=YES -DfTPMDebug -DRUNTIME_SIZE_CHECKS -DLIBRARY_COMPATIBILITY_CHECK -DFAIL_TRACE
FTPM_RELEASE = -DCOMPILER_CHECKS=NO -DRUNTIME_SIZE_CHECKS=NO -DLIBRARY_COMPATIBILITY_CHECK=NO
FTPM_WARNING_SUPPRESS = -Wno-cast-align -Wno-switch-default -Wno-suggest-attribute=noreturn -Wno-missing-braces -Wno-sign-compare

ifeq ($(CFG_TA_AUTHVAR_HIGH_PERFORMANCE_MODE),y)
AUTHVAR_FLAGS = -DAUTHVAR_HIGH_PERFORMANCE_MODE -DAUTHVAR_WRITEBACK_DELAY=10
endif

WOLF_SSL_FLAGS = -DSINGLE_THREADED -DNO_FILESYSTEM -DNO_WOLFSSL_CLIENT -DNO_WOLFSSL_SERVER -DOPENSSL_EXTRA -DWOLFSSL_USER_SETTINGS -DTIME_OVERRIDES -DSTRING_USER -DCTYPE_USER -DHAVE_PKCS7 -DHAVE_AES_KEYWRAP -DHAVE_X963_KDF -DNO_WRITEV -DNO_ASN_TIME -DHAVE_TIME_T_TYPE -DWOLFCRYPT_ONLY
WOLF_WARNING_SUPPRESS = -Wno-unused-function -Wno-switch-default

#
# The fTPM needs to overwrite some of the header files used in the reference implementation. The search order GCC
# uses is dependent on the order the '-I/include/path' arguments are passed in. This is depended on the optee_os build
# system which makes it brittle. Force including these files here will make sure the correct files are used first.
#
FTPM_INCLUDES = -include ./reference/include/VendorString.h -include ./reference/include/Implementation.h
WOLF_INCLUDES = -include ./reference/include/user_settings.h
INCLUDE_OVERWRITES = $(FTPM_INCLUDES) $(WOLF_INCLUDES)

CPPFLAGS += -DTHIRTY_TWO_BIT -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -D_ARM_ -w -Wno-strict-prototypes -mcpu=$(TA_CPU) -fstack-protector -Wstack-protector -mno-unaligned-access
cflags-y += $(INCLUDE_OVERWRITES)

ifeq ($(CFG_TA_DEBUG),y)
CPPFLAGS += -DfTPMDebug=1
CPPFLAGS += -DDBG=1
CPPFLAGS += -O0
CPPFLAGS += -DDEBUG
else
CPPFLAGS += -Os
CPPFLAGS += -DNDEBUG
endif

#
# Link the required external code into the libraries folder. OP-TEE build
# does not work well when accessing anything below the root directory. Use
# symlinks to trick it.
#
all: create_lib_symlinks
clean: clean_lib_symlinks

subdirs-y += lib

global-incdirs-y += include
global-incdirs-y += reference/include
global-incdirs-y += platform/include
global-incdirs-y += platform/authvar/include

srcs-y += platform/AdminPPI.c
srcs-y += platform/Cancel.c
srcs-y += platform/Clock.c
srcs-y += platform/Entropy.c
srcs-y += platform/LocalityPlat.c
srcs-y += platform/NvAdmin.c
srcs-y += platform/NVMem.c
srcs-y += platform/PowerPlat.c
srcs-y += platform/PlatformData.c
srcs-y += platform/PPPlat.c
srcs-y += platform/RunCommand.c
srcs-y += platform/Unique.c
srcs-y += platform/EPS.c
srcs-y += reference/RuntimeSupport.c

subdirs-y += platform/authvar

srcs-y += fTPM.c
