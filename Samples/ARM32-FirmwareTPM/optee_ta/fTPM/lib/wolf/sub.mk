#
# Wolfcrypt has multiple unused functions, unfortunately the OPTEE build system can only turn off compiler flags for
# files in the same directory as the sub.mk file. It is not possible to place sub.mk files in the git submodules without
# creating a new fork of each submodule repo. To avoid spurious warnings these warnings are disabled here globally.
#

WOLF_WARNING_SUPPRESS = -Wno-unused-function -Wno-switch-default

#
# For the purposes of this command the current working directory is the makefile root (/fTPM) folder,
# but the symlink will be created relative to THIS directory so the source requires an extra '../../'.
#
./lib/wolf/wolf_symlink:
	@echo Checking symlink to the WolfSSL folder: $(abspath $(WOLF_ROOT))
	@if [ -L ./lib/wolf/wolf_symlink ] ; \
	then \
	echo Symlink already established ; \
	else \
	echo Establishing symlink. ; \
	ln -s ../../$(WOLF_ROOT) ./lib/wolf/wolf_symlink; \
	fi

.PHONY: remove_wolf_symlink
remove_wolf_symlink:
	@if [ -e ./lib/wolf/wolf_symlink ] ; \
	then \
	unlink ./lib/wolf/wolf_symlink ; \
	echo Clearing symlink to the Wolf folder: $(abspath $(WOLF_ROOT)) ; \
	fi

global-incdirs-y += wolf_symlink

wolf_crypt_files = \
wolf_symlink/wolfcrypt/src/aes.c \
 wolf_symlink/wolfcrypt/src/asn.c \
 wolf_symlink/wolfcrypt/src/ecc.c \
 wolf_symlink/wolfcrypt/src/integer.c \
 wolf_symlink/wolfcrypt/src/memory.c \
 wolf_symlink/wolfcrypt/src/rsa.c \
 wolf_symlink/wolfcrypt/src/sha.c \
 wolf_symlink/wolfcrypt/src/sha256.c \
 wolf_symlink/wolfcrypt/src/sha512.c \
 wolf_symlink/wolfcrypt/src/tfm.c \
 wolf_symlink/wolfcrypt/src/wolfmath.c \
 wolf_symlink/wolfcrypt/src/des3.c \
 wolf_symlink/wolfcrypt/src/random.c \

srcs-y = $(foreach wcfile, $(wolf_crypt_files), $(wcfile) )
$(foreach wcfile, $(wolf_crypt_files), $(eval  cflags-$(wcfile)-y += -DFOOBAR $(WOLF_SSL_FLAGS) $(WOLF_WARNING_SUPPRESS)))