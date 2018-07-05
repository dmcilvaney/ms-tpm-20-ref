
export V?=0

.PHONY: all
all:
	$(MAKE) -C hello_world CROSS_COMPILE=$(TA_CROSS_COMPILE)
	$(MAKE) -C auth_var CROSS_COMPILE=$(TA_CROSS_COMPILE)
	$(MAKE) -C fTPM CROSS_COMPILE=$(TA_CROSS_COMPILE)

.PHONY: clean
clean:
	$(MAKE) -C hello_world clean
	$(MAKE) -C auth_var clean
	$(MAKE) -C fTPM clean
	rm -rf out/wolfssl out/TAs