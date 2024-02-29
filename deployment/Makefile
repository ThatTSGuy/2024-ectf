
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	echo "uint8_t SECRET[] = { 0x84, 0x92, 0x95, 0xbb, 0x81, 0xc5, 0x16, 0x1a, 0x77, 0x75, 0x70, 0xc0, 0xe4, 0x4a, 0xc3, 0x76 };" > global_secrets.h

clean:
	rm -f global_secrets.h
