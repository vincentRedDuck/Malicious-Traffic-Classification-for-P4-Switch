include /usr/local/etc/PcapPlusPlus.mk

CCFLAG = -std=c++17

# All Target
all:
	g++ $(PCAPPP_INCLUDES) $(CCFLAG) -c -o 2_llc2eth_header.o 2_llc2eth_header.cpp
	g++ $(PCAPPP_LIBS_DIR) $(CCFLAG) -o 2_llc2eth_header 2_llc2eth_header.o $(PCAPPP_LIBS)
	rm 2_llc2eth_header.o  
