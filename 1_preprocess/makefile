CC = g++
CCFLAG = -std=c++17 -pthread -lpcap

OBJ_FILE = 1_fileEachFlow.o 

all: $(OBJ_FILE)
	$(foreach obj, $(OBJ_FILE), \
		$(CC) $(CCFLAG) -o $(basename $(obj)) $(obj); \
		rm $(obj); \
	)
%.o: %.cpp
	$(CC) $(CCFLAG) -c $<

clean:
	rm $(basename $(OBJ_FILE))
	
