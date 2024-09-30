
CC = gcc
CFlAGS = -Wall -gcc 
TARGET1 = attack
SRC = attack.c
PY_FILES = DNS_Request2.py Spoof_DNS_Replies3.py

# The 'all' target 
all: run

#run the python files and the attack
run:$(TARGET1)
	python3 DNS_Request2.py
	python3 Spoof_DNS_Replies3.py
	./$(TARGET1)
#run only the attack
run-attack:$(TARGET1)
	./$(TARGET1)

#build the executable
$(TARGET1): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET1) $(SRC)

clean:
	rm -f $(TARGET1) ip_req.bin ip_resp.bin

.PHONY: all clean run run-attack																



