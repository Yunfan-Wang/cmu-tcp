TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build
CC=gcc
FLAGS = -pthread -fPIC -g -ggdb -pedantic -Wall -Wextra -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/cmu_packet.o $(BUILD_DIR)/cmu_tcp.o $(BUILD_DIR)/backend.o

all: server client tests/testing_server

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(FLAGS) -MMD -MP -c -o $@ $<

-include $(OBJS:.o=.d)

server: $(OBJS) $(SRC_DIR)/server.c
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)

client: $(OBJS) $(SRC_DIR)/client.c
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS)

tests/testing_server: $(OBJS)
	$(CC) $(FLAGS) tests/testing_server.c -o tests/testing_server $(OBJS)

format:
	pre-commit run --all-files

test:
	python3 tests/test_cp1_reference.py

test-vagrant:
	sudo -E python3 tests/test_cp1.py
	sudo -E python3 tests/test_cp1_basic_ack_packets.py

clean:
	rm -f $(BUILD_DIR)/*.o peer client server
	rm -f $(BUILD_DIR)/*.d
	rm -f tests/testing_server

.PHONY: all format test test-vagrant clean
