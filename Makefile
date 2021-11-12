
TEST_FILE1 = "test"
TEST_FILE2 = "2021-09-08 10-41-51.mkv"

all:
	cd build && make -j 8 || clear && make

run: all
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/robustFileDating $(TEST_FILE1) key
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/robustFileDating $(TEST_FILE2) key

re:
	./run.sh

_clear:
	clear

valgrind: _clear all
	#####################################
	#                                   #
	#                                   #
	#####################################
	valgrind --track-origins=yes ./build/bin/robustFileDating $(TEST_FILE1) key
	#####################################
	#                                   #
	#                                   #
	#####################################
	valgrind --track-origins=yes ./build/bin/robustFileDating $(TEST_FILE2) key

generateKeys:
	./build/bin/robustFileDating -g key

verify: all
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/robustFileDating $(TEST_FILE1)
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/robustFileDating $(TEST_FILE2)
