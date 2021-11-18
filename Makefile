
TEST_FILE1 = "test"
TEST_FILE2 = "2021-09-08 10-41-51.mkv"
TEST_FILE3 = conanfile.txt Makefile README.md

BINARY = robustFileDating


all:
	rm $(BINARY)
	cd build && make -j 8 || clear && make
	cp ./build/bin/$(BINARY) .

run: all
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/$(BINARY) key $(TEST_FILE1)
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/$(BINARY) key $(TEST_FILE2)
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/$(BINARY) key $(TEST_FILE3)

re:
	./run.sh
	cp ./build/bin/$(BINARY) .

_clear:
	clear

valgrind: _clear all
	#####################################
	#                                   #
	#                                   #
	#####################################
	valgrind --track-origins=yes ./build/bin/$(BINARY) key $(TEST_FILE1)
	#####################################
	#                                   #
	#                                   #
	#####################################
	valgrind --track-origins=yes ./build/bin/$(BINARY) key $(TEST_FILE2)
	#####################################
	#                                   #
	#                                   #
	#####################################
	valgrind --track-origins=yes ./build/bin/$(BINARY) key $(TEST_FILE3)

generateKeys:
	./build/bin/$(BINARY) -g key

verify: all
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/$(BINARY) $(TEST_FILE1)
	#####################################
	#                                   #
	#                                   #
	#####################################
	./build/bin/$(BINARY) $(TEST_FILE2)

date_all:
	find -type f -exec "./$(BINARY)" "{}" "key" \;

undate_all:
	find -type f -exec "rm" "{}.date" \;