# Compiler
CXX = g++
CXXFLAGS = -Wall -std=c++17
GCOVFLAGS = -fprofile-arcs -ftest-coverage -g


# Default target: build both
all: bar_drinks molecule_requester

bar_drinks: bar_drinks.cpp
	$(CXX) $(CXXFLAGS) -o bar_drinks bar_drinks.cpp

molecule_requester: molecule_requester.cpp
	$(CXX) $(CXXFLAGS) -o molecule_requester molecule_requester.cpp

gcov:
	rm -f bar_drinks *.gcda *.gcno *.gcov
	g++ -Wall -std=c++17 -g -fprofile-arcs -ftest-coverage bar_drinks.cpp -o bar_drinks
	g++ -Wall -std=c++17 -g -fprofile-arcs -ftest-coverage molecule_requester.cpp -o molecule_requester


# Clean up
clean:
	rm -f bar_drinks molecule_requester *.gcda *.gcno *.gcov

