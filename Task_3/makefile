# Compiler
CXX = g++
CXXFLAGS = -Wall -std=c++17


all: bar_drinks molecule_requester

bar_drinks: bar_drinks.cpp
	$(CXX) $(CXXFLAGS) -o bar_drinks bar_drinks.cpp

molecule_requester: molecule_requester.cpp
	$(CXX) $(CXXFLAGS) -o molecule_requester molecule_requester.cpp

# Clean up
clean:
	rm -f bar_drinks molecule_requester
