# Compiler
CXX = g++
CXXFLAGS = -Wall -std=c++17


all: molecule_supplier molecule_requester

molecule_supplier: molecule_supplier.cpp
	$(CXX) $(CXXFLAGS) -o molecule_supplier molecule_supplier.cpp

molecule_requester: molecule_requester.cpp
	$(CXX) $(CXXFLAGS) -o molecule_requester molecule_requester.cpp

# Clean up
clean:
	rm -f molecule_supplier molecule_requester
