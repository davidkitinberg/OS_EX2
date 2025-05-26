# Compiler
CXX = g++
CXXFLAGS = -Wall -std=c++17


# Default target: build both
all: atom_warehouse atom_supplier

atom_warehouse: atom_warehouse.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

atom_supplier: atom_supplier.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

# Clean up
clean:
	rm -f atom_warehouse atom_supplier

