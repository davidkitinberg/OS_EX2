.PHONY: all Task_1 Task_2 Task_3 Task_4 Task_5 Task_6 gcov clean

# Build everything
all: Task_1 Task_2 Task_3 Task_4 Task_5 Task_6

Task_1:
	$(MAKE) -C Task_1

Task_2:
	$(MAKE) -C Task_2

Task_3:
	$(MAKE) -C Task_3

Task_4:
	$(MAKE) -C Task_4

Task_5:
	$(MAKE) -C Task_5

Task_6:
	$(MAKE) -C Task_6

# Run gcov in Task_6 only
gcov:
	$(MAKE) -C Task_6 gcov

# Clean all
clean:
	$(MAKE) -C Task_1 clean || true
	$(MAKE) -C Task_2 clean || true
	$(MAKE) -C Task_3 clean || true
	$(MAKE) -C Task_4 clean || true
	$(MAKE) -C Task_5 clean || true
	$(MAKE) -C Task_6 clean || true