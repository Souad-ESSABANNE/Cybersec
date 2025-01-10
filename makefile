# Variables
REVERSE_SCRIPT = reverse.sh
FUZZING_SCRIPT = fuzzer.py
FUZZING_RESULTS = fuzzing_results.txt

# Targets
all: reverse fuzz

# Step 1: Run reverse engineering script
reverse: $(REVERSE_SCRIPT)
	@echo "Running reverse engineering script..."
	chmod +x $(REVERSE_SCRIPT)
	./$(REVERSE_SCRIPT)

# Step 2: Run fuzzing script
fuzz: $(FUZZING_SCRIPT)
	@echo "Running fuzzing script..."
	python3 $(FUZZING_SCRIPT) > $(FUZZING_RESULTS)

# Clean generated files
clean:
	@echo "Cleaning up temporary files..."
	rm -f reverse_test.txt critical_functions.txt $(FUZZING_RESULTS)
