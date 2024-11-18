import subprocess
import os

# Base directory for all tests
BASE_TEST_DIR = "test"

def test_dns_monitor():
    # List of test case names and their associated DNS record types
    test_cases = [
        'A',
        'AAAA',
        'SOA',
        'NS',
        'CNAME',
        'BIG',
    ]
    
    # Dictionary to store file paths for comparison later
    generated_files = {}

    # Iterate over each test case
    for test_case in test_cases:
        print(f"Running test {test_case} ({test_case} record)")

        # Construct file paths using helper function
        pcap_file = test_case + '/test.pcapng'
        translation_file = test_case +  '/translation.txt'
        correct_file = test_case + '/translation_correct.txt'

        # Construct the test command
        test_command = f"cd .. && make && sudo ./dns-monitor -p {BASE_TEST_DIR}/{pcap_file} -t {BASE_TEST_DIR}/{translation_file} -v"
        
        # Run the test command
        subprocess.run(test_command, shell=True)
        
        # Store the generated translation file for later comparison
        generated_files[test_case] = {
            'translation_file': translation_file,
            'correct_file': correct_file,
            'name': test_case
        }

    # Now compare all files at once at the end
    compare_all_files(generated_files)


def compare_all_files(generated_files):
    """
    Compare all the generated files with their corresponding correct files at the end.

    :param generated_files: A dictionary containing test case names as keys 
                             and paths to the generated and correct files.
    """
    for test_case, files in generated_files.items():
        compare_files(files['correct_file'], files['translation_file'], test_case)

def compare_files(file1_path, file2_path, test_name):
    """
    Compares two files line by line and prints differences.

    :param file1_path: Path to the first file
    :param file2_path: Path to the second file
    :param test_name: The name of the test to include in output
    """
    try:
        with open(file1_path, 'r') as file1, open(file2_path, 'r') as file2:
            # Read lines from both files
            file1_lines = file1.readlines()
            file2_lines = file2.readlines()
            
            # Compare line by line
            max_lines = max(len(file1_lines), len(file2_lines))
            differences_found = False  # Flag to track if any difference is found
            for i in range(max_lines):
                file1_line = file1_lines[i].strip() if i < len(file1_lines) else "[No line in File 1]"
                file2_line = file2_lines[i].strip() if i < len(file2_lines) else "[No line in File 2]"
                
                if file1_line != file2_line:
                    print(f"Difference at line {i+1}:")
                    print(f"    File 1: {file1_line}")
                    print(f"    File 2: {file2_line}")
                    differences_found = True

            if not differences_found:
                print(f"TEST {test_name} PASSED")
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Run the test function
test_dns_monitor()
