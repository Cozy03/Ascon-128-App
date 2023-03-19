import string
import random

def generate_random_file(size):
    """Generates a random text file of the specified size"""
    # Generate a random string of printable ASCII characters
    content = ''.join(random.choice(string.printable) for _ in range(size))
    # Write the string to a file
    with open("random_file.txt", "w") as f:
        f.write(content)

# Example usage: generate a 1 MB file
generate_random_file(1024 * 1024)