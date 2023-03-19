def compare_files(file1, file2):
    """Compares the content of two text files and returns True if they are the same"""
    with open(file1, "r") as f1, open(file2, "r") as f2:
        content1 = f1.read()
        content2 = f2.read()
        return content1 == content2

# Example usage: compare two files named "file1.txt" and "file2.txt"
if compare_files("file1.txt", "file2.txt"):
    print("The files have the same content.")
else:
    print("The files have different content.")
