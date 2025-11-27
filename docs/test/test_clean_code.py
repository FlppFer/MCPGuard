"""
Test script with CLEAN code - should generate NO security findings
This is used as a control test to verify false positive rate
"""
import json
import logging

def safe_function(data: str) -> str:
    """A completely safe function that processes data"""
    return data.strip().upper()

def safe_file_read(filename: str) -> str:
    """Safe file reading with proper handling"""
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def safe_json_parse(text: str) -> dict:
    """Safe JSON parsing"""
    return json.loads(text)

def safe_logging(message: str) -> None:
    """Safe logging without sensitive data"""
    logging.info("Processing: %s", message[:50])

def safe_calculation(a: int, b: int) -> int:
    """Safe arithmetic operation"""
    return a + b

def safe_list_processing(items: list) -> list:
    """Safe list processing"""
    return [item.strip() for item in items if item]

class SafeClass:
    """A safe class with no vulnerabilities"""
    
    def __init__(self, name: str):
        self.name = name
    
    def greet(self) -> str:
        return f"Hello, {self.name}!"
    
    def process(self, data: list) -> list:
        return sorted(data)

def main():
    """Main function - safe entry point"""
    processor = SafeClass("User")
    print(processor.greet())
    
    result = safe_calculation(10, 20)
    print(f"Result: {result}")

if __name__ == "__main__":
    main()
