class TestClass:
    def method1(self) -> list:
        results = []
        for i in range(3):
            results.append(i)
        return results
    
    def method2(self) -> list:
        return []

print("Syntax OK")