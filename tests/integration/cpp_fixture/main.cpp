// Integration fixture: a small C++ project that intentionally triggers
// multiple ASTHarbor rules across different categories. Every issue below
// corresponds to a rule expected to fire in the integration test suite.

#define NULL 0

typedef int MyInt; // readability/use-using-alias

class Base {
  public:
    virtual void draw();
    ~Base() {} // ub/delete-non-virtual-dtor when deleted polymorphically
};

class Derived : public Base {
  public:
    void draw(); // modernize/use-override
};

class Widget {
  public:
    Widget(int value); // best-practice/explicit-single-arg-ctor
};

int divide_by_zero(int value) {
    return value / 0; // ub/division-by-zero-literal
}

int null_cast_example() {
    int *pointer = NULL; // modernize/use-nullptr
    return pointer == 0 ? 1 : 0;
}

int oob_access() {
    int array[10];
    return array[15]; // ub/static-array-oob-constant
}

void raw_ownership() {
    int *block = new int[5]; // best-practice/no-raw-new-delete + array form
    delete block;            // ub/new-delete-array-mismatch (safe autofix)
}

int main() {
    Derived instance;
    instance.draw();
    return oob_access() + divide_by_zero(null_cast_example());
}
