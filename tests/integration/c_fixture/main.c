/* Integration fixture: a small C project that intentionally triggers
 * several C-applicable ASTHarbor rules. The Python integration suite
 * asserts each rule fires. Declarations are manual so the fixture builds
 * without system headers (keeps the test hermetic).
 */

typedef unsigned long size_t;

extern char *gets(char *s);
extern char *strcpy(char *dst, const char *src);
extern int atoi(const char *s);

void unsafe_copy(const char *source) {
    char buffer[32];
    strcpy(buffer, source); /* security/no-strcpy-strcat */
}

int parse_input(const char *text) { return atoi(text); /* security/no-atoi-atol-atof */ }

int divide(int value) { return value / 0; /* ub/division-by-zero-literal */ }

int main(void) {
    char line[16];
    gets(line); /* security/no-gets */
    unsafe_copy(line);
    return parse_input(line) + divide(1);
}
