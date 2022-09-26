#include <list>

class TokenScanner {
private:
    ~TokenScanner() = default;

public:
    static std::list<std::string> scanForTokens();

    TokenScanner() = default;
};

