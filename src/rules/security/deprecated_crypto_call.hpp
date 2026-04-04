#pragma once
#include "astharbor/rule.hpp"

namespace astharbor {
class SecurityDeprecatedCryptoCallRule : public Rule {
  public:
    std::string id() const override { return "security/deprecated-crypto-call"; }
    std::string title() const override { return "Deprecated crypto call"; }
    std::string category() const override { return "security"; }
    std::string summary() const override {
        return "Detects calls to known-weak cryptographic functions such as MD5, SHA1, RC4, and DES.";
    }
    std::string defaultSeverity() const override { return "warning"; }

    void registerMatchers(clang::ast_matchers::MatchFinder &Finder) override {
        using namespace clang::ast_matchers;
        Finder.addMatcher(
            callExpr(callee(functionDecl(hasAnyName(
                         "MD5", "MD5_Init", "MD5_Update", "MD5_Final",
                         "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
                         "RC4", "RC4_set_key",
                         "DES_ecb_encrypt", "DES_set_key",
                         "EVP_md5", "EVP_sha1"))))
                .bind("crypto_call"),
            this);
    }

    void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
        const auto *Call = Result.Nodes.getNodeAs<clang::CallExpr>("crypto_call");
        if (Call == nullptr || Result.SourceManager == nullptr) {
            return;
        }

        const auto *Callee = Call->getDirectCallee();
        if (Callee == nullptr) {
            return;
        }

        auto &sourceManager = *Result.SourceManager;
        const std::string FunctionName = Callee->getName().str();

        Finding finding;
        finding.ruleId = id();
        finding.message = FunctionName +
                          "() uses a weak or broken cryptographic algorithm (CWE-327) — use a modern alternative (SHA-256+, AES, etc.)";
        finding.severity = defaultSeverity();
        finding.category = category();
        finding.file = sourceManager.getFilename(Call->getExprLoc()).str();
        finding.line = sourceManager.getSpellingLineNumber(Call->getExprLoc());
        finding.column = sourceManager.getSpellingColumnNumber(Call->getExprLoc());

        if (!finding.file.empty()) {
            findings.push_back(finding);
        }
    }
};
} // namespace astharbor
