#pragma once
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Lex/PPCallbacks.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Tooling/Tooling.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace astharbor {

/// PPCallbacks hook that records every user-header `#include` the
/// preprocessor resolves. System headers are skipped because they change
/// with the toolchain version, not with user edits, and tracking them
/// would force every incremental run to re-analyze everything whenever
/// a platform SDK was updated.
class IncludeTrackingCallbacks : public clang::PPCallbacks {
  public:
    explicit IncludeTrackingCallbacks(std::set<std::string> &deps) : deps(deps) {}

    void InclusionDirective(clang::SourceLocation /*HashLoc*/,
                             const clang::Token & /*IncludeTok*/,
                             llvm::StringRef /*FileName*/, bool /*IsAngled*/,
                             clang::CharSourceRange /*FilenameRange*/,
                             clang::OptionalFileEntryRef File,
                             llvm::StringRef /*SearchPath*/,
                             llvm::StringRef /*RelativePath*/,
                             const clang::Module * /*SuggestedModule*/,
                             bool /*ModuleImported*/,
                             clang::SrcMgr::CharacteristicKind FileType) override {
        if (!File) {
            return;
        }
        if (FileType != clang::SrcMgr::C_User) {
            return;
        }
        std::string path = File->getFileEntry().tryGetRealPathName().str();
        if (path.empty()) {
            path = File->getName().str();
        }
        deps.insert(std::move(path));
    }

  private:
    std::set<std::string> &deps;
};

/// Wrapping FrontendAction that delegates its ASTConsumer to a shared
/// MatchFinder (so existing rule matchers run unchanged) and additionally
/// installs `IncludeTrackingCallbacks` on the preprocessor. On end-of-file
/// it stashes the collected dependency set into a per-source map the
/// caller can consume after `ClangTool::run` returns.
class MatchFinderWithDepsAction : public clang::ASTFrontendAction {
  public:
    MatchFinderWithDepsAction(
        clang::ast_matchers::MatchFinder *finder,
        std::map<std::string, std::vector<std::string>> *depsByFile)
        : finder(finder), depsByFile(depsByFile) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance &compilerInstance,
                      llvm::StringRef file) override {
        currentFile = file.str();
        currentDeps.clear();
        compilerInstance.getPreprocessor().addPPCallbacks(
            std::make_unique<IncludeTrackingCallbacks>(currentDeps));
        return finder->newASTConsumer();
    }

    void EndSourceFileAction() override {
        if (depsByFile != nullptr) {
            // Prefer the SourceManager's resolved main-file path so the
            // key matches the absolute paths used elsewhere in the
            // analysis pipeline (the `--incremental` hash map in
            // particular). If the file entry isn't available, fall back
            // to whatever the tooling layer handed us.
            std::string key = currentFile;
            if (auto *ci = &getCompilerInstance(); ci->hasSourceManager()) {
                auto &sourceManager = ci->getSourceManager();
                if (auto mainFile =
                        sourceManager.getFileEntryRefForID(sourceManager.getMainFileID())) {
                    std::string realPath =
                        mainFile->getFileEntry().tryGetRealPathName().str();
                    if (!realPath.empty()) {
                        key = std::move(realPath);
                    }
                }
            }
            if (!key.empty()) {
                std::vector<std::string> sortedDeps(currentDeps.begin(), currentDeps.end());
                (*depsByFile)[key] = std::move(sortedDeps);
            }
        }
        ASTFrontendAction::EndSourceFileAction();
    }

  private:
    clang::ast_matchers::MatchFinder *finder;
    std::map<std::string, std::vector<std::string>> *depsByFile;
    std::string currentFile;
    std::set<std::string> currentDeps;
};

/// Factory producing fresh `MatchFinderWithDepsAction` instances sharing
/// the same MatchFinder and dependency accumulator. ClangTool calls
/// `create()` once per source file.
class MatchFinderWithDepsFactory : public clang::tooling::FrontendActionFactory {
  public:
    MatchFinderWithDepsFactory(
        clang::ast_matchers::MatchFinder *finder,
        std::map<std::string, std::vector<std::string>> *depsByFile)
        : finder(finder), depsByFile(depsByFile) {}

    std::unique_ptr<clang::FrontendAction> create() override {
        return std::make_unique<MatchFinderWithDepsAction>(finder, depsByFile);
    }

  private:
    clang::ast_matchers::MatchFinder *finder;
    std::map<std::string, std::vector<std::string>> *depsByFile;
};

} // namespace astharbor
