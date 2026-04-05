#pragma once
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Basic/FileEntry.h>
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
    IncludeTrackingCallbacks(std::set<std::string> &deps,
                              std::map<std::string, std::string> &fileAliases)
        : deps(deps), fileAliases(fileAliases) {}

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
        std::string realPath = File->getFileEntry().tryGetRealPathName().str();
        std::string name = File->getName().str();
        // Record the short-name → real-path mapping so finding-path
        // post-processing can normalize `./lib.hpp`-style strings that
        // rules pick up via `SourceManager::getFilename`.
        if (!realPath.empty() && !name.empty() && realPath != name) {
            fileAliases[name] = realPath;
        }
        std::string path = !realPath.empty() ? realPath : name;
        if (!path.empty()) {
            deps.insert(std::move(path));
        }
    }

  private:
    std::set<std::string> &deps;
    std::map<std::string, std::string> &fileAliases;
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
        std::map<std::string, std::vector<std::string>> *depsByFile,
        std::map<std::string, std::string> *fileAliases)
        : finder(finder), depsByFile(depsByFile), fileAliases(fileAliases) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance &compilerInstance,
                      llvm::StringRef file) override {
        currentFile = file.str();
        currentDeps.clear();
        compilerInstance.getPreprocessor().addPPCallbacks(
            std::make_unique<IncludeTrackingCallbacks>(currentDeps, *fileAliases));
        return finder->newASTConsumer();
    }

    void EndSourceFileAction() override {
        auto *ci = &getCompilerInstance();
        std::string key = currentFile;
        if (ci->hasSourceManager()) {
            auto &sourceManager = ci->getSourceManager();
            // Resolve the main file's real path so the dependency-map
            // key matches the absolute paths used elsewhere (notably
            // the `--incremental` hash map). Also seed the alias map
            // with every short-name Clang saw for the main file so
            // finding paths can be normalized after tool.run().
            if (auto mainFile =
                    sourceManager.getFileEntryRefForID(sourceManager.getMainFileID())) {
                std::string realPath =
                    mainFile->getFileEntry().tryGetRealPathName().str();
                std::string name = mainFile->getName().str();
                if (!realPath.empty()) {
                    key = realPath;
                    if (fileAliases != nullptr && !name.empty() && name != realPath) {
                        (*fileAliases)[name] = realPath;
                    }
                }
            }
        }
        if (depsByFile != nullptr && !key.empty()) {
            std::vector<std::string> sortedDeps(currentDeps.begin(), currentDeps.end());
            (*depsByFile)[key] = std::move(sortedDeps);
        }
        ASTFrontendAction::EndSourceFileAction();
    }

  private:
    clang::ast_matchers::MatchFinder *finder;
    std::map<std::string, std::vector<std::string>> *depsByFile;
    std::map<std::string, std::string> *fileAliases;
    std::string currentFile;
    std::set<std::string> currentDeps;
};

/// Factory producing fresh `MatchFinderWithDepsAction` instances sharing
/// the same MatchFinder, dependency accumulator, and file-alias map.
/// ClangTool calls `create()` once per source file.
class MatchFinderWithDepsFactory : public clang::tooling::FrontendActionFactory {
  public:
    MatchFinderWithDepsFactory(
        clang::ast_matchers::MatchFinder *finder,
        std::map<std::string, std::vector<std::string>> *depsByFile,
        std::map<std::string, std::string> *fileAliases)
        : finder(finder), depsByFile(depsByFile), fileAliases(fileAliases) {}

    std::unique_ptr<clang::FrontendAction> create() override {
        return std::make_unique<MatchFinderWithDepsAction>(finder, depsByFile,
                                                            fileAliases);
    }

  private:
    clang::ast_matchers::MatchFinder *finder;
    std::map<std::string, std::vector<std::string>> *depsByFile;
    std::map<std::string, std::string> *fileAliases;
};

} // namespace astharbor
