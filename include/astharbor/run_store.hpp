#pragma once
#include "astharbor/result.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <llvm/Support/JSON.h>
#include <optional>
#include <string>

namespace astharbor {

/// Persistence layer for analysis runs so that `astharbor fix --run-id` can
/// operate on a previously captured analysis without re-running Clang.
class RunStore {
  public:
    /// Default on-disk location: `$HOME/.astharbor/runs/`
    static std::filesystem::path defaultDirectory() {
        const char *home = std::getenv("HOME");
        if (home == nullptr) {
            return std::filesystem::temp_directory_path() / "astharbor" / "runs";
        }
        return std::filesystem::path(home) / ".astharbor" / "runs";
    }

    /// Build the default path for a run with the given id.
    static std::filesystem::path defaultPathFor(const std::string &runId) {
        return defaultDirectory() / (runId + ".json");
    }

    /// Serialize the result as llvm::json and write it to the given path.
    /// Returns true on success, false on filesystem or IO failure.
    static bool save(const AnalysisResult &result, const std::filesystem::path &path) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return false;
        }
        std::ofstream out(path);
        if (!out) {
            return false;
        }
        out << toJson(result);
        return static_cast<bool>(out);
    }

    /// Load a previously saved run from disk. Returns nullopt on parse or IO
    /// failure.
    static std::optional<AnalysisResult> load(const std::filesystem::path &path) {
        std::ifstream in(path);
        if (!in) {
            return std::nullopt;
        }
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        auto parsed = llvm::json::parse(content);
        if (!parsed) {
            llvm::consumeError(parsed.takeError());
            return std::nullopt;
        }
        const llvm::json::Object *object = parsed->getAsObject();
        if (object == nullptr) {
            return std::nullopt;
        }
        return fromJson(*object);
    }

  private:
    static std::string toJson(const AnalysisResult &result) {
        llvm::json::Array findingsArray;
        for (const auto &finding : result.findings) {
            llvm::json::Array fixesArray;
            for (const auto &fix : finding.fixes) {
                fixesArray.push_back(llvm::json::Object{
                    {"fixId", fix.fixId},
                    {"description", fix.description},
                    {"safety", fix.safety},
                    {"replacementText", fix.replacementText},
                    {"offset", fix.offset},
                    {"length", fix.length},
                });
            }
            findingsArray.push_back(llvm::json::Object{
                {"findingId", finding.findingId},
                {"ruleId", finding.ruleId},
                {"severity", finding.severity},
                {"category", finding.category},
                {"message", finding.message},
                {"file", finding.file},
                {"line", finding.line},
                {"column", finding.column},
                {"fixes", std::move(fixesArray)},
            });
        }
        llvm::json::Object hashes;
        for (const auto &[path, hash] : result.fileHashes) {
            hashes[path] = hash;
        }
        llvm::json::Object dependencies;
        for (const auto &[sourcePath, deps] : result.dependencies) {
            llvm::json::Array depsArray;
            for (const auto &dep : deps) {
                depsArray.push_back(dep);
            }
            dependencies[sourcePath] = std::move(depsArray);
        }
        llvm::json::Object root{
            {"runId", result.runId},
            {"success", result.success},
            {"findings", std::move(findingsArray)},
            {"fileHashes", std::move(hashes)},
            {"dependencies", std::move(dependencies)},
        };
        std::string output;
        llvm::raw_string_ostream stream(output);
        stream << llvm::formatv("{0:2}", llvm::json::Value(std::move(root)));
        stream.flush();
        return output;
    }

    static AnalysisResult fromJson(const llvm::json::Object &object) {
        AnalysisResult result;
        if (auto runId = object.getString("runId")) {
            result.runId = runId->str();
        }
        if (auto success = object.getBoolean("success")) {
            result.success = *success;
        }
        if (const auto *findingsArray = object.getArray("findings")) {
            for (const auto &value : *findingsArray) {
                const llvm::json::Object *findingObj = value.getAsObject();
                if (findingObj == nullptr) {
                    continue;
                }
                Finding finding;
                if (auto field = findingObj->getString("findingId")) {
                    finding.findingId = field->str();
                }
                if (auto field = findingObj->getString("ruleId")) {
                    finding.ruleId = field->str();
                }
                if (auto field = findingObj->getString("severity")) {
                    finding.severity = field->str();
                }
                if (auto field = findingObj->getString("category")) {
                    finding.category = field->str();
                }
                if (auto field = findingObj->getString("message")) {
                    finding.message = field->str();
                }
                if (auto field = findingObj->getString("file")) {
                    finding.file = field->str();
                }
                if (auto field = findingObj->getInteger("line")) {
                    finding.line = static_cast<int>(*field);
                }
                if (auto field = findingObj->getInteger("column")) {
                    finding.column = static_cast<int>(*field);
                }
                if (const auto *fixesArray = findingObj->getArray("fixes")) {
                    for (const auto &fixValue : *fixesArray) {
                        const llvm::json::Object *fixObj = fixValue.getAsObject();
                        if (fixObj == nullptr) {
                            continue;
                        }
                        Fix fix;
                        if (auto field = fixObj->getString("fixId")) {
                            fix.fixId = field->str();
                        }
                        if (auto field = fixObj->getString("description")) {
                            fix.description = field->str();
                        }
                        if (auto field = fixObj->getString("safety")) {
                            fix.safety = field->str();
                        }
                        if (auto field = fixObj->getString("replacementText")) {
                            fix.replacementText = field->str();
                        }
                        if (auto field = fixObj->getInteger("offset")) {
                            fix.offset = static_cast<int>(*field);
                        }
                        if (auto field = fixObj->getInteger("length")) {
                            fix.length = static_cast<int>(*field);
                        }
                        finding.fixes.push_back(std::move(fix));
                    }
                }
                result.findings.push_back(std::move(finding));
            }
        }
        if (const auto *hashObj = object.getObject("fileHashes")) {
            for (const auto &entry : *hashObj) {
                if (auto value = entry.getSecond().getAsString()) {
                    result.fileHashes[entry.getFirst().str()] = value->str();
                }
            }
        }
        if (const auto *depsObj = object.getObject("dependencies")) {
            for (const auto &entry : *depsObj) {
                const llvm::json::Array *depsArray = entry.getSecond().getAsArray();
                if (depsArray == nullptr) {
                    continue;
                }
                std::vector<std::string> depsList;
                depsList.reserve(depsArray->size());
                for (const auto &depValue : *depsArray) {
                    if (auto depString = depValue.getAsString()) {
                        depsList.push_back(depString->str());
                    }
                }
                result.dependencies[entry.getFirst().str()] = std::move(depsList);
            }
        }
        return result;
    }
};

} // namespace astharbor
