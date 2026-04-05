#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <string>
#include <sys/wait.h>
#include <tuple>
#include <vector>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <cstdint>
#include <llvm/Support/xxhash.h>
#include "astharbor/rule_registry.hpp"
#include "astharbor/analyzer.hpp"
#include "astharbor/config.hpp"
#include "astharbor/fix_applicator.hpp"
#include "astharbor/run_store.hpp"
#include "dependency_collector.hpp"
#include "../emitters/json_emitter.hpp"
#include "../emitters/text_emitter.hpp"
#include "../emitters/sarif_emitter.hpp"
#include "llvm/Support/CommandLine.h"

using namespace clang::tooling;
using namespace astharbor;

static llvm::cl::OptionCategory ASTHarborCategory("astharbor options");

static llvm::cl::opt<std::string> Format("format",
                                         llvm::cl::desc("Output format (text, json, sarif)"),
                                         llvm::cl::init("text"), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool> Apply("apply", llvm::cl::desc("Apply safe fixes"),
                                 llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool> DryRun("dry-run", llvm::cl::desc("Preview fixes without applying"),
                                   llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string> RuleFilter("rule", llvm::cl::desc("Filter by rule ID pattern"),
                                              llvm::cl::init(""),
                                              llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool> Backup("backup",
                                   llvm::cl::desc("Create .bak backup before applying fixes"),
                                   llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool>
    AllSafe("all-safe",
            llvm::cl::desc("Discoverable alias for `--apply` that applies every safe fix "
                           "across the analyzed source set and reports a per-rule breakdown."),
            llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool>
    Verify("verify",
           llvm::cl::desc("After applying fixes, run `clang++ -fsyntax-only` on each "
                          "modified file. If any file fails to parse, restore its original "
                          "content from an in-memory snapshot."),
           llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    SaveRun("save-run",
            llvm::cl::desc("Persist the analysis result to disk for later "
                           "`fix --run-id`. Optionally takes a path; defaults "
                           "to ~/.astharbor/runs/<runId>.json"),
            llvm::cl::init(""), llvm::cl::ValueOptional, llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    RunId("run-id", llvm::cl::desc("Load a previously saved run by id"),
          llvm::cl::init(""), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    FindingId("finding-id",
              llvm::cl::desc("Restrict fix to a single finding id from the loaded run"),
              llvm::cl::init(""), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    Checks("checks",
           llvm::cl::desc("Comma-separated substring patterns; only rules whose id "
                          "contains any pattern are enabled. Prefix a pattern with "
                          "'-' to disable matching rules instead."),
           llvm::cl::init(""), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool>
    Verbose("verbose",
            llvm::cl::desc("Print per-file progress, active rule count, and timing to stderr"),
            llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    Std("std",
        llvm::cl::desc("Language standard to use in single-file mode, e.g. c++20, c17"),
        llvm::cl::init(""), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    CompilerProfile("compiler-profile",
                    llvm::cl::desc("Compiler dialect profile: auto (default), clang, or gcc"),
                    llvm::cl::init("auto"), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<unsigned>
    Jobs("jobs",
         llvm::cl::desc("Number of parallel analysis workers (default: 1). Each worker owns a "
                        "fresh RuleRegistry and ClangTool; findings are merged deterministically."),
         llvm::cl::init(1), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool>
    ChangedOnly("changed-only",
                llvm::cl::desc("Only analyze files reported as modified by `git diff`."),
                llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<std::string>
    CompareCompilers("compare-compilers",
                     llvm::cl::desc("Comma-separated list of compilers for `astharbor "
                                    "compare`. Defaults to 'clang++,g++'. Each compiler is "
                                    "invoked with -fsyntax-only -Wall -Wextra via popen."),
                     llvm::cl::init(""), llvm::cl::cat(ASTHarborCategory));

static llvm::cl::opt<bool>
    Incremental("incremental",
                llvm::cl::desc("Skip files whose content hash matches the most recent "
                               "saved run for this source set. Requires a prior run with "
                               "--save-run."),
                llvm::cl::init(false), llvm::cl::cat(ASTHarborCategory));

// Project config discovered from .astharbor.yml. CLI option values are
// merged from this struct after setupParser() has populated the cl::opts,
// so explicit CLI flags always win and config-provided values fill in
// gaps only.
static Config projectConfig; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void applyConfigDefaults() {
    auto applyConfigString = [](llvm::cl::opt<std::string> &option,
                                 const std::string &value) {
        if (!value.empty() && option.getNumOccurrences() == 0) {
            option = value;
        }
    };
    applyConfigString(Checks, projectConfig.checks);
    applyConfigString(Std, projectConfig.std);
    applyConfigString(CompilerProfile, projectConfig.compilerProfile);
    if (projectConfig.jobs > 0 && Jobs.getNumOccurrences() == 0) {
        Jobs = projectConfig.jobs;
    }
}

void print_help() {
    std::cout << "ASTHarbor CLI\n";
    std::cout << "Commands:\n";
    std::cout << "  analyze <files...>  Analyze C/C++ source files\n";
    std::cout << "  fix <files...>      Preview or apply fixes\n";
    std::cout << "  rules               List available rules\n";
    std::cout << "  doctor              Check toolchain health\n";
    std::cout << "  compare <file>      Compare clang vs gcc diagnostics on a file\n";
    std::cout << "  explain <rule-id>   Show full metadata for a rule\n";
    std::cout << "  init                Scaffold .astharbor.yml in the current directory\n";
    std::cout << "\nAnalyze options:\n";
    std::cout << "  --checks=PATTERNS   Comma-separated rule-id substrings to enable;\n";
    std::cout << "                      prefix a pattern with '-' to disable matching rules\n";
    std::cout << "  --save-run[=PATH]   Persist result to ~/.astharbor/runs/<runId>.json or\n";
    std::cout << "                      to PATH for later `fix --run-id`\n";
    std::cout << "  --verbose           Print progress and timing to stderr\n";
    std::cout << "  --std=VALUE         Language standard in single-file mode (e.g. c++20)\n";
    std::cout << "  --compiler-profile=P  Compiler dialect: auto (default), clang, or gcc\n";
    std::cout << "  --jobs=N            Run analysis across N parallel workers\n";
    std::cout << "  --changed-only      Only analyze files modified per `git diff`\n";
    std::cout << "\nFix options:\n";
    std::cout << "  --apply             Apply safe fixes (default: preview only)\n";
    std::cout << "  --dry-run           Preview fixes without applying\n";
    std::cout << "  --rule=PATTERN      Only process fixes for matching rule IDs\n";
    std::cout << "  --run-id=ID         Load a previously saved run instead of re-analyzing\n";
    std::cout << "  --finding-id=ID     Apply fix only for a specific finding id\n";
    std::cout << "  --backup            Create .bak backup files before modifying\n";
    std::cout << "  --all-safe          Apply every safe fix (alias for --apply) with summary\n";
    std::cout << "  --verify            Run clang++ -fsyntax-only after apply; roll back on failure\n";
    std::cout << "\nCommon options:\n";
    std::cout << "  --format=FORMAT     Output format: text, json, sarif\n";
}

/// Parse a `--checks` pattern string into (positive, negative) substring lists.
/// Patterns are comma-separated; a leading '-' marks a negative pattern.
static std::pair<std::vector<std::string>, std::vector<std::string>>
parseChecksPattern(const std::string &input) {
    std::vector<std::string> positive;
    std::vector<std::string> negative;
    size_t start = 0;
    while (start <= input.size()) {
        size_t comma = input.find(',', start);
        std::string token = input.substr(start, comma == std::string::npos
                                                    ? std::string::npos
                                                    : comma - start);
        if (!token.empty()) {
            if (token.front() == '-') {
                if (token.size() > 1) {
                    negative.push_back(token.substr(1));
                }
            } else {
                positive.push_back(std::move(token));
            }
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return {std::move(positive), std::move(negative)};
}

/// Return true if the rule with the given id should be enabled given the
/// parsed --checks patterns.
///
/// Patterns are matched against both the canonical ASTHarbor id (e.g.
/// `modernize/use-nullptr`) and the clang-tidy-style alias produced by
/// replacing '/' with '-' (e.g. `modernize-use-nullptr`). This lets users
/// migrating from clang-tidy keep their existing `.clang-tidy` Checks
/// strings mostly intact.
static bool ruleIsEnabled(const std::string &ruleId,
                          const std::vector<std::string> &positive,
                          const std::vector<std::string> &negative) {
    std::string aliasId = ruleId;
    std::replace(aliasId.begin(), aliasId.end(), '/', '-');
    auto matchesAny = [&](const std::vector<std::string> &patterns) {
        for (const auto &pattern : patterns) {
            if (ruleId.contains(pattern) || aliasId.contains(pattern)) {
                return true;
            }
        }
        return false;
    };

    bool enabled = positive.empty(); // start all-on iff no positive patterns
    if (!enabled && matchesAny(positive)) {
        enabled = true;
    }
    if (!enabled) {
        return false;
    }
    if (matchesAny(negative)) {
        return false;
    }
    return true;
}

/// Resolve a path to its canonical real-path form (following symlinks
/// and normalizing `..` segments). The dependency collector stores
/// paths resolved by Clang's SourceManager, which goes through the same
/// real-path resolution; using the canonical form everywhere is the
/// only way `--incremental` lookups can match both sides. Returns the
/// input unchanged on filesystem errors so callers don't have to
/// special-case missing files.
static std::string canonicalizePath(const std::string &path) {
    std::error_code ec;
    auto canonical = std::filesystem::canonical(path, ec);
    if (ec) {
        return path;
    }
    return canonical.string();
}

/// Compute a stable 64-bit content hash of a file as a lowercase hex
/// string. Uses LLVM's xxh3 (non-cryptographic but fast and stable across
/// runs on the same architecture). Returns empty string on IO failure.
static std::string hashFileContent(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    uint64_t hash = llvm::xxh3_64bits(content);
    char buffer[17];
    std::snprintf(buffer, sizeof(buffer), "%016llx",
                  static_cast<unsigned long long>(hash));
    return std::string(buffer);
}

/// Read a file's entire contents into a string. Returns nullopt on IO
/// failure so callers can distinguish "file missing" from "file empty".
static std::optional<std::string> readFileContent(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    return content;
}

/// Write `content` back to `path`. Returns true on success.
static bool writeFileContent(const std::string &path, const std::string &content) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }
    out << content;
    return static_cast<bool>(out);
}

/// Run `clang++ -fsyntax-only` on `path`. Returns true if the file parses
/// cleanly (exit code 0), false otherwise. Absence of clang++ on the host
/// is treated as "verification unavailable" — the caller can choose to
/// proceed. We use popen here for consistency with `compare`.
static bool syntaxCheckFile(const std::string &path) {
    std::string command = "clang++ -fsyntax-only -w \"" + path + "\" 2>/dev/null";
    FILE *pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return true;
    }
    // Drain stdout/stderr; we only care about exit code.
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    }
    int status = pclose(pipe);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/// Return the set of files reported as modified by `git diff --name-only`
/// (both uncommitted and staged changes). Returns nullopt if git is not
/// available or we are not inside a git repository.
static std::optional<std::vector<std::string>> gitChangedFiles() {
    std::vector<std::string> changed;
    auto capture = [&](const char *command) -> bool {
        FILE *pipe = popen(command, "r");
        if (pipe == nullptr) {
            return false;
        }
        char buffer[4096];
        while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string line = buffer;
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
                line.pop_back();
            }
            if (!line.empty()) {
                changed.push_back(line);
            }
        }
        int status = pclose(pipe);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    };
    if (!capture("git diff --name-only 2>/dev/null")) {
        return std::nullopt;
    }
    capture("git diff --cached --name-only 2>/dev/null");
    return changed;
}

/// Keep only paths whose absolute form or basename is present in `changed`.
/// The match is permissive on purpose — git reports paths relative to the
/// repo root, while ASTHarbor receives whatever the user passed on argv.
static std::vector<std::string>
filterByChangedFiles(const std::vector<std::string> &paths,
                     const std::vector<std::string> &changed) {
    std::vector<std::string> filtered;
    for (const auto &path : paths) {
        std::filesystem::path candidate(path);
        std::string basename = candidate.filename().string();
        for (const auto &changedPath : changed) {
            std::filesystem::path changedFsPath(changedPath);
            if (changedFsPath.filename().string() == basename) {
                filtered.push_back(path);
                break;
            }
        }
    }
    return filtered;
}

/// Apply --std and --compiler-profile adjusters to a ClangTool.
static void applyCompilerAdjusters(ClangTool &tool) {
    if (!Std.getValue().empty()) {
        tool.appendArgumentsAdjuster(getInsertArgumentAdjuster(
            ("-std=" + Std.getValue()).c_str(), ArgumentInsertPosition::BEGIN));
    }
    const std::string profile = CompilerProfile.getValue();
    if (profile == "gcc") {
        tool.appendArgumentsAdjuster(
            getInsertArgumentAdjuster("-fgnu-keywords", ArgumentInsertPosition::BEGIN));
        tool.appendArgumentsAdjuster(
            getInsertArgumentAdjuster("-fgnu89-inline", ArgumentInsertPosition::BEGIN));
    } else if (profile != "auto" && profile != "clang") {
        llvm::errs() << "Warning: unknown --compiler-profile '" << profile
                     << "', falling back to auto\n";
    }
}

/// Result of running the analyzer on a chunk of source files.
struct AnalysisChunkResult {
    std::vector<Finding> findings;
    int exitCode = 0;
    /// Per-source list of transitively-included user-header paths.
    std::map<std::string, std::vector<std::string>> dependencies;
    /// Content hashes of header files discovered during dep collection.
    /// Computed inside the worker so the hashing I/O runs in parallel
    /// with other workers rather than serially on the main thread after
    /// the join. Duplicates across workers are tolerated — the merge
    /// step on the main thread deduplicates by path and the values
    /// agree because they hash the same file content.
    std::map<std::string, std::string> depHashes;
};

/// Run analysis on a single chunk of source files with a fresh RuleRegistry.
/// Used as the per-worker function for parallel analysis; the sequential
/// path just calls it once with all sources.
static AnalysisChunkResult
runAnalysisChunk(const std::vector<std::string> &chunkPaths,
                 CompilationDatabase &compilationDb,
                 const std::vector<std::string> &positivePatterns,
                 const std::vector<std::string> &negativePatterns) {
    RuleRegistry registry;
    registerBuiltinRules(registry);

    ClangTool tool(compilationDb, chunkPaths);
    applyCompilerAdjusters(tool);

    std::vector<const Rule *> activeRules;
    clang::ast_matchers::MatchFinder finder;
    for (const auto &rule : registry.getRules()) {
        if (!ruleIsEnabled(rule->id(), positivePatterns, negativePatterns)) {
            continue;
        }
        rule->registerMatchers(finder);
        activeRules.push_back(rule.get());
    }

    std::map<std::string, std::vector<std::string>> dependencies;
    MatchFinderWithDepsFactory factory(&finder, &dependencies);
    int toolExitCode = tool.run(&factory);

    std::vector<Finding> findings;
    for (const Rule *rule : activeRules) {
        auto ruleFindings = rule->getFindings();
        findings.insert(findings.end(), ruleFindings.begin(), ruleFindings.end());
    }

    // Hash every unique header dep discovered by this worker. Running
    // here (inside the std::async worker) lets the I/O overlap with
    // other workers' Clang invocations; the old path did this on the
    // main thread after the join and was a visible serial bottleneck
    // on large codebases with many shared headers.
    std::map<std::string, std::string> depHashes;
    for (const auto &[sourcePath, deps] : dependencies) {
        for (const auto &depPath : deps) {
            if (depHashes.count(depPath) > 0) {
                continue;
            }
            auto hash = hashFileContent(depPath);
            if (!hash.empty()) {
                depHashes[depPath] = std::move(hash);
            }
        }
    }
    return {std::move(findings), toolExitCode, std::move(dependencies),
            std::move(depHashes)};
}

/// Set up CommonOptionsParser from argv (skipping the subcommand).
static std::optional<CommonOptionsParser> setupParser(int argc, const char **argv) {
    std::vector<const char *> args;
    args.push_back(argv[0]);
    for (int index = 2; index < argc; ++index) {
        args.push_back(argv[index]);
    }
    int newArgc = static_cast<int>(args.size());

    auto expectedParser =
        CommonOptionsParser::create(newArgc, args.data(), ASTHarborCategory, llvm::cl::ZeroOrMore);
    if (!expectedParser) {
        llvm::errs() << expectedParser.takeError();
        return std::nullopt;
    }
    return std::move(*expectedParser);
}

/// Run analysis and return findings. Honors --jobs, --changed-only, --checks,
/// --std, --compiler-profile, --verbose.
static std::pair<AnalysisResult, int> runAnalysis(CommonOptionsParser &parser,
                                                   const RuleRegistry &registry) {
    const bool verbose = Verbose.getValue();
    std::vector<std::string> sourcePaths = parser.getSourcePathList();
    CompilationDatabase &compilationDb = parser.getCompilations();

    if (sourcePaths.empty()) {
        sourcePaths = compilationDb.getAllFiles();
        if (sourcePaths.empty()) {
            llvm::errs()
                << "Error: No source files specified and could not find any in the compilation database.\n";
            return {{}, 2};
        }
        if (verbose) {
            llvm::errs() << "[verbose] Auto-discovered " << sourcePaths.size()
                         << " source files from compilation database\n";
        }
    }

    // Incremental mode: hash each source file and compare against the
    // most recent saved run. Files whose hash matches AND whose
    // transitively-included user headers all still hash to their prior
    // values are skipped and their findings carried forward from the
    // prior run. Otherwise the TU is re-analyzed.
    std::vector<Finding> carriedFindings;
    std::map<std::string, std::string> currentHashes;
    std::map<std::string, std::vector<std::string>> carriedDependencies;
    const bool incrementalMode = Incremental.getValue();
    if (incrementalMode) {
        // Canonicalize source paths up-front so the hash-map keys match
        // the real-path form the dependency collector writes out of the
        // Clang SourceManager. Without this, a relative path on the CLI
        // and an absolute path in the saved run would never compare
        // equal and incremental would silently re-analyze everything.
        for (auto &path : sourcePaths) {
            path = canonicalizePath(path);
        }
        for (const auto &path : sourcePaths) {
            currentHashes[path] = hashFileContent(path);
        }
        // Find the newest run file in the default directory.
        auto runsDir = RunStore::defaultDirectory();
        std::error_code ec;
        std::optional<std::filesystem::path> newestPath;
        std::filesystem::file_time_type newestTime{};
        if (std::filesystem::exists(runsDir, ec) && !ec) {
            for (auto &entry : std::filesystem::directory_iterator(runsDir, ec)) {
                if (ec) {
                    break;
                }
                if (!entry.is_regular_file() || entry.path().extension() != ".json") {
                    continue;
                }
                auto mtime = entry.last_write_time(ec);
                if (ec) {
                    continue;
                }
                if (!newestPath || mtime > newestTime) {
                    newestPath = entry.path();
                    newestTime = mtime;
                }
            }
        }
        if (newestPath) {
            if (auto priorRun = RunStore::load(*newestPath)) {
                // Cache of current-on-disk hashes for dependency files, so
                // several TUs sharing a common header only hash it once.
                std::map<std::string, std::string> currentDepHashes;
                auto currentHashOf = [&](const std::string &path) -> std::string {
                    auto sourceIt = currentHashes.find(path);
                    if (sourceIt != currentHashes.end()) {
                        return sourceIt->second;
                    }
                    auto depIt = currentDepHashes.find(path);
                    if (depIt != currentDepHashes.end()) {
                        return depIt->second;
                    }
                    auto hash = hashFileContent(path);
                    currentDepHashes[path] = hash;
                    return hash;
                };

                std::set<std::string> unchangedFiles;
                size_t invalidatedByDep = 0;
                for (const auto &[path, currentHash] : currentHashes) {
                    if (currentHash.empty()) {
                        continue; // IO failure — re-analyze to be safe
                    }
                    auto sourceHashIt = priorRun->fileHashes.find(path);
                    if (sourceHashIt == priorRun->fileHashes.end() ||
                        sourceHashIt->second != currentHash) {
                        continue;
                    }
                    // Source matches; now check every recorded dependency.
                    // A missing dependency entry in the prior run means
                    // we have no dep info — fall back to same-file-only
                    // invalidation for that TU.
                    bool depsStable = true;
                    auto depsIt = priorRun->dependencies.find(path);
                    if (depsIt != priorRun->dependencies.end()) {
                        for (const auto &depPath : depsIt->second) {
                            auto priorDepHashIt = priorRun->fileHashes.find(depPath);
                            if (priorDepHashIt == priorRun->fileHashes.end()) {
                                depsStable = false;
                                break;
                            }
                            auto currentDepHash = currentHashOf(depPath);
                            if (currentDepHash.empty() ||
                                currentDepHash != priorDepHashIt->second) {
                                depsStable = false;
                                break;
                            }
                        }
                    }
                    if (!depsStable) {
                        ++invalidatedByDep;
                        continue;
                    }
                    unchangedFiles.insert(path);
                    // Preserve the prior dep list so the next incremental
                    // run still knows what to watch for this TU, even if
                    // we don't re-run the analyzer on it now.
                    if (depsIt != priorRun->dependencies.end()) {
                        carriedDependencies[path] = depsIt->second;
                    }
                }
                // Carry forward findings for unchanged files. Findings
                // may record their file path in whatever form Clang
                // reported it (often a short name relative to the
                // compile command's directory), so we also match on
                // basename against the canonical unchanged set. This
                // can alias distinct files that share a basename, but
                // the worst case is a false carry-forward that re-runs
                // correctly on the next invocation.
                std::set<std::string> unchangedBasenames;
                for (const auto &path : unchangedFiles) {
                    unchangedBasenames.insert(
                        std::filesystem::path(path).filename().string());
                }
                for (const auto &finding : priorRun->findings) {
                    if (unchangedFiles.count(finding.file) > 0 ||
                        unchangedBasenames.count(
                            std::filesystem::path(finding.file).filename().string()) > 0) {
                        carriedFindings.push_back(finding);
                    }
                }
                // Merge current dep hashes into the working hash set so
                // the next run has them even if we skipped every TU.
                for (auto &entry : currentDepHashes) {
                    if (!entry.second.empty()) {
                        currentHashes.emplace(entry.first, std::move(entry.second));
                    }
                }
                // Drop unchanged files from the source list.
                std::vector<std::string> remaining;
                remaining.reserve(sourcePaths.size());
                for (const auto &path : sourcePaths) {
                    if (unchangedFiles.count(path) == 0) {
                        remaining.push_back(path);
                    }
                }
                if (verbose) {
                    llvm::errs() << "[verbose] --incremental: " << unchangedFiles.size()
                                 << " of " << sourcePaths.size()
                                 << " file(s) unchanged; " << invalidatedByDep
                                 << " invalidated by header dep changes; carrying "
                                 << carriedFindings.size() << " finding(s) forward\n";
                }
                sourcePaths = std::move(remaining);
            }
        }
        if (sourcePaths.empty()) {
            // Everything was unchanged — emit a synthetic result with just
            // the carried findings and the current hashes.
            AnalysisResult result;
            result.runId = generateRunId();
            result.success = true;
            result.findings = std::move(carriedFindings);
            result.fileHashes = std::move(currentHashes);
            result.dependencies = std::move(carriedDependencies);
            assignFindingIds(result);
            if (verbose) {
                llvm::errs() << "[verbose] --incremental: nothing to re-analyze\n";
            }
            return {std::move(result), result.findings.empty() ? 0 : 1};
        }
    }

    if (ChangedOnly.getValue()) {
        auto changed = gitChangedFiles();
        if (!changed) {
            llvm::errs() << "Warning: --changed-only requested but git is not available "
                            "or the working directory is not a repository; analyzing all "
                            "files.\n";
        } else {
            auto filtered = filterByChangedFiles(sourcePaths, *changed);
            if (verbose) {
                llvm::errs() << "[verbose] --changed-only: " << filtered.size() << " of "
                             << sourcePaths.size() << " files match git-changed set\n";
            }
            sourcePaths = std::move(filtered);
            if (sourcePaths.empty()) {
                AnalysisResult emptyResult;
                emptyResult.runId = generateRunId();
                emptyResult.success = true;
                return {std::move(emptyResult), 0};
            }
        }
    }

    if (verbose) {
        llvm::errs() << "[verbose] Analyzing " << sourcePaths.size() << " file(s)\n";
        for (const auto &path : sourcePaths) {
            llvm::errs() << "[verbose]   " << path << "\n";
        }
    }

    auto [positivePatterns, negativePatterns] = parseChecksPattern(Checks.getValue());

    // Determine worker count. Single-file or --jobs=1 uses the sequential
    // path so we don't pay thread-startup overhead for tiny analyses.
    unsigned requestedJobs = std::max(1U, Jobs.getValue());
    unsigned workerCount =
        std::min<unsigned>(requestedJobs, static_cast<unsigned>(sourcePaths.size()));
    if (workerCount == 0) {
        workerCount = 1;
    }

    if (verbose && workerCount > 1) {
        llvm::errs() << "[verbose] Using " << workerCount << " parallel worker(s)\n";
    }

    auto startTime = std::chrono::steady_clock::now();
    std::vector<Finding> allFindings;
    std::map<std::string, std::vector<std::string>> collectedDependencies;
    std::map<std::string, std::string> collectedDepHashes;
    int worstExitCode = 0;

    if (workerCount == 1) {
        auto chunkResult = runAnalysisChunk(sourcePaths, compilationDb, positivePatterns,
                                             negativePatterns);
        allFindings = std::move(chunkResult.findings);
        worstExitCode = chunkResult.exitCode;
        collectedDependencies = std::move(chunkResult.dependencies);
        collectedDepHashes = std::move(chunkResult.depHashes);
    } else {
        // Partition sources into round-robin chunks so individual large TUs
        // are spread across workers rather than concentrated in one.
        std::vector<std::vector<std::string>> chunks(workerCount);
        for (size_t index = 0; index < sourcePaths.size(); ++index) {
            chunks[index % workerCount].push_back(sourcePaths[index]);
        }

        std::vector<std::future<AnalysisChunkResult>> futures;
        futures.reserve(chunks.size());
        for (auto &chunk : chunks) {
            if (chunk.empty()) {
                continue;
            }
            futures.push_back(std::async(std::launch::async, [&, chunk]() {
                return runAnalysisChunk(chunk, compilationDb, positivePatterns,
                                        negativePatterns);
            }));
        }
        for (auto &future : futures) {
            auto chunkResult = future.get();
            allFindings.insert(allFindings.end(),
                               std::make_move_iterator(chunkResult.findings.begin()),
                               std::make_move_iterator(chunkResult.findings.end()));
            for (auto &entry : chunkResult.dependencies) {
                collectedDependencies[entry.first] = std::move(entry.second);
            }
            for (auto &entry : chunkResult.depHashes) {
                collectedDepHashes.insert(std::move(entry));
            }
            if (chunkResult.exitCode > worstExitCode) {
                worstExitCode = chunkResult.exitCode;
            }
        }
        // Parallel execution can interleave findings from different workers;
        // sort deterministically so output order is stable.
        std::sort(allFindings.begin(), allFindings.end(),
                  [](const Finding &lhs, const Finding &rhs) {
                      return std::tie(lhs.file, lhs.line, lhs.column, lhs.ruleId) <
                             std::tie(rhs.file, rhs.line, rhs.column, rhs.ruleId);
                  });
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - startTime)
                       .count();

    // Apply .astharbor.yml HeaderFilterRegex if configured: only keep
    // findings whose file path matches the regex. Files in the explicit
    // source path list are always kept (the regex is intended for
    // transitively-included headers). An invalid regex is reported on
    // stderr and treated as "no filter".
    if (!projectConfig.headerFilterRegex.empty()) {
        try {
            std::regex filterRegex(projectConfig.headerFilterRegex);
            std::vector<std::string> absSources;
            absSources.reserve(sourcePaths.size());
            for (const auto &path : sourcePaths) {
                std::error_code ec;
                auto absolute = std::filesystem::absolute(path, ec);
                absSources.push_back(ec ? path : absolute.string());
            }
            auto isMainSource = [&](const std::string &file) {
                for (const auto &source : absSources) {
                    if (source == file) {
                        return true;
                    }
                }
                return false;
            };
            size_t beforeCount = allFindings.size();
            allFindings.erase(
                std::remove_if(allFindings.begin(), allFindings.end(),
                               [&](const Finding &finding) {
                                   if (isMainSource(finding.file)) {
                                       return false;
                                   }
                                   return !std::regex_search(finding.file, filterRegex);
                               }),
                allFindings.end());
            if (verbose) {
                llvm::errs() << "[verbose] HeaderFilterRegex filtered "
                             << (beforeCount - allFindings.size()) << " of " << beforeCount
                             << " finding(s)\n";
            }
        } catch (const std::regex_error &err) {
            llvm::errs() << "Warning: invalid HeaderFilterRegex in .astharbor.yml: "
                         << err.what() << "\n";
        }
    }

    // Apply .astharbor.yml Severity overrides. The config maps rule IDs to
    // alternate severity strings, escalating or demoting findings without
    // touching rule source.
    if (!projectConfig.severityOverrides.empty()) {
        for (auto &finding : allFindings) {
            auto it = projectConfig.severityOverrides.find(finding.ruleId);
            if (it != projectConfig.severityOverrides.end()) {
                finding.severity = it->second;
            }
        }
    }

    // Merge any incremental-carryover findings before assigning ids so
    // carried findings get stable ids within the new run.
    if (!carriedFindings.empty()) {
        allFindings.insert(allFindings.end(),
                           std::make_move_iterator(carriedFindings.begin()),
                           std::make_move_iterator(carriedFindings.end()));
        std::sort(allFindings.begin(), allFindings.end(),
                  [](const Finding &lhs, const Finding &rhs) {
                      return std::tie(lhs.file, lhs.line, lhs.column, lhs.ruleId) <
                             std::tie(rhs.file, rhs.line, rhs.column, rhs.ruleId);
                  });
    }

    AnalysisResult result;
    result.runId = generateRunId();
    result.success = (worstExitCode == 0);
    result.findings = std::move(allFindings);
    // Record the hashes of everything we just analyzed (or carried over)
    // so the next --incremental run can skip them. Header-dep hashes
    // come from the workers (see runAnalysisChunk), which compute them
    // in parallel with analysis — the main thread only has to merge.
    if (incrementalMode) {
        result.fileHashes = std::move(currentHashes);
        result.dependencies = std::move(carriedDependencies);
        for (auto &entry : collectedDependencies) {
            result.dependencies[entry.first] = std::move(entry.second);
        }
    } else {
        for (const auto &path : sourcePaths) {
            auto hash = hashFileContent(path);
            if (!hash.empty()) {
                result.fileHashes[path] = std::move(hash);
            }
        }
        result.dependencies = std::move(collectedDependencies);
    }
    // Merge dep hashes computed by workers. `insert` keeps any hash
    // already present in `fileHashes` — e.g., carried over from the
    // prior run via `currentHashes` / `currentDepHashes` — which is
    // what we want since those are authoritative when they exist.
    for (auto &entry : collectedDepHashes) {
        result.fileHashes.insert(std::move(entry));
    }
    assignFindingIds(result);

    if (verbose) {
        llvm::errs() << "[verbose] Analysis completed in " << elapsed << " ms, "
                     << result.findings.size() << " finding(s), tool exit "
                     << worstExitCode << "\n";
    }

    (void)registry;
    int exitCode = (worstExitCode != 0) ? 2 : (result.findings.empty() ? 0 : 1);
    return {std::move(result), exitCode};
}

/// Extract --format=VALUE from argv for commands that don't use CommonOptionsParser.
static std::string extractFormat(int argc, const char **argv) {
    for (int index = 2; index < argc; ++index) {
        std::string arg = argv[index];
        if (arg.starts_with("--format=")) {
            return arg.substr(9);
        }
        if (arg == "--format" && index + 1 < argc) {
            return argv[index + 1];
        }
    }
    return "text";
}

int main(int argc, const char **argv) {
    if (argc < 2) {
        print_help();
        return 2;
    }

    std::string command = argv[1];

    // Load .astharbor.yml from the current directory upward. Values are
    // merged into cl::opts after each command's CommonOptionsParser has
    // populated them, so explicit CLI flags always win. The config fills
    // in defaults only.
    std::string configPathStr;
    if (auto configPath = discoverConfig(std::filesystem::current_path())) {
        if (auto loaded = loadConfig(*configPath)) {
            projectConfig = std::move(*loaded);
            configPathStr = configPath->string();
        } else {
            llvm::errs() << "Warning: failed to parse " << configPath->string() << "\n";
        }
    }

    RuleRegistry registry;
    registerBuiltinRules(registry);

    if (command == "analyze") {
        auto parser = setupParser(argc, argv);
        if (!parser) {
            return 2;
        }
        applyConfigDefaults();
        if (!configPathStr.empty() && Verbose.getValue()) {
            llvm::errs() << "[verbose] Loaded config: " << configPathStr << "\n";
        }

        auto [result, exitCode] = runAnalysis(*parser, registry);
        if (exitCode == 2 && !result.success) {
            // Tool failure, still emit what we have
        }

        // Persist the run if --save-run was passed. An empty value means
        // "use the default path"; a non-empty value is treated as an explicit
        // target path.
        bool savedRun = false;
        std::filesystem::path savedPath;
        if (SaveRun.getNumOccurrences() > 0) {
            std::string savePathValue = SaveRun.getValue();
            savedPath = savePathValue.empty() ? RunStore::defaultPathFor(result.runId)
                                              : std::filesystem::path(savePathValue);
            if (RunStore::save(result, savedPath)) {
                savedRun = true;
            } else {
                llvm::errs() << "Warning: failed to persist run to " << savedPath.string()
                             << "\n";
            }
        }

        std::unique_ptr<IEmitter> emitter;
        std::string formatValue = Format.getValue();
        if (formatValue == "json") {
            emitter = std::make_unique<JsonEmitter>();
        } else if (formatValue == "sarif") {
            emitter = std::make_unique<SarifEmitter>(&registry);
        } else {
            emitter = std::make_unique<TextEmitter>();
        }

        emitter->emit(result, std::cout);
        if (savedRun && formatValue == "text") {
            std::cout << "Run saved to " << savedPath.string() << "\n";
        }
        return exitCode;

    }
    if (command == "fix") {
        // Call setupParser first so that cl::opt values (including --run-id,
        // --finding-id, --rule, --apply, etc.) are populated before we branch.
        auto parser = setupParser(argc, argv);
        if (!parser) {
            return 2;
        }
        applyConfigDefaults();

        AnalysisResult result;

        // Two modes: load a previously saved run via --run-id, or re-run the
        // analysis on the given sources.
        if (!RunId.getValue().empty()) {
            auto runPath = RunStore::defaultPathFor(RunId.getValue());
            auto loaded = RunStore::load(runPath);
            if (!loaded) {
                llvm::errs() << "Error: could not load run '" << RunId.getValue()
                             << "' from " << runPath.string() << "\n";
                return 2;
            }
            result = std::move(*loaded);
        } else {
            auto analysis = runAnalysis(*parser, registry);
            result = std::move(analysis.first);
        }

        // Filter findings to only those with fixes (and optional rule /
        // finding-id filters).
        std::vector<Finding> fixableFindings;
        std::string rulePattern = RuleFilter.getValue();
        std::string findingIdFilter = FindingId.getValue();
        for (const auto &finding : result.findings) {
            if (finding.fixes.empty()) {
                continue;
            }
            if (!rulePattern.empty() && !finding.ruleId.contains(rulePattern)) {
                continue;
            }
            if (!findingIdFilter.empty() && finding.findingId != findingIdFilter) {
                continue;
            }
            fixableFindings.push_back(finding);
        }

        if (fixableFindings.empty()) {
            std::cout << "No fixes available.\n";
            return 0;
        }

        // `--all-safe` is a discoverable alias for `--apply` with no rule
        // filter. It also enables the per-rule summary so batch modernization
        // runs produce a useful audit trail.
        const bool shouldApply =
            (Apply.getValue() || AllSafe.getValue()) && !DryRun.getValue();
        if (shouldApply) {
            // Snapshot originals before applying so --verify can roll back on
            // a post-apply syntax failure. Also remember which files were
            // already broken before we touched them — we must not roll those
            // back if they remain broken after the apply (no regression).
            std::map<std::string, std::string> originalContents;
            std::set<std::string> alreadyBroken;
            if (Verify.getValue()) {
                std::set<std::string> targetFiles;
                for (const auto &finding : fixableFindings) {
                    if (!finding.fixes.empty()) {
                        targetFiles.insert(finding.file);
                    }
                }
                for (const auto &path : targetFiles) {
                    if (auto content = readFileContent(path)) {
                        originalContents.emplace(path, std::move(*content));
                    }
                    if (!syntaxCheckFile(path)) {
                        alreadyBroken.insert(path);
                    }
                }
            }

            auto applyResult = FixApplicator::apply(fixableFindings, Backup.getValue());

            // --verify: re-parse each modified file with clang++. Revert on
            // regressions only — files that were already broken before the
            // fix are not counted against --verify, since the fix can't be
            // blamed for preexisting syntax errors.
            int rolledBack = 0;
            if (Verify.getValue()) {
                std::vector<std::string> failingFiles;
                for (const auto &[path, _] : originalContents) {
                    if (alreadyBroken.count(path) > 0) {
                        continue; // already broken before apply
                    }
                    if (!syntaxCheckFile(path)) {
                        failingFiles.push_back(path);
                    }
                }
                if (!failingFiles.empty()) {
                    llvm::errs() << "Warning: --verify detected " << failingFiles.size()
                                 << " file(s) that no longer parse; rolling back.\n";
                    for (const auto &path : failingFiles) {
                        llvm::errs() << "  " << path << "\n";
                    }
                    for (const auto &[path, content] : originalContents) {
                        writeFileContent(path, content);
                    }
                    rolledBack = static_cast<int>(originalContents.size());
                    applyResult.fixesApplied = 0;
                    applyResult.filesModified = 0;
                    applyResult.errors.push_back(
                        "verify failed; rolled back " + std::to_string(rolledBack) +
                        " file(s)");
                }
            }

            // Per-rule breakdown: count safe fixes grouped by rule id.
            std::map<std::string, int> perRuleApplied;
            for (const auto &finding : fixableFindings) {
                for (const auto &fix : finding.fixes) {
                    if (fix.safety == "safe") {
                        perRuleApplied[finding.ruleId]++;
                    }
                }
            }

            if (Format.getValue() == "json") {
                std::cout << "{\n";
                std::cout << R"(  "filesModified": )" << applyResult.filesModified << ",\n";
                std::cout << R"(  "fixesApplied": )" << applyResult.fixesApplied << ",\n";
                std::cout << R"(  "fixesSkipped": )" << applyResult.fixesSkipped << ",\n";
                std::cout << "  \"byRule\": {";
                bool first = true;
                for (const auto &[ruleId, count] : perRuleApplied) {
                    std::cout << (first ? "\n" : ",\n");
                    std::cout << "    \"" << ruleId << "\": " << count;
                    first = false;
                }
                if (!perRuleApplied.empty()) {
                    std::cout << "\n  ";
                }
                std::cout << "},\n";
                std::cout << "  \"errors\": [";
                for (size_t index = 0; index < applyResult.errors.size(); ++index) {
                    std::cout << "\"" << applyResult.errors[index] << "\"";
                    if (index + 1 < applyResult.errors.size()) {
                        std::cout << ", ";
                    }
                }
                std::cout << "]\n}\n";
            } else {
                std::cout << "Applied " << applyResult.fixesApplied << " fix(es) across "
                          << applyResult.filesModified << " file(s).\n";
                if (!perRuleApplied.empty()) {
                    std::cout << "By rule:\n";
                    for (const auto &[ruleId, count] : perRuleApplied) {
                        std::cout << "  " << ruleId << ": " << count << "\n";
                    }
                }
                if (applyResult.fixesSkipped > 0) {
                    std::cout << "Skipped " << applyResult.fixesSkipped
                              << " non-safe fix(es).\n";
                }
                for (const auto &error : applyResult.errors) {
                    std::cerr << "Error: " << error << "\n";
                }
            }
            return applyResult.errors.empty() ? 0 : 2;
        }
        // Preview mode (default or --dry-run).
        if (Format.getValue() == "json") {
            AnalysisResult fixableResult;
            fixableResult.runId = result.runId;
            fixableResult.success = result.success;
            fixableResult.findings = fixableFindings;
            JsonEmitter jsonEmitter;
            jsonEmitter.emit(fixableResult, std::cout);
        } else {
            FixApplicator::preview(fixableFindings, std::cout);
        }
        return 0;

    }
    if (command == "rules") {
        std::string formatValue = extractFormat(argc, argv);
        if (formatValue == "json") {
            std::cout << "[\n";
            const auto &rules = registry.getRules();
            for (size_t index = 0; index < rules.size(); ++index) {
                const auto &rule = rules[index];
                std::cout << R"(  {"id": ")" << rule->id() << R"(", "title": ")" << rule->title()
                          << R"(", "category": ")" << rule->category() << R"(", "severity": ")"
                          << rule->defaultSeverity() << R"(", "summary": ")" << rule->summary()
                          << "\"}";
                if (index + 1 < rules.size()) {
                    std::cout << ",";
                }
                std::cout << "\n";
            }
            std::cout << "]\n";
        } else {
            for (const auto &rule : registry.getRules()) {
                std::cout << rule->id() << " - " << rule->title() << " [" << rule->category()
                          << "] (" << rule->defaultSeverity() << ")\n";
                std::cout << "  " << rule->summary() << "\n";
            }
        }
        return 0;

    }
    if (command == "doctor") {
        bool healthy = true;
        std::string databaseError;
        auto compilationDb = CompilationDatabase::loadFromDirectory(".", databaseError);

        std::string formatValue = extractFormat(argc, argv);
        if (formatValue == "json") {
            std::cout << "{\n";
            std::cout << "  \"rulesRegistered\": " << registry.getRules().size() << ",\n";
            std::cout << "  \"compilationDatabase\": " << (compilationDb ? "true" : "false")
                      << ",\n";
            std::cout << "  \"healthy\": " << (healthy ? "true" : "false") << "\n";
            std::cout << "}\n";
        } else {
            std::cout << "ASTHarbor Doctor\n";
            std::cout << "  Rules registered: " << registry.getRules().size() << "\n";
            if (compilationDb) {
                std::cout << "  Compilation database: found\n";
            } else {
                std::cout << "  Compilation database: not found (run from a directory with "
                             "compile_commands.json)\n";
            }
            std::cout << "  Status: " << (healthy ? "OK" : "UNHEALTHY") << "\n";
        }
        return healthy ? 0 : 1;

    }
    if (command == "compare") {
        if (argc < 3) {
            llvm::errs() << "Usage: astharbor compare <file>\n";
            return 2;
        }
        std::string sourceFile;
        for (int index = 2; index < argc; ++index) {
            std::string arg = argv[index];
            if (arg == "--" || arg.starts_with("--")) {
                continue;
            }
            sourceFile = arg;
            break;
        }
        if (sourceFile.empty()) {
            llvm::errs() << "Error: compare requires a source file argument\n";
            return 2;
        }

        const bool isCxx = sourceFile.ends_with(".cpp") || sourceFile.ends_with(".cc") ||
                           sourceFile.ends_with(".cxx") || sourceFile.ends_with(".hpp");

        struct CompilerReport {
            int exitCode = -1;
            int errorCount = 0;
            int warningCount = 0;
            // Distinct diagnostic codes bucketed by the "[-Wflag]" suffix
            // Clang/GCC include on warning lines. Allows us to surface
            // "clang says X, gcc doesn't" without parsing column/offsets.
            std::set<std::string> codes;
        };

        auto runCompiler = [&](const std::string &compiler) -> CompilerReport {
            CompilerReport report;
            std::string langFlag = isCxx ? "-xc++" : "-xc";
            std::string command = compiler + " " + langFlag +
                                   " -fsyntax-only -Wall -Wextra \"" + sourceFile +
                                   "\" 2>&1";
            FILE *pipe = popen(command.c_str(), "r");
            if (pipe == nullptr) {
                return report;
            }
            std::regex codeRegex(R"(\[-W([^\]]+)\])");
            char buffer[4096];
            while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                std::string line = buffer;
                bool isWarning = line.contains("warning:");
                bool isError = line.contains("error:");
                if (!isWarning && !isError) {
                    continue;
                }
                if (isError) {
                    report.errorCount++;
                } else {
                    report.warningCount++;
                }
                std::smatch match;
                if (std::regex_search(line, match, codeRegex) && match.size() > 1) {
                    report.codes.insert(match[1].str());
                }
            }
            int status = pclose(pipe);
            report.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            return report;
        };

        // Collect the compiler list from --compare-compilers if set, else
        // default to "clang++,g++" so existing invocations work unchanged.
        // compare doesn't use CommonOptionsParser, so we parse the flag
        // manually from argv (like extractFormat does for --format).
        std::vector<std::string> compilerList;
        {
            std::string value;
            for (int index = 2; index < argc; ++index) {
                std::string arg = argv[index];
                if (arg.starts_with("--compare-compilers=")) {
                    value = arg.substr(20);
                    break;
                }
                if (arg == "--compare-compilers" && index + 1 < argc) {
                    value = argv[index + 1];
                    break;
                }
            }
            if (value.empty()) {
                compilerList = {"clang++", "g++"};
            } else {
                size_t start = 0;
                while (start < value.size()) {
                    size_t comma = value.find(',', start);
                    std::string token =
                        value.substr(start, comma == std::string::npos ? std::string::npos
                                                                        : comma - start);
                    // Trim whitespace.
                    while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front()))) {
                        token.erase(token.begin());
                    }
                    while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back()))) {
                        token.pop_back();
                    }
                    if (!token.empty()) {
                        compilerList.push_back(std::move(token));
                    }
                    if (comma == std::string::npos) {
                        break;
                    }
                    start = comma + 1;
                }
            }
        }

        std::vector<std::pair<std::string, CompilerReport>> reports;
        reports.reserve(compilerList.size());
        for (const auto &compiler : compilerList) {
            reports.emplace_back(compiler, runCompiler(compiler));
        }

        // Compute pairwise code diffs against the first available compiler
        // so the text output can still highlight "compiler X has a finding
        // Y that others don't".
        std::set<std::string> unionCodes;
        for (const auto &[_, report] : reports) {
            unionCodes.insert(report.codes.begin(), report.codes.end());
        }

        bool agree = true;
        int baselineExit = -999;
        for (const auto &[name, report] : reports) {
            if (report.exitCode < 0) {
                continue; // treat unavailable compilers as neutral
            }
            if (baselineExit == -999) {
                baselineExit = report.exitCode;
            } else if (report.exitCode != baselineExit) {
                agree = false;
            }
            if (report.codes != reports.front().second.codes) {
                agree = false;
            }
        }

        auto joinCodes = [](const std::vector<std::string> &codes) {
            std::string result;
            for (size_t i = 0; i < codes.size(); ++i) {
                if (i > 0) {
                    result += "\", \"";
                }
                result += codes[i];
            }
            return result;
        };

        std::string formatValue = extractFormat(argc, argv);
        if (formatValue == "json") {
            auto emitReport = [](const std::string &name, const CompilerReport &report) {
                std::cout << R"(  ")" << name << R"(": {)"
                          << R"("available": )" << (report.exitCode >= 0 ? "true" : "false")
                          << R"(, "exit": )" << report.exitCode
                          << R"(, "errors": )" << report.errorCount
                          << R"(, "warnings": )" << report.warningCount
                          << R"(, "codes": [)";
                bool first = true;
                for (const auto &code : report.codes) {
                    std::cout << (first ? "\"" : ", \"") << code << "\"";
                    first = false;
                }
                std::cout << "]}";
            };
            std::cout << "{\n";
            std::cout << R"(  "file": ")" << sourceFile << "\",\n";
            std::cout << R"(  "compilers": {)" << "\n";
            for (size_t i = 0; i < reports.size(); ++i) {
                emitReport(reports[i].first, reports[i].second);
                std::cout << (i + 1 < reports.size() ? ",\n" : "\n");
            }
            std::cout << "  },\n";
            // Per-compiler unique-code sets.
            std::cout << R"(  "uniqueCodes": {)" << "\n";
            for (size_t i = 0; i < reports.size(); ++i) {
                const auto &[name, report] = reports[i];
                std::vector<std::string> unique;
                for (const auto &code : report.codes) {
                    bool seenElsewhere = false;
                    for (const auto &[otherName, otherReport] : reports) {
                        if (&otherReport == &report) {
                            continue;
                        }
                        if (otherReport.codes.count(code) > 0) {
                            seenElsewhere = true;
                            break;
                        }
                    }
                    if (!seenElsewhere) {
                        unique.push_back(code);
                    }
                }
                std::cout << R"(    ")" << name << R"(": [)";
                if (!unique.empty()) {
                    std::cout << "\"" << joinCodes(unique) << "\"";
                }
                std::cout << "]" << (i + 1 < reports.size() ? ",\n" : "\n");
            }
            std::cout << "  },\n";
            std::cout << R"(  "agreement": )" << (agree ? "true" : "false") << "\n";
            std::cout << "}\n";
        } else {
            auto printReport = [](const std::string &label, const CompilerReport &report) {
                std::cout << "  " << label;
                if (report.exitCode < 0) {
                    std::cout << " not available\n";
                    return;
                }
                std::cout << " exit=" << report.exitCode
                          << ", errors=" << report.errorCount
                          << ", warnings=" << report.warningCount;
                if (!report.codes.empty()) {
                    std::cout << " [";
                    bool first = true;
                    for (const auto &code : report.codes) {
                        std::cout << (first ? "" : " ") << "-W" << code;
                        first = false;
                    }
                    std::cout << "]";
                }
                std::cout << "\n";
            };
            std::cout << "ASTHarbor Compare: " << sourceFile << "\n";
            for (const auto &[name, report] : reports) {
                printReport(name + ":", report);
            }
            // Per-compiler uniques (only when at least two compilers available).
            size_t available = 0;
            for (const auto &[_, report] : reports) {
                if (report.exitCode >= 0) {
                    ++available;
                }
            }
            if (available >= 2) {
                for (const auto &[name, report] : reports) {
                    if (report.exitCode < 0) {
                        continue;
                    }
                    std::vector<std::string> unique;
                    for (const auto &code : report.codes) {
                        bool seenElsewhere = false;
                        for (const auto &[otherName, otherReport] : reports) {
                            if (&otherReport == &report) {
                                continue;
                            }
                            if (otherReport.codes.count(code) > 0) {
                                seenElsewhere = true;
                                break;
                            }
                        }
                        if (!seenElsewhere) {
                            unique.push_back(code);
                        }
                    }
                    if (!unique.empty()) {
                        std::cout << "  " << name << "-only codes: ";
                        for (const auto &code : unique) {
                            std::cout << "-W" << code << " ";
                        }
                        std::cout << "\n";
                    }
                }
                std::cout << "  Agreement: " << (agree ? "YES" : "NO — compilers differ")
                          << "\n";
            }
        }
        return 0;
    }
    if (command == "init") {
        // Scaffold a new .astharbor.yml in the current directory. Refuses
        // to overwrite an existing file unless --force is passed.
        bool force = false;
        for (int index = 2; index < argc; ++index) {
            if (std::string(argv[index]) == "--force") {
                force = true;
            }
        }
        auto targetPath = std::filesystem::current_path() / ".astharbor.yml";
        if (std::filesystem::exists(targetPath) && !force) {
            llvm::errs() << "Error: " << targetPath.string()
                         << " already exists. Pass --force to overwrite.\n";
            return 2;
        }
        std::ofstream out(targetPath);
        if (!out) {
            llvm::errs() << "Error: cannot write " << targetPath.string() << "\n";
            return 2;
        }
        out << "---\n"
            << "# ASTHarbor project configuration.\n"
            << "# See docs/cli.md and `astharbor rules` for the full rule catalog.\n"
            << "#\n"
            << "# Checks: comma-separated substring patterns. Prefix with '-' to disable.\n"
            << "# Examples: 'modernize,ub' / 'security,-security/no-alloca'\n"
            << "Checks: \"modernize,ub,bugprone,security\"\n"
            << "\n"
            << "# HeaderFilterRegex: only report findings whose file path matches this\n"
            << "# regex (main source files are always reported regardless).\n"
            << "# HeaderFilterRegex: \"^(src|include)/.*\\\\.(hpp|h)$\"\n"
            << "\n"
            << "# Jobs: parallel analysis workers. Leave unset to default to 1.\n"
            << "# Jobs: 4\n"
            << "\n"
            << "# Std: language standard for single-file mode (no compile_commands.json).\n"
            << "# Std: \"c++20\"\n"
            << "\n"
            << "# CompilerProfile: auto | clang | gcc. gcc enables -fgnu-keywords etc.\n"
            << "# CompilerProfile: \"auto\"\n"
            << "\n"
            << "# Severity: per-rule overrides. Valid values: error, warning, note.\n"
            << "# Severity:\n"
            << "#   modernize/use-nullptr: error\n"
            << "#   security/no-gets: error\n";
        if (!out) {
            llvm::errs() << "Error: failed to write " << targetPath.string() << "\n";
            return 2;
        }
        std::cout << "Wrote " << targetPath.string() << "\n"
                  << "Next steps:\n"
                  << "  1. Edit the file to scope Checks/Severity for your project.\n"
                  << "  2. Run `astharbor rules` to list all available rule ids.\n"
                  << "  3. Run `astharbor analyze <path> --` from any directory under "
                  << "this one — the config is discovered automatically.\n";
        return 0;
    }
    if (command == "explain") {
        if (argc < 3) {
            llvm::errs() << "Usage: astharbor explain <rule-id> [--format=text|json]\n";
            return 2;
        }
        std::string ruleId = argv[2];
        const Rule *found = nullptr;
        for (const auto &rule : registry.getRules()) {
            if (rule->id() == ruleId) {
                found = rule.get();
                break;
            }
        }
        if (found == nullptr) {
            llvm::errs() << "Error: rule '" << ruleId << "' not found. Run `astharbor rules` "
                         << "to list all rule ids.\n";
            return 2;
        }
        std::string formatValue = extractFormat(argc, argv);
        if (formatValue == "json") {
            std::cout << "{\n";
            std::cout << R"(  "id": ")" << found->id() << "\",\n";
            std::cout << R"(  "title": ")" << found->title() << "\",\n";
            std::cout << R"(  "category": ")" << found->category() << "\",\n";
            std::cout << R"(  "severity": ")" << found->defaultSeverity() << "\",\n";
            std::cout << R"(  "summary": ")" << found->summary() << "\"\n";
            std::cout << "}\n";
        } else {
            std::cout << found->id() << "\n";
            std::cout << std::string(found->id().size(), '=') << "\n\n";
            std::cout << "Title:    " << found->title() << "\n";
            std::cout << "Category: " << found->category() << "\n";
            std::cout << "Severity: " << found->defaultSeverity() << "\n\n";
            std::cout << "Summary:\n  " << found->summary() << "\n";
        }
        return 0;
    }

    print_help();
    return 2;
}
