#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <tuple>
#include <vector>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include "astharbor/rule_registry.hpp"
#include "astharbor/analyzer.hpp"
#include "astharbor/fix_applicator.hpp"
#include "astharbor/run_store.hpp"
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

void print_help() {
    std::cout << "ASTHarbor CLI\n";
    std::cout << "Commands:\n";
    std::cout << "  analyze <files...>  Analyze C/C++ source files\n";
    std::cout << "  fix <files...>      Preview or apply fixes\n";
    std::cout << "  rules               List available rules\n";
    std::cout << "  doctor              Check toolchain health\n";
    std::cout << "  compare <file>      Compare clang vs gcc diagnostics on a file\n";
    std::cout << "  explain <rule-id>   Show full metadata for a rule\n";
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
static bool ruleIsEnabled(const std::string &ruleId,
                          const std::vector<std::string> &positive,
                          const std::vector<std::string> &negative) {
    bool enabled = positive.empty(); // start all-on iff no positive patterns
    for (const auto &pattern : positive) {
        if (ruleId.contains(pattern)) {
            enabled = true;
            break;
        }
    }
    if (!enabled) {
        return false;
    }
    for (const auto &pattern : negative) {
        if (ruleId.contains(pattern)) {
            return false;
        }
    }
    return true;
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

/// Run analysis on a single chunk of source files with a fresh RuleRegistry.
/// Used as the per-worker function for parallel analysis; the sequential
/// path just calls it once with all sources.
static std::pair<std::vector<Finding>, int>
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

    int toolExitCode = tool.run(newFrontendActionFactory(&finder).get());

    std::vector<Finding> findings;
    for (const Rule *rule : activeRules) {
        auto ruleFindings = rule->getFindings();
        findings.insert(findings.end(), ruleFindings.begin(), ruleFindings.end());
    }
    return {std::move(findings), toolExitCode};
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
    int worstExitCode = 0;

    if (workerCount == 1) {
        auto [findings, exitCode] =
            runAnalysisChunk(sourcePaths, compilationDb, positivePatterns, negativePatterns);
        allFindings = std::move(findings);
        worstExitCode = exitCode;
    } else {
        // Partition sources into round-robin chunks so individual large TUs
        // are spread across workers rather than concentrated in one.
        std::vector<std::vector<std::string>> chunks(workerCount);
        for (size_t index = 0; index < sourcePaths.size(); ++index) {
            chunks[index % workerCount].push_back(sourcePaths[index]);
        }

        std::vector<std::future<std::pair<std::vector<Finding>, int>>> futures;
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
            auto [findings, exitCode] = future.get();
            allFindings.insert(allFindings.end(),
                               std::make_move_iterator(findings.begin()),
                               std::make_move_iterator(findings.end()));
            if (exitCode > worstExitCode) {
                worstExitCode = exitCode;
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

    AnalysisResult result;
    result.runId = generateRunId();
    result.success = (worstExitCode == 0);
    result.findings = std::move(allFindings);
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

    RuleRegistry registry;
    registerBuiltinRules(registry);

    if (command == "analyze") {
        auto parser = setupParser(argc, argv);
        if (!parser) {
            return 2;
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

        if (Apply.getValue() && !DryRun.getValue()) {
            auto applyResult = FixApplicator::apply(fixableFindings, Backup.getValue());

            if (Format.getValue() == "json") {
                std::cout << "{\n";
                std::cout << "  \"filesModified\": " << applyResult.filesModified << ",\n";
                std::cout << "  \"fixesApplied\": " << applyResult.fixesApplied << ",\n";
                std::cout << "  \"fixesSkipped\": " << applyResult.fixesSkipped << ",\n";
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
        auto runCompiler = [&](const std::string &compiler) -> std::pair<int, int> {
            std::string langFlag = isCxx ? "-xc++" : "-xc";
            std::string command = compiler + " " + langFlag +
                                   " -fsyntax-only -Wall -Wextra \"" + sourceFile +
                                   "\" 2>&1";
            FILE *pipe = popen(command.c_str(), "r");
            if (pipe == nullptr) {
                return {-1, 0};
            }
            int warningCount = 0;
            char buffer[1024];
            while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                std::string line = buffer;
                if (line.contains("warning:") || line.contains("error:")) {
                    warningCount++;
                }
            }
            int status = pclose(pipe);
            int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            return {exitCode, warningCount};
        };

        auto [clangExit, clangDiags] = runCompiler("clang++");
        auto [gccExit, gccDiags] = runCompiler("g++");

        std::string formatValue = extractFormat(argc, argv);
        if (formatValue == "json") {
            std::cout << "{\n";
            std::cout << R"(  "file": ")" << sourceFile << "\",\n";
            std::cout << R"(  "clang": {"available": )" << (clangExit >= 0 ? "true" : "false")
                      << ", \"exit\": " << clangExit << ", \"diagnostics\": " << clangDiags
                      << "},\n";
            std::cout << R"(  "gcc": {"available": )" << (gccExit >= 0 ? "true" : "false")
                      << ", \"exit\": " << gccExit << ", \"diagnostics\": " << gccDiags << "},\n";
            std::cout << "  \"agreement\": "
                      << (clangExit == gccExit && clangDiags == gccDiags ? "true" : "false")
                      << "\n";
            std::cout << "}\n";
        } else {
            std::cout << "ASTHarbor Compare: " << sourceFile << "\n";
            std::cout << "  clang++: ";
            if (clangExit < 0) {
                std::cout << "not available\n";
            } else {
                std::cout << "exit=" << clangExit << ", diagnostics=" << clangDiags << "\n";
            }
            std::cout << "  g++:     ";
            if (gccExit < 0) {
                std::cout << "not available\n";
            } else {
                std::cout << "exit=" << gccExit << ", diagnostics=" << gccDiags << "\n";
            }
            if (clangExit >= 0 && gccExit >= 0) {
                bool agree = (clangExit == gccExit) && (clangDiags == gccDiags);
                std::cout << "  Agreement: " << (agree ? "YES" : "NO — compilers differ")
                          << "\n";
            }
        }
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
