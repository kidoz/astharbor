#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "astharbor/result.hpp"
#include "astharbor/run_store.hpp"
#include "../../src/emitters/json_emitter.hpp"
#include "../../src/emitters/sarif_emitter.hpp"

using namespace astharbor;

TEST(EmittersTest, JsonEscapesStrings) {
    AnalysisResult res;
    res.runId = "test-run";
    Finding f;
    f.findingId = "f1";
    f.ruleId = "my-rule";
    f.severity = "warning";
    f.category = "test";
    f.message = "Message with \"quotes\" and \\ backslashes";
    f.file = "C:\\path\\to\\file.cpp";
    f.line = 10;
    f.column = 5;

    Fix fix;
    fix.fixId = "fix1";
    fix.description = "Fix it";
    fix.safety = "safe";
    fix.replacementText = "int x = 0;";
    fix.offset = 100;
    fix.length = 5;
    f.fixes.push_back(fix);

    res.findings.push_back(f);

    std::ostringstream os;
    JsonEmitter emitter;
    emitter.emit(res, os);
    std::string json = os.str();

    EXPECT_NE(json.find("\"runId\": \"test-run\""), std::string::npos);
    EXPECT_NE(json.find("\\\"quotes\\\""), std::string::npos);
    EXPECT_NE(json.find("C:\\\\path\\\\to\\\\file.cpp"), std::string::npos);
    EXPECT_NE(json.find("\"severity\": \"warning\""), std::string::npos);
    EXPECT_NE(json.find("\"category\": \"test\""), std::string::npos);
    EXPECT_NE(json.find("\"fixes\": ["), std::string::npos);
}

TEST(EmittersTest, SarifOutputsCorrectly) {
    AnalysisResult res;
    res.runId = "test-run";
    Finding f;
    f.ruleId = "my-rule";
    f.message = "Message with \"quotes\"";
    f.file = "file.cpp";
    f.line = 10;
    f.column = 5;
    res.findings.push_back(f);

    std::ostringstream os;
    SarifEmitter emitter;
    emitter.emit(res, os);
    std::string sarif = os.str();

    EXPECT_NE(sarif.find("\"version\": \"2.1.0\""), std::string::npos);
    EXPECT_NE(sarif.find("\"ruleId\": \"my-rule\""), std::string::npos);
    EXPECT_NE(sarif.find("Message with \\\"quotes\\\""), std::string::npos);
    EXPECT_NE(sarif.find("\"uri\": \"file://file.cpp\""), std::string::npos);
}

TEST(RunStoreTest, PersistsAndLoadsDependencies) {
    // Round-trip a result with a non-empty dependencies map through
    // RunStore::save / RunStore::load. Confirms that --incremental can
    // carry per-TU header dependency lists across runs.
    AnalysisResult original;
    original.runId = "run-deps-test";
    original.success = true;
    original.fileHashes["/abs/main.cpp"] = "aaaaaaaaaaaaaaaa";
    original.fileHashes["/abs/lib.hpp"] = "bbbbbbbbbbbbbbbb";
    original.dependencies["/abs/main.cpp"] = {"/abs/lib.hpp"};

    auto tempPath = std::filesystem::temp_directory_path() /
                    "astharbor_runstore_deps_test.json";
    std::filesystem::remove(tempPath);
    ASSERT_TRUE(RunStore::save(original, tempPath));

    auto loaded = RunStore::load(tempPath);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->runId, "run-deps-test");
    EXPECT_EQ(loaded->fileHashes["/abs/main.cpp"], "aaaaaaaaaaaaaaaa");
    EXPECT_EQ(loaded->fileHashes["/abs/lib.hpp"], "bbbbbbbbbbbbbbbb");
    ASSERT_EQ(loaded->dependencies.size(), 1u);
    const auto &deps = loaded->dependencies.at("/abs/main.cpp");
    ASSERT_EQ(deps.size(), 1u);
    EXPECT_EQ(deps[0], "/abs/lib.hpp");

    std::filesystem::remove(tempPath);
}

TEST(RunStoreTest, LoadsRunWithoutDependenciesField) {
    // Ensure backward compatibility: a run file written before the
    // dependencies field existed must still round-trip through load.
    auto tempPath = std::filesystem::temp_directory_path() /
                    "astharbor_runstore_legacy_test.json";
    {
        std::ofstream out(tempPath);
        out << R"({"runId": "legacy", "success": true,
                  "findings": [], "fileHashes": {"/a.cpp": "deadbeef"}})";
    }
    auto loaded = RunStore::load(tempPath);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->runId, "legacy");
    EXPECT_TRUE(loaded->dependencies.empty());
    std::filesystem::remove(tempPath);
}
