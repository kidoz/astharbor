#include <gtest/gtest.h>
#include <sstream>
#include "astharbor/result.hpp"
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
