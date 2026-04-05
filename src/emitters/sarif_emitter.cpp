#include "sarif_emitter.hpp"
#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace astharbor {

static std::string escapeJson(const std::string &input) {
    std::ostringstream stream;
    for (char c : input) {
        switch (c) {
        case '"':
            stream << "\\\"";
            break;
        case '\\':
            stream << "\\\\";
            break;
        case '\b':
            stream << "\\b";
            break;
        case '\f':
            stream << "\\f";
            break;
        case '\n':
            stream << "\\n";
            break;
        case '\r':
            stream << "\\r";
            break;
        case '\t':
            stream << "\\t";
            break;
        default:
            if ('\x00' <= c && c <= '\x1f') {
                stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<int>(c);
            } else {
                stream << c;
            }
            break;
        }
    }
    return stream.str();
}

/// Map ASTHarbor severity strings to SARIF levels per SARIF 2.1.0 §3.27.10.
static std::string toSarifLevel(const std::string &severity) {
    if (severity == "error") {
        return "error";
    }
    if (severity == "warning") {
        return "warning";
    }
    if (severity == "note" || severity == "info") {
        return "note";
    }
    return "warning";
}

void SarifEmitter::emit(const AnalysisResult &result, std::ostream &out) {
    // Build a rule-id → index lookup so `results[].ruleIndex` points into
    // the tool.driver.rules array.
    std::unordered_map<std::string, size_t> ruleIndex;
    std::vector<const Rule *> orderedRules;
    if (ruleRegistry != nullptr) {
        orderedRules.reserve(ruleRegistry->getRules().size());
        for (const auto &rule : ruleRegistry->getRules()) {
            ruleIndex[rule->id()] = orderedRules.size();
            orderedRules.push_back(rule.get());
        }
    }

    out << "{\n";
    out << "  \"$schema\": "
           "\"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    out << "  \"version\": \"2.1.0\",\n";
    out << "  \"runs\": [\n";
    out << "    {\n";
    out << "      \"tool\": {\n";
    out << "        \"driver\": {\n";
    out << "          \"name\": \"ASTHarbor\",\n";
    out << "          \"informationUri\": \"https://github.com/anthropics/astharbor\",\n";
    out << "          \"rules\": [";
    for (size_t i = 0; i < orderedRules.size(); ++i) {
        const Rule *rule = orderedRules[i];
        out << (i == 0 ? "\n" : ",\n");
        out << "            {\n";
        out << R"(              "id": ")" << escapeJson(rule->id()) << "\",\n";
        out << R"(              "name": ")" << escapeJson(rule->title()) << "\",\n";
        out << "              \"shortDescription\": {\n";
        out << R"(                "text": ")" << escapeJson(rule->summary()) << "\"\n";
        out << "              },\n";
        out << "              \"fullDescription\": {\n";
        out << R"(                "text": ")" << escapeJson(rule->summary()) << "\"\n";
        out << "              },\n";
        out << "              \"defaultConfiguration\": {\n";
        out << R"(                "level": ")" << toSarifLevel(rule->defaultSeverity()) << "\"\n";
        out << "              },\n";
        out << "              \"properties\": {\n";
        out << R"(                "category": ")" << escapeJson(rule->category()) << "\",\n";
        out << R"(                "tags": [")" << escapeJson(rule->category()) << "\"]\n";
        out << "              }\n";
        out << "            }";
    }
    if (!orderedRules.empty()) {
        out << "\n          ";
    }
    out << "]\n";
    out << "        }\n";
    out << "      },\n";
    out << "      \"results\": [";
    for (size_t i = 0; i < result.findings.size(); ++i) {
        const auto &finding = result.findings[i];
        out << (i == 0 ? "\n" : ",\n");
        out << "        {\n";
        out << R"(          "ruleId": ")" << escapeJson(finding.ruleId) << "\",\n";
        auto indexIt = ruleIndex.find(finding.ruleId);
        if (indexIt != ruleIndex.end()) {
            out << "          \"ruleIndex\": " << indexIt->second << ",\n";
        }
        out << R"(          "level": ")" << toSarifLevel(finding.severity) << "\",\n";
        out << "          \"message\": {\n";
        out << R"(            "text": ")" << escapeJson(finding.message) << "\"\n";
        out << "          },\n";
        out << "          \"locations\": [\n";
        out << "            {\n";
        out << "              \"physicalLocation\": {\n";
        out << "                \"artifactLocation\": {\n";
        out << R"(                  "uri": "file://)" << escapeJson(finding.file) << "\"\n";
        out << "                },\n";
        out << "                \"region\": {\n";
        out << "                  \"startLine\": " << finding.line << ",\n";
        out << "                  \"startColumn\": " << finding.column << "\n";
        out << "                }\n";
        out << "              }\n";
        out << "            }\n";
        out << "          ],\n";
        out << "          \"properties\": {\n";
        out << R"(            "findingId": ")" << escapeJson(finding.findingId) << "\",\n";
        out << R"(            "category": ")" << escapeJson(finding.category) << "\"\n";
        out << "          }";
        if (!finding.fixes.empty()) {
            out << ",\n          \"fixes\": [";
            for (size_t j = 0; j < finding.fixes.size(); ++j) {
                const auto &fix = finding.fixes[j];
                out << (j == 0 ? "\n" : ",\n");
                out << "            {\n";
                out << "              \"description\": {\n";
                out << R"(                "text": ")" << escapeJson(fix.description)
                    << " [safety=" << escapeJson(fix.safety) << "]\"\n";
                out << "              },\n";
                out << "              \"artifactChanges\": [\n";
                out << "                {\n";
                out << "                  \"artifactLocation\": {\n";
                out << R"(                    "uri": "file://)" << escapeJson(finding.file)
                    << "\"\n";
                out << "                  },\n";
                out << "                  \"replacements\": [\n";
                out << "                    {\n";
                out << "                      \"deletedRegion\": {\n";
                out << "                        \"charOffset\": " << fix.offset << ",\n";
                out << "                        \"charLength\": " << fix.length << "\n";
                out << "                      },\n";
                out << "                      \"insertedContent\": {\n";
                out << R"(                        "text": ")" << escapeJson(fix.replacementText)
                    << "\"\n";
                out << "                      }\n";
                out << "                    }\n";
                out << "                  ]\n";
                out << "                }\n";
                out << "              ]\n";
                out << "            }";
            }
            out << "\n          ]";
        }
        out << "\n        }";
    }
    if (!result.findings.empty()) {
        out << "\n      ";
    }
    out << "]\n";
    out << "    }\n";
    out << "  ]\n";
    out << "}\n";
}

} // namespace astharbor
