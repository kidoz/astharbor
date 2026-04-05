#include "json_emitter.hpp"
#include <iomanip>
#include <sstream>

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

void JsonEmitter::emit(const AnalysisResult &result, std::ostream &out) {
    out << "{\n";
    out << R"(  "runId": ")" << escapeJson(result.runId) << "\",\n";
    out << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
    out << "  \"findings\": [\n";
    for (size_t i = 0; i < result.findings.size(); ++i) {
        const auto &finding = result.findings[i];
        out << "    {\n";
        out << R"(      "findingId": ")" << escapeJson(finding.findingId) << "\",\n";
        out << R"(      "ruleId": ")" << escapeJson(finding.ruleId) << "\",\n";
        out << R"(      "severity": ")" << escapeJson(finding.severity) << "\",\n";
        out << R"(      "category": ")" << escapeJson(finding.category) << "\",\n";
        out << R"(      "message": ")" << escapeJson(finding.message) << "\",\n";
        out << R"(      "file": ")" << escapeJson(finding.file) << "\",\n";
        out << "      \"line\": " << finding.line << ",\n";
        out << "      \"column\": " << finding.column << ",\n";
        out << "      \"fixes\": [";
        for (size_t j = 0; j < finding.fixes.size(); ++j) {
            const auto &fix = finding.fixes[j];
            out << "\n        {\n";
            out << R"(          "fixId": ")" << escapeJson(fix.fixId) << "\",\n";
            out << R"(          "description": ")" << escapeJson(fix.description) << "\",\n";
            out << R"(          "safety": ")" << escapeJson(fix.safety) << "\",\n";
            out << R"(          "replacementText": ")" << escapeJson(fix.replacementText)
                << "\",\n";
            out << "          \"offset\": " << fix.offset << ",\n";
            out << "          \"length\": " << fix.length << "\n";
            out << "        }" << (j + 1 < finding.fixes.size() ? "," : "");
        }
        if (!finding.fixes.empty()) {
            out << "\n      ]\n";
        } else {
            out << "]\n";
        }
        out << "    }" << (i + 1 < result.findings.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

} // namespace astharbor
