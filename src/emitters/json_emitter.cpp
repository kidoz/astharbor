#include "json_emitter.hpp"
#include <iomanip>
#include <sstream>

namespace astharbor {

static std::string escapeJson(const std::string &input) {
    std::ostringstream stream;
    for (char c : input) {
        if (c == '"')
            stream << "\\\"";
        else if (c == '\\')
            stream << "\\\\";
        else if (c == '\b')
            stream << "\\b";
        else if (c == '\f')
            stream << "\\f";
        else if (c == '\n')
            stream << "\\n";
        else if (c == '\r')
            stream << "\\r";
        else if (c == '\t')
            stream << "\\t";
        else if ('\x00' <= c && c <= '\x1f') {
            stream << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        } else {
            stream << c;
        }
    }
    return stream.str();
}

void JsonEmitter::emit(const AnalysisResult &result, std::ostream &out) {
    out << "{\n";
    out << "  \"runId\": \"" << escapeJson(result.runId) << "\",\n";
    out << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
    out << "  \"findings\": [\n";
    for (size_t i = 0; i < result.findings.size(); ++i) {
        const auto &finding = result.findings[i];
        out << "    {\n";
        out << "      \"findingId\": \"" << escapeJson(finding.findingId) << "\",\n";
        out << "      \"ruleId\": \"" << escapeJson(finding.ruleId) << "\",\n";
        out << "      \"severity\": \"" << escapeJson(finding.severity) << "\",\n";
        out << "      \"category\": \"" << escapeJson(finding.category) << "\",\n";
        out << "      \"message\": \"" << escapeJson(finding.message) << "\",\n";
        out << "      \"file\": \"" << escapeJson(finding.file) << "\",\n";
        out << "      \"line\": " << finding.line << ",\n";
        out << "      \"column\": " << finding.column << ",\n";
        out << "      \"fixes\": [";
        for (size_t j = 0; j < finding.fixes.size(); ++j) {
            const auto &fix = finding.fixes[j];
            out << "\n        {\n";
            out << "          \"fixId\": \"" << escapeJson(fix.fixId) << "\",\n";
            out << "          \"description\": \"" << escapeJson(fix.description) << "\",\n";
            out << "          \"safety\": \"" << escapeJson(fix.safety) << "\",\n";
            out << "          \"replacementText\": \"" << escapeJson(fix.replacementText)
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
