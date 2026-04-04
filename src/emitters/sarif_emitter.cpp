#include "sarif_emitter.hpp"
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

void SarifEmitter::emit(const AnalysisResult &result, std::ostream &out) {
    out << "{\n";
    out << "  \"version\": \"2.1.0\",\n";
    out << "  \"runs\": [\n";
    out << "    {\n";
    out << "      \"tool\": {\n";
    out << "        \"driver\": {\n";
    out << "          \"name\": \"ASTHarbor\"\n";
    out << "        }\n";
    out << "      },\n";
    out << "      \"results\": [\n";
    for (size_t i = 0; i < result.findings.size(); ++i) {
        const auto &finding = result.findings[i];
        out << "        {\n";
        out << "          \"ruleId\": \"" << escapeJson(finding.ruleId) << "\",\n";
        out << "          \"message\": {\n";
        out << "            \"text\": \"" << escapeJson(finding.message) << "\"\n";
        out << "          },\n";
        out << "          \"locations\": [\n";
        out << "            {\n";
        out << "              \"physicalLocation\": {\n";
        out << "                \"artifactLocation\": {\n";
        out << "                  \"uri\": \"file://" << escapeJson(finding.file) << "\"\n";
        out << "                },\n";
        out << "                \"region\": {\n";
        out << "                  \"startLine\": " << finding.line << ",\n";
        out << "                  \"startColumn\": " << finding.column << "\n";
        out << "                }\n";
        out << "              }\n";
        out << "            }\n";
        out << "          ]\n";
        out << "        }" << (i + 1 < result.findings.size() ? "," : "") << "\n";
    }
    out << "      ]\n";
    out << "    }\n";
    out << "  ]\n";
    out << "}\n";
}

} // namespace astharbor
