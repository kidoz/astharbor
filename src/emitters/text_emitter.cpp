#include "text_emitter.hpp"

namespace astharbor {

void TextEmitter::emit(const AnalysisResult &result, std::ostream &out) {
    if (!result.success) {
        out << "error: analysis failed due to compilation errors\n";
    }
    for (const auto &finding : result.findings) {
        out << finding.file << ":" << finding.line << ":" << finding.column << ": warning: "
            << finding.message << " [" << finding.ruleId << "]\n";
    }
}

} // namespace astharbor
