#pragma once
#include "astharbor/emitter.hpp"

namespace astharbor {

class TextEmitter : public IEmitter {
  public:
    void emit(const AnalysisResult &result, std::ostream &out) override;
};

} // namespace astharbor
