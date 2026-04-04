#pragma once
#include "astharbor/emitter.hpp"

namespace astharbor {

class JsonEmitter : public IEmitter {
  public:
    void emit(const AnalysisResult &result, std::ostream &out) override;
};

} // namespace astharbor
