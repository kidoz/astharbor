#pragma once
#include "astharbor/result.hpp"
#include <ostream>

namespace astharbor {

class IEmitter {
  public:
    virtual ~IEmitter() = default;
    virtual void emit(const AnalysisResult &result, std::ostream &out) = 0;
};

} // namespace astharbor
