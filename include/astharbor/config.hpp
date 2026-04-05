#pragma once
#include <filesystem>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/YAMLTraits.h>
#include <optional>
#include <string>
#include <system_error>

namespace astharbor {

/// Persistent project configuration loaded from `.astharbor.yml`.
///
/// The file is discovered by walking up from the current working directory
/// toward the filesystem root. CLI flags take precedence over config
/// values — the config provides defaults, not overrides.
///
/// Example file:
///
///     ---
///     Checks: "modernize-*,ub/*,-ub/sizeof-array-parameter"
///     HeaderFilterRegex: "^src/.*\\.hpp$"
///     Jobs: 4
///     Std: "c++20"
///     CompilerProfile: "auto"
struct Config {
    std::string checks;
    std::string headerFilterRegex;
    unsigned jobs = 0;
    std::string std;
    std::string compilerProfile;
};

} // namespace astharbor

// MappingTraits specialization must appear before Config::load() is defined
// so the llvm::yaml machinery can find it during template instantiation.
template <> struct llvm::yaml::MappingTraits<astharbor::Config> {
    static void mapping(llvm::yaml::IO &io, astharbor::Config &config) {
        io.mapOptional("Checks", config.checks);
        io.mapOptional("HeaderFilterRegex", config.headerFilterRegex);
        io.mapOptional("Jobs", config.jobs);
        io.mapOptional("Std", config.std);
        io.mapOptional("CompilerProfile", config.compilerProfile);
    }
};

namespace astharbor {

/// Walk up from `start` toward the root, looking for `.astharbor.yml`.
/// Returns the path of the first match, or nullopt if none found.
inline std::optional<std::filesystem::path>
discoverConfig(const std::filesystem::path &start) {
    std::error_code ec;
    auto current = std::filesystem::absolute(start, ec);
    if (ec) {
        return std::nullopt;
    }
    while (true) {
        auto candidate = current / ".astharbor.yml";
        if (std::filesystem::exists(candidate, ec) && !ec) {
            return std::optional<std::filesystem::path>{candidate};
        }
        auto parent = current.parent_path();
        if (parent == current) {
            return std::nullopt;
        }
        current = parent;
    }
}

/// Load and parse a config file from disk. Returns nullopt on IO or parse
/// failure; unknown fields are silently ignored for forward compatibility.
inline std::optional<Config> loadConfig(const std::filesystem::path &path) {
    auto bufferOrError = llvm::MemoryBuffer::getFile(path.string());
    if (!bufferOrError) {
        return std::nullopt;
    }
    Config config;
    llvm::yaml::Input input((*bufferOrError)->getBuffer());
    input >> config;
    if (input.error()) {
        return std::nullopt;
    }
    return std::optional<Config>{std::move(config)};
}

} // namespace astharbor
