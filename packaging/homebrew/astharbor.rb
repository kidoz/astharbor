class Astharbor < Formula
  desc "A Clang-first C/C++ code analyzer with deterministic AST static analysis"
  homepage "https://github.com/kidoz/astharbor"
  url "https://github.com/kidoz/astharbor/archive/refs/tags/v1.0.0.tar.gz"
  # sha256 must be set from the release tarball before publishing:
  #   curl -sL <url> | shasum -a 256
  sha256 ""
  license "MIT"

  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "llvm"

  def install
    # Homebrew provides std_meson_args which sets the prefix, buildtype=release, etc.
    system "meson", "setup", "build", *std_meson_args
    system "meson", "compile", "-C", "build", "--verbose"
    system "meson", "install", "-C", "build"
  end

  test do
    assert_match "Rules registered:", shell_output("#{bin}/astharbor doctor")
    assert_match "modernize/use-nullptr", shell_output("#{bin}/astharbor rules")
  end
end
