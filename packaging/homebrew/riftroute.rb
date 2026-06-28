# Homebrew formula for the RiftRoute CLI + daemon (the GUI ships as a signed
# .dmg, not via Homebrew). Publish to a tap, e.g. Amirhat/homebrew-tap.
#
# The sha256 values and version are filled in by the release workflow
# (scripts/bump-homebrew.sh) from the published checksums.txt.
class Riftroute < Formula
  desc "Cross-platform split-tunneling / policy-based routing controller"
  homepage "https://github.com/Amirhat/riftroute"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Amirhat/riftroute/releases/download/v#{version}/riftroute_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_DARWIN_ARM64"
    end
    on_intel do
      url "https://github.com/Amirhat/riftroute/releases/download/v#{version}/riftroute_#{version}_darwin_amd64.tar.gz"
      sha256 "REPLACE_DARWIN_AMD64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Amirhat/riftroute/releases/download/v#{version}/riftroute_#{version}_linux_arm64.tar.gz"
      sha256 "REPLACE_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/Amirhat/riftroute/releases/download/v#{version}/riftroute_#{version}_linux_amd64.tar.gz"
      sha256 "REPLACE_LINUX_AMD64"
    end
  end

  def install
    bin.install "riftroute"
    bin.install "riftrouted"
  end

  def caveats
    <<~EOS
      riftrouted is a privileged daemon (it owns the routing table). Install and
      start it as a service deliberately:

        sudo riftroute daemon install   # writes the launchd/systemd unit

      RiftRoute never mutates routes without the Apply Protocol's guardrails.
    EOS
  end

  test do
    assert_match "riftroute", shell_output("#{bin}/riftroute version")
  end
end
