# Homebrew Formula — MYTH Desktop
# Install: brew install --cask myth

cask "myth" do
  version "1.1.4"
  sha256 "" # TO BE FILLED AFTER BUILD

  url "https://github.com/shesher010/MYTH/releases/download/v#{version}/MYTH_#{version}_universal.dmg"
  name "MYTH"
  desc "High-Performance Offensive Intelligence Engine"
  homepage "https://github.com/shesher011/MYTH"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :catalina"

  app "MYTH.app"

  zap trash: [
    "~/Library/Application Support/com.myth-tools.myth",
    "~/Library/Caches/com.myth-tools.myth",
    "~/Library/Preferences/com.myth-tools.myth.plist",
  ]
end
