{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation rec {
  pname = "myth-desktop";
  version = "1.1.2";

  src = ./..; # Assumes nix/ is in the project root

  nativeBuildInputs = with pkgs; [
    pkg-config
    rustc
    cargo
    nodejs
    python3
    wrapGAppsHook
  ];

  buildInputs = with pkgs; [
    gtk3
    webkitgtk
    openssl
    libappindicator-gtk3
  ];

  buildPhase = ''
    export HOME=$TMPDIR
    cd ui
    npm ci
    npm run tauri:build -- --target x86_64-unknown-linux-gnu
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp src-tauri/target/x86_64-unknown-linux-gnu/release/myth $out/bin/myth
    
    mkdir -p $out/share/applications
    cp src-tauri/icons/myth.desktop $out/share/applications/ 2>/dev/null || true
    
    mkdir -p $out/share/icons/hicolor/512x512/apps
    cp src-tauri/icons/icon.png $out/share/icons/hicolor/512x512/apps/myth.png 2>/dev/null || true
  '';

  meta = with pkgs.lib; {
    description = "High-Performance Offensive Intelligence Engine";
    homepage = "https://github.com/shesher010/MYTH";
    license = licenses.mit;
    platforms = platforms.linux;
  };
}
