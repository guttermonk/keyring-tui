{
  description = "keyring-tui — a terminal replacement for GNOME Seahorse";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "keyring-tui";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ gpgme libgpg-error libassuan ];

          postInstall = ''
            # The launcher entry. No icon is installed with it: Icon= names a
            # themed icon so it follows the user's icon theme rather than
            # shipping a look of our own.
            install -Dm644 keyring-tui.desktop \
              $out/share/applications/keyring-tui.desktop

            # The commented default config, for `man`-less discovery.
            install -Dm644 config.example.toml \
              $out/share/doc/keyring-tui/config.example.toml
          '';

          meta = with pkgs.lib; {
            description = "Terminal UI for GPG keys, SSH keys and the GNOME keyring";
            license = licenses.gpl3Plus;
            mainProgram = "keyring-tui";
            platforms = platforms.linux;
          };
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          # Build-time tooling.
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer
            # bindgen, for the gpgme / sequoia-nettle phases
            clang
          ];

          # Native libraries. gpgme/libassuan are needed as soon as the GPG
          # backend lands; nettle+gmp only if sequoia-openpgp is built with its
          # default backend instead of `crypto-rust`.
          buildInputs = with pkgs; [
            gpgme
            libgpg-error
            libassuan
            nettle
            gmp
            openssl
          ];

          # Runtime conveniences for poking at the real thing.
          packages = with pkgs; [
            gnupg
            openssh
            libsecret # provides secret-tool
          ];

          env.LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          env.RUST_BACKTRACE = "1";

          shellHook = ''
            echo "keyring-tui dev shell — rustc $(rustc --version | cut -d' ' -f2)"
          '';
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
